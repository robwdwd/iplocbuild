#!/usr/bin/env python3
"""Command to find routes on network devices and build IP location data."""

import os
import sys
import pprint
import json
import re
import click

from netaddr import IPSet
from lxml import etree

from jnpr.junos import Device

pp = pprint.PrettyPrinter(indent=2, width=120)

verbose_level = 0
cfg = {}
cities = {}

paSpaceSet = IPSet([])


def ipset_to_list(ipSetFrom):
    """Convert an IP Set into a list.

    Args:
        ipSetFrom (IPSet): The IPSet to convert from

    Returns:
        list: List of IP Addresses
    """
    toList = []
    for cidr in ipSetFrom.iter_cidrs():
        toList.append(str(cidr))

    return toList


def get_routes(host, communities, piSpace=False):
    """Get routes from a network device.

    Args:
        host (str): Hostname of device
        communities (list): Communities to search for
        piSpace (bool, optional): Find PI Space and carve out prefix if
                                  external ASN. Defaults to False.

    Returns:
        tuple (IPSet, IPSet): Returns a tuble with an IP set with the prefixes
                              and carved prefixes (Not annouced by our ASN.)
    """
    try:
        with Device(
            host=host, user=cfg['username'], passwd=cfg['password'], transport='ssh', port='22', normalize=True
        ) as dev:
            routesXML = dev.rpc.get_route_information(
                dev_timeout=60, level='detail', table='inet.0', protocol='bgp', community=communities
            )

            prefixSet = IPSet([])
            carvedSet = IPSet([])

            routes = routesXML.findall('.//rt')

            if len(routes) == 0:
                if verbose_level >= 1:
                    print("No prefix found with communities: {}".format(str(communities)))
                return None, None

            # Regex to capture AS Path.
            #
            aspathRE = re.compile(r'AS path: ([\d\?I\s]+) [\w\(]')

            for rt in routes:
                # print(etree.tounicode(rt, pretty_print=True))
                prefix = rt.find('.//rt-destination').text
                prefixLen = rt.find('.//rt-prefix-length').text
                cidr = prefix + '/' + prefixLen

                if verbose_level >= 3:
                    print("Network {} : Mask {}".format(prefix, prefixLen))

                if int(prefixLen) >= 32:
                    if verbose_level >= 2:
                        print("Ignoring PI prefix as /32 host route: {}".format(cidr))
                    continue

                if piSpace:
                    # If the CIDR is in our own PA Space but annouced by another ASN we need to carve it out.
                    #
                    if cidr in paSpaceSet:

                        aspathMatch = aspathRE.match(rt.find('.//as-path').text)

                        if not aspathMatch:
                            print("ERROR finding match for AS path ({}): {}".format(rt.find('.//as-path').text, cidr))
                            print(etree.tounicode(rt, pretty_print=True))
                            continue

                        fullaspath = aspathMatch.group(1).split()

                        # Not an internal prefix (our own allocation annoucement) but annouced by external ASN.
                        #
                        if fullaspath[0] != 'I' and fullaspath[0] != '?':
                            carvedSet.add(cidr)
                            if verbose_level >= 1:
                                print(
                                    "Carving out PA space annouced by external ASN ({}): {}".format(
                                        fullaspath[0], cidr
                                    )
                                )
                            continue

                        if verbose_level >= 1:
                            print("Ignoring PI prefix as colt space: {}".format(cidr))
                        continue

                prefixSet.add(cidr)

            return prefixSet, carvedSet

    except Exception as e:
        print('ERROR: Connecting to {} failed: {}'.format(host, e), file=sys.stderr)
        return None, None


def process_routes(prefixSet, country, city, piSpace=False, carvedSpace=False):
    """Process the routes and allocate them to the cities.

    Args:
        prefixSet (IPSet): IP Prefix Set to process
        country (str): Country to allocate the prefixes too
        city (str): City to allocate the preofix set to
        piSpace (bool, optional): Add to piSpace. Defaults to False.
        carvedSpace (bool, optional): Add prefix to carved space. Defaults to False.
    """
    global cities

    # Check if CIDR is in the cities lists
    for cidr in prefixSet.iter_cidrs():

        # Check if the CIDR is in the allocation for the country
        #
        if cidr in cities[city]['base']:
            # In the correct City allocation but annouced by external ASN.
            if carvedSpace:
                cities[city]['exclude'].add(cidr)
                cities[city]['carvedSpace'].add(cidr)
                if verbose_level >= 1:
                    print(
                        "{} belongs to correct city allocation but annouced by external ASN: {}, {}".format(
                            cidr, city, country
                        )
                    )
                continue
            if verbose_level >= 3:
                print("{} belongs to correct city allocation: {}, {}".format(cidr, city, country))
            continue

        # The range has come out of another countries allocation, find it and add to city
        #
        foundSupernet = False
        for snCity in cities:
            if cidr in cities[snCity]['base']:
                foundSupernet = True
                cities[snCity]['exclude'].add(cidr)
                # In different city but annnouced by an external ASN.
                if carvedSpace:
                    cities[city]['carvedSpace'].add(cidr)
                    if verbose_level >= 1:
                        print("Moving {} announced by an external ASN from {} to {}.".format(cidr, snCity, city))
                else:
                    cities[city]['additions'].add(cidr)
                    if verbose_level >= 2:
                        print("Moving {} from {} to {}.".format(cidr, snCity, city))
                break

        # This block did not belong to any existing allocation, create new one.
        if not foundSupernet:
            if verbose_level >= 2:
                print("{} is a small allocation or PI range adding to city {} allocation.".format(cidr, city))
            if piSpace:
                cities[city]['piSpace'].add(cidr)
            else:
                cities[city]['smallpiSpace'].add(cidr)


@click.command()
@click.option(
    "--config",
    metavar="CONFIG_FILE",
    help="Configuaration file to load.",
    default=os.environ["HOME"] + "/.config/iplocbuild/config.json",
    envvar='IPLOCBUILD_CONFIG_FILE',
    type=click.File(mode='r')
)
@click.option(
    '--verbose', '-v', count=True, help="Output some debug information, use multiple times for increased verbosity."
)
@click.option(
    "-o",
    "--outfile",
    default="iplocdata",
    help="The base name for the output file, csv and json extensions will be added automatically."
)
def cli(config, verbose, outfile):
    """Entry point for command."""
    # Allow acces to cfg and verbose_level vars
    #
    global cfg
    global verbose_level
    global paSpaceSet

    verbose_level = verbose
    cfg = json.load(config)

    # First convert all the cities
    #
    for city in cfg['cities']:
        if city not in cities:
            cities[city] = {
                'base': None,
                'additions': IPSet([]),
                'exclude': IPSet([]),
                'country': cfg['cities'][city]['country'],
                'piSpace': IPSet([]),
                'smallpiSpace': IPSet([]),
                'carvedSpace': IPSet([])
            }

        if 'override' in cfg['cities'][city]:
            cities[city]['override'] = IPSet(cfg['cities'][city]['override'])
        else:
            cities[city]['override'] = IPSet([])

        if 'community' in cfg['cities'][city]:
            cities[city]['community'] = cfg['cities'][city]['community']

        if 'device' in cfg['cities'][city]:
            cities[city]['device'] = cfg['cities'][city]['device']

        if 'region' in cfg['cities'][city]:
            cities[city]['region'] = cfg['cities'][city]['region']
        else:
            cities[city]['region'] = ""

        cities[city]['base'] = IPSet(cfg['cities'][city]['cidrs'])

    # Free up some memory here we don't need the cities in the cfg now.
    #
    del cfg['cities']

    # Check there are no overlapping address space
    #
    hasError = False
    for city in cities:
        for cidr in cities[city]['base'].iter_cidrs():
            for checkCity in cities:
                if checkCity == city:
                    continue
                if cidr in cities[checkCity]['base']:
                    print("ERROR: Overlapping cidr {} from {} found in {}.".format(cidr, city, checkCity))
                    hasError = True

    if hasError:
        sys.exit()

    # Now convert the PA Space

    for paPrefix in cfg['paspace']:
        paSpaceSet.add(paPrefix)

    for city in cities:

        # Skip if community or device is missing or empty
        #
        if 'community' not in cities[city]:
            continue

        if 'device' not in cities[city]:
            continue

        if not cities[city]['community']:
            continue

        if not cities[city]['device']:
            continue

        country = cities[city]['country']
        community = cities[city]['community']
        device = cities[city]['device']

        if verbose_level >= 1:
            print("Working on {}, {}, {}".format(city, country, community))

        # Get internal and small prefix routes.
        #
        prefixSet, carvedSet = get_routes(device, [community, '8220:65404'])

        # prefixSet contains our allocation address space, add it to the correct country.
        #
        if prefixSet is not None:
            process_routes(prefixSet, country, city)

        # This should never fire off.
        #
        if carvedSet is not None:
            process_routes(carvedSet, country, city, False, True)

        # Get any prefixes annouced by external ASN.
        #
        prefixSet, carvedSet = get_routes(device, [community, '8220:65403'], True)

        # prefixSet contains all PI space annoucements.
        if prefixSet is not None:
            process_routes(prefixSet, country, city, True)

        # carvedSet are routes advertised by another ASN but from our own allocation.
        # Add them to the correct country but in the carvedSet.
        #
        if carvedSet is not None:
            process_routes(carvedSet, country, city, True, True)

    # Check there are no overlapping PI address space
    #
    smallPISpace = IPSet([])
    for city in cities:
        smallPISpace = smallPISpace | cities[city]['smallpiSpace']

    for city in cities:
        for smallcidr in smallPISpace.iter_cidrs():
            for cidr in cities[city]['piSpace'].iter_cidrs():
                if smallcidr in cidr:
                    if verbose_level >= 2:
                        print(
                            "Removing duplicate (containing) PI cidr from {}: {} contains {}.".format(
                                city, cidr, smallcidr
                            )
                        )
                    cities[city]['piSpace'].remove(cidr)
                    break

    del smallPISpace

    # pp.pprint(cities)

    # Consolidate the results and do the removals and adds.
    #
    for city in cities:
        cities[city]['base'] = cities[city]['base'] | cities[city]['additions']
        cities[city]['base'] = cities[city]['base'] - cities[city]['exclude']
        cities[city]['base'] = cities[city]['base'] | cities[city]['override']
        cities[city]['piSpace'] = cities[city]['piSpace'] | cities[city]['smallpiSpace'] | cities[city]['carvedSpace']

        del cities[city]['additions']
        del cities[city]['exclude']
        del cities[city]['smallpiSpace']
        del cities[city]['carvedSpace']

        if 'community' in cities[city]:
            del cities[city]['community']

        if 'device' in cities[city]:
            del cities[city]['device']

    # Remove the override from the other cities
    #
    for city in cities:
        for cidr in cities[city]['override'].iter_cidrs():
            for checkCity in cities:
                if checkCity == city:
                    continue
                if cidr in cities[checkCity]['base']:
                    if verbose_level >= 1:
                        print("Overridden cidr {} from {} found in {}.".format(cidr, city, checkCity))
                    cities[checkCity]['base'].remove(cidr)
                if cidr in cities[checkCity]['piSpace']:
                    if verbose_level >= 1:
                        print("Overridden cidr {} from {} found in {}.".format(cidr, city, checkCity))
                    cities[checkCity]['piSpace'].remove(cidr)

        del cities[city]['override']

    # Convert for json output
    #
    for city in cities:
        cities[city]['cidrs'] = ipset_to_list(cities[city]['base'])
        del cities[city]['base']

        cities[city]['piCidrs'] = ipset_to_list(cities[city]['piSpace'])
        del cities[city]['piSpace']

    # Open the output files
    #
    csvFile = open(outfile + '.csv', 'w')
    csvPIFile = open(outfile + '_pi.csv', 'w')
    jsonFile = open(outfile + '.json', 'w')
    jsonFileCountry = open(outfile + '_country.json', 'w')

    # Output json file with full structure
    #
    json.dump(cities, jsonFile, sort_keys=True, indent=4)

    #
    # Google Feed format: ip_range,country,region,city,postal_code
    #
    csvFormat = "{},{},{},{},"

    for city in cities:
        for cidrOut in cities[city]['cidrs']:
            print(csvFormat.format(cidrOut, cities[city]['country'], cities[city]['region'], city), file=csvFile)

    for city in cities:
        cidrSet = IPSet(cities[city]['cidrs']) | IPSet(cities[city]['piCidrs'])
        for cidrOut in cidrSet.iter_cidrs():
            print(csvFormat.format(str(cidrOut), cities[city]['country'], cities[city]['region'], city), file=csvPIFile)

    # Output the data based on coutry rather than city.

    countries = {}

    for city in cities:
        country = cities[city]['country']
        if country not in countries:
            countries[country] = {'cidrs': IPSet(cities[city]['cidrs']), 'piCidrs': IPSet(cities[city]['piCidrs'])}
        else:
            countries[country]['cidrs'] = countries[country]['cidrs'] | IPSet(cities[city]['cidrs'])
            countries[country]['piCidrs'] = countries[country]['piCidrs'] | IPSet(cities[city]['piCidrs'])

    # Convert country object to lists for Json output.
    #
    for country in countries:
        countries[country]['cidrs'] = ipset_to_list(countries[country]['cidrs'])
        countries[country]['piCidrs'] = ipset_to_list(countries[country]['piCidrs'])

    # Output countries json file with full structure
    #
    json.dump(countries, jsonFileCountry, sort_keys=True, indent=4)

    # Close all the files
    #
    csvFile.flush()
    csvPIFile.flush()
    jsonFile.flush()
    jsonFileCountry.flush()

    csvFile.close()
    csvPIFile.close()
    jsonFile.close()
    jsonFileCountry.close()
