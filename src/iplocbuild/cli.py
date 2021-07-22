#!/usr/bin/env python3

import click
import os
import sys
import pprint
import json
import re

from netaddr import IPSet
from lxml import etree

from jnpr.junos import Device

pp = pprint.PrettyPrinter(indent=2, width=120)

with open(os.environ['HOME'] + '/.cfg/iplocbuild.json') as cfgfile:
    cfg = json.load(cfgfile)

def ipset_to_list(ipSetFrom):
    toList = []
    for cidr in ipSetFrom.iter_cidrs():
        toList.append(str(cidr))

    return toList


def get_routes(host, communities, piSpace=False):
    try:
        with Device(host=host, user=cfg['username'], passwd=cfg['password'], transport='ssh', port='22', normalize=True) as dev:
            routesXML = dev.rpc.get_route_information(dev_timeout=60, level='detail', table='inet.0', protocol='bgp', community=communities)

            prefixSet = IPSet([])
            carvedSet = IPSet([])

            routes = routesXML.findall('.//rt')

            if len(routes) == 0:
                if prog_args.verbose >= 1:
                    print("No prefix found with communities: {}".format(str(communities)))
                return None, None

            # Regex to capture AS Path.
            #
            aspathRE = re.compile('AS path: ([\d\?I\s]+) [\w\(]')

            for rt in routes:
                #print(etree.tounicode(rt, pretty_print=True))
                prefix = rt.find('.//rt-destination').text
                prefixLen = rt.find('.//rt-prefix-length').text
                cidr = prefix + '/' + prefixLen

                if prog_args.verbose >= 3:
                    print ("Network {} : Mask {}".format(prefix, prefixLen))

                if int(prefixLen) >= 32:
                    if prog_args.verbose >= 2:
                        print("Ignoring PI prefix as /32 host route: {}".format(cidr))
                    continue

                if piSpace:
                    if cidr in paSpaceSet:

                        aspathMatch = aspathRE.match(rt.find('.//as-path').text)

                        if not aspathMatch:
                            print("ERROR finding match for AS path ({}): {}".format(rt.find('.//as-path').text, cidr))
                            print(etree.tounicode(rt, pretty_print=True))
                            continue

                        fullaspath = aspathMatch.group(1).split()

                        if fullaspath[0] != 'I' and fullaspath[0] != '?':
                            carvedSet.add(cidr)
                            if prog_args.verbose >= 1:
                                print("Carving out PA space annouced by external ASN ({}): {}".format(fullaspath[0], cidr))
                            continue

                        if prog_args.verbose >= 1:
                            print("Ignoring PI prefix as colt space: {}".format(cidr))
                        continue

                prefixSet.add(cidr)

            return prefixSet, carvedSet

    except Exception as e:
        print('ERROR: Connecting to {} failed: {}'.format(
            host, e), file=sys.stderr)
        return None, None


def process_routes(prefixSet, country, city, piSpace=False, carvedSpace=False):
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
                if prog_args.verbose >= 1:
                    print("{} belongs to correct city allocation but annouced by external ASN: {}, {}".format(cidr, city, country))
                continue
            if prog_args.verbose >= 3:
                print("{} belongs to correct city allocation: {}, {}".format(cidr, city, country))
            continue

        # The range has come out of another countries allocation, find it.
        #
        foundSupernet = False
        for snCity in cities:
            if cidr in cities[snCity]['base']:
                foundSupernet = True
                cities[snCity]['exclude'].add(cidr)
                if carvedSpace:
                    cities[city]['carvedSpace'].add(cidr)
                    if prog_args.verbose >= 1:
                        print("Moving {} announced by an external ASN from {} to {}.".format(cidr, snCity, city))
                else:
                    cities[city]['additions'].add(cidr)
                    if prog_args.verbose >= 2:
                        print("Moving {} from {} to {}.".format(cidr, snCity, city))
                break

        # This block did not belong to any existing allocation, create new one.
        if not foundSupernet:
            if prog_args.verbose >= 2:
                print("{} is a small allocation or PI range adding to city {} allocation.".format(cidr, city))
            if piSpace:
                cities[city]['piSpace'].add(cidr)
            else:
                cities[city]['smallpiSpace'].add(cidr)

@click.command()
@click.option('--verbose', '-v', action='count', default=0,
                    help="Output some debug information, use multiple times for increased verbosity.")

@click.option("-o", "--outfile", default="iplocdata",
                    help="The base name for the output file, csv and json extensions will be added automatically.")

prog_args = parser.parse_args()


def cli():
# First convert all the cities
#
cities = {}

for city in cfg['cities']:
    if city not in cities:
        cities[city] = {'base': None, 'additions': IPSet([]), 'exclude': IPSet(
            []), 'country': cfg['cities'][city]['country'], 'piSpace': IPSet([]), 'smallpiSpace': IPSet([]), 'carvedSpace': IPSet([])}

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

paSpaceSet = IPSet([])

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

    if prog_args.verbose >= 1:
        print("Working on {}, {}, {}".format(city, country, community))

    prefixSet, carvedSet = get_routes(device, [community, '8220:65404'])
    if prefixSet is not None:
        process_routes(prefixSet, country, city)
    if carvedSet is not None:
        process_routes(carvedSet, country, city, False, True)


    prefixSet, carvedSet = get_routes(device, [community, '8220:65403'], True)
    if prefixSet is not None:
        process_routes(prefixSet, country, city, True)
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
                if prog_args.verbose >= 2:
                    print("Removing duplicate (containing) PI cidr from {}: {} contains {}.".format(city, cidr, smallcidr))
                cities[city]['piSpace'].remove(cidr)
                break

del smallPISpace

#pp.pprint(cities)

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
                if prog_args.verbose >= 1:
                    print("Overridden cidr {} from {} found in {}.".format(cidr, city, checkCity))
                cities[checkCity]['base'].remove(cidr)
            if cidr in cities[checkCity]['piSpace']:
                if prog_args.verbose >= 1:
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
csvFile = open(prog_args.outfile + '.csv', 'w')
csvPIFile = open(prog_args.outfile + '_pi.csv', 'w')
jsonFile = open(prog_args.outfile + '.json', 'w')
jsonFileCountry = open(prog_args.outfile + '_country.json', 'w')

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

