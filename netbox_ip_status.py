#!/usr/bin/env python3

""" Script to tag IPs in NetBox with when they were last pingable """

from configparser import ConfigParser
from subprocess import Popen, PIPE
import datetime
import logging
import os
import pickle
import socket
import sys

from IPy import IP
import requests

import pynetbox

today_datetime = datetime.datetime.now()
today = today_datetime.strftime('%Y-%m-%d')
last_seen = {}
logger = logging.getLogger('netbox-ip-status')


def ping_addresses(netbox, addresses, prefix_mask):
    with Popen(["fping", "-a", "-g", str(addresses)], stdout=PIPE, stderr=PIPE) as fping:
        ips_alive = fping.communicate()[0].decode('utf8').splitlines()
        logger.debug("fping returned: %s", ips_alive)

        for address in addresses:
            process_address(netbox, address, prefix_mask, str(address) in ips_alive)


def reverse_lookup(ip):
    logger.debug("Getting reverse DNS for %s", ip)
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except socket.herror:
        return None


def generate_tag(address, is_alive):
    logger.debug("Generating tag for %s", address)
    if is_alive:
        logger.debug("Is alive")
        last_seen[str(address)] = today
        return {"name": "lastseen:today"}

    if str(address) in last_seen.keys():
        last_seen_date = datetime.datetime.strptime(last_seen[str(address)], '%Y-%m-%d')
        delta = today_datetime - last_seen_date
        delta = delta.days
        tag = {"name": "lastseen:overayear"}

        if delta == 0:
            tag =  {"name": "lastseen:today"}
        elif delta == 1:
            tag =  {"name": "lastseen:yesterday"}
        elif 2 <= delta < 8:
            tag =  {"name": "lastseen:week"}
        elif 8 <= delta < 32:
            tag =  {"name": "lastseen:month"}
        elif 32 <= delta < 366:
            tag =  {"name": "lastseen:year"}

        logger.debug("tag = %s", tag)
        return tag

    # Last seen is none, and we haven't been able to see it today either!
    logger.debug("Never seen")
    return {"name": "lastseen:never"}


def update_tag(address, new_tag):
    logger.debug("Adding tag %s to %s", new_tag, address)
    logger.debug("Tags before: %s", address.tags)
    updated = False
    for tag in address.tags:
        logger.debug("Examining tag: %s", tag)
        if tag.name.startswith("lastseen") and (tag.name != new_tag["name"]):
            address.tags.remove(tag)
            address.tags.append(new_tag)
            updated = True
    logger.debug("Tags after: %s", address.tags)
    return address, updated


def add_address(netbox, ipy_address, prefix_mask, rev):
    logger.debug("Adding new address %s", ipy_address)
    new_address = {
        "address": ipy_address.strNormal(1) + "/" + prefix_mask,
        "tags": [
            {"name": "found"},
            {"name": "lastseen:today"}
        ],
        "status": "reserved",
    }
    if rev is not None:
        new_address["dns_name"] = rev
    netbox.ipam.ip_addresses.create(new_address)
    address = netbox.ipam.ip_addresses.get(address=ipy_address.strNormal(1))
    last_seen[str(address)] = today


def process_address(netbox, ipy_address, prefix_mask, is_alive):
    logger.debug("processing address %s, is_alive=%s", ipy_address, is_alive)
    ip = ipy_address.strNormal()
    rev_updated = False
    tag_updated = False

    rev = reverse_lookup(ip)
    logger.debug("reverse DNS is %s", rev)

    address = netbox.ipam.ip_addresses.get(address=ipy_address.strNormal(1))

    if address is not None:
        new_tag = generate_tag(address, is_alive)
        address, tag_updated = update_tag(address, new_tag)

        # Only update reverse DNS if it changes
        if rev is not None:
            if address.dns_name != rev:
                address.dns_name = rev
                rev_updated = True

        if rev_updated or tag_updated:
            address.save()

    elif is_alive:
        # The address does not currently exist in Netbox, so lets add a reservation so somebody does not re-use it.
        add_address(netbox, ipy_address, prefix_mask, rev)



def main():
    global last_seen

    config = ConfigParser()
    config.read(['netbox_ip_status.cfg.default', 'netbox_ip_status.cfg'])

    logging.basicConfig(level=config['SCANNER']['LOG_LEVEL'], format="%(levelname)-8s %(name)-22s %(funcName)-16s %(message)s")

    logger.debug("Starting NetBox session")
    netbox_session = requests.Session()
    netbox = pynetbox.api(
        config['NETBOX']['URL'],
        token=config['NETBOX']['API_KEY'],
        threading=True
    )
    netbox.http_session = netbox_session

    logger.debug("Getting prefixes from NetBox")
    prefixes = netbox.ipam.prefixes.filter(tag=[config['NETBOX']['PREFIX_TAG']])

    if socket.getfqdn() != config['SCANNER']['PROD_HOSTNAME']:
        logger.error("This is not the production host, exiting now to prevent damage.")
        sys.exit(0)

    if os.path.exists(config['SCANNER']['LAST_SEEN_DATABASE']):
        try:
            last_seen = pickle.load(open(config['SCANNER']['LAST_SEEN_DATABASE'], "rb"))
            logger.debug("LAST_SEEN_DATABASE loaded")
        except Exception:
            logger.info("LAST_SEEN_DATABASE does not exist, will be created on this run.")
            pass

    for prefix in prefixes:
        logger.info("Scanning prefix %s", prefix)
        prefix_ip_object = IP(prefix.prefix)
        prefix_mask = prefix.prefix.split("/")[1]
        ping_addresses(netbox, prefix_ip_object, prefix_mask)

    pickle.dump(last_seen, open(config['SCANNER']['LAST_SEEN_DATABASE'], "wb"))


if __name__ == "__main__":
    main()
