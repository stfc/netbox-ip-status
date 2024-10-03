#!/usr/bin/env python3

""" Script to tag IPs in NetBox with when they were last pingable """

from configparser import ConfigParser
import datetime
import os
import pickle
import socket
import sys

from icmplib import ping
from IPy import IP
import requests

import pynetbox

netbox_session = requests.Session()
nb = pynetbox.api(
    config.NETBOX_URL,
    token=config.API_KEY,
    threading=True
)
nb.http_session = netbox_session

prefixes = nb.ipam.prefixes.filter(tag=[config.PREFIX_TAG])

today_datetime = datetime.datetime.now()
today = today_datetime.strftime('%Y-%m-%d')

last_seen = {}


def update_addresses(addresses, prefix_mask):
    for address in addresses:
        update_address(address, prefix_mask)


def reverse_lookup(ip):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except socket.herror:
        return None


def update_address(ipy_address, prefix_mask):
    ip = ipy_address.strNormal()
    updated = False
    try:
        ping_result = ping(address=ip, timeout=0.5, interval=1, count=3)
        rev = reverse_lookup(ip)
        address = nb.ipam.ip_addresses.get(address=ipy_address.strNormal(1))
        if address is not None:
            new_tag = None

            if ping_result.is_alive:
                last_seen[str(address)] = today
                new_tag = {"name": "lastseen:today"}
            else:
                if str(address) in last_seen.keys():
                    last_seen_date = datetime.datetime.strptime(last_seen[str(address)], '%Y-%m-%d')
                    #lastseen = datetime.datetime.strptime("2021-01-01", '%Y-%m-%d')
                    delta = today_datetime - last_seen_date
                    delta = delta.days
                    if delta == 0:
                        new_tag = {"name": "lastseen:today"}
                    elif delta == 1:
                        new_tag = {"name": "lastseen:yesterday"}
                    elif 2 <= delta < 8:
                        new_tag = {"name": "lastseen:week"}
                    elif 8 <= delta < 32:
                        new_tag = {"name": "lastseen:month"}
                    elif 32 <= delta < 366:
                        new_tag = {"name": "lastseen:year"}
                    else:
                        new_tag = {"name": "lastseen:overayear"}
                else:
                    # Last seen is none, and we haven't been able to see it today either!
                    new_tag = {"name": "lastseen:never"}

            # Only update reverse DNS if it changes
            if rev is not None:
                if address.dns_name != rev:
                    address.dns_name = rev
                    updated = True

            for tag in address.tags:
                if tag.name.startswith("lastseen") and (tag.name != new_tag["name"]):
                    print("##")
                    print(str(address) + " " + tag.name + " " + new_tag["name"])
                    print(list(address.tags))
                    print("##")
                    address.tags.remove(tag)
                    address.tags.append(new_tag)
                    updated = True

            if updated:
                address.save()

        elif ping_result.is_alive:
            print(ip + " -> " + str(ping_result.is_alive))
            # The address does not currently exist in Netbox, so lets add a reservation so somebody does not re-use it.
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
            nb.ipam.ip_addresses.create(new_address)
            address = nb.ipam.ip_addresses.get(address=ipy_address.strNormal(1))
            last_seen[str(address)] = today
    except ValueError as e:
        # Lets just go to the next one
        print(e)


def main():
    global last_seen

    config = ConfigParser()
    config.read(['netbox_ip_status.cfg.default', 'netbox_ip_status.cfg'])

    if socket.getfqdn() != config['SCANNER']['PROD_HOSTNAME']:
        sys.exit(0)

    if os.path.exists(config['SCANNER']['LAST_SEEN_DATABASE']):
        try:
            last_seen = pickle.load(open(config['SCANNER']['LAST_SEEN_DATABASE'], "rb"))
        except Exception:
            pass

    for prefix in prefixes:
        prefix_ip_object = IP(prefix.prefix)
        prefix_mask = prefix.prefix.split("/")[1]
        update_addresses(prefix_ip_object, prefix_mask)

    pickle.dump(last_seen, open(config['SCANNER']['LAST_SEEN_DATABASE'], "wb"))


if __name__ == "__main__":
    main()
