import config
import pynetbox
import requests
from icmplib import ping
import datetime
import multiprocessing
import socket
from IPy import IP

netbox_session = requests.Session()
netbox_session.verify = False
nb = pynetbox.api(
    config.NETBOX_URL,
    token=config.API_KEY,
    threading=True
)
nb.http_session = netbox_session

prefixes = nb.ipam.prefixes.filter(tag=[config.PREFIX_TAG])

today_datetime = datetime.datetime.now()
today = today_datetime.strftime('%Y-%m-%d')

def chunk(l, n):
    return list(l[i::n] for i in range(n))

def update_addresses(addresses):
    for address in addresses:
        update_address(address)

def reverse_lookup(ip):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except socket.herror:
        return None

def update_address(ipy_address):
    ip = ipy_address.strNormal()
    print(ip)
    try:
        ping_result = ping(ip)
        rev = reverse_lookup(ip)
        address = nb.ipam.ip_addresses.get(address=ipy_address.strNormal(1) + "/32")
        if address is not None:
            if rev is not None:
                address.dns_name = rev
            newtags = []
            for tag in address.tags:
                if "lastseen" not in str(tag):
                    newtags.append(tag)
            address.tags = newtags # Remove any lastseen: tags, but keep others
            if ping_result.is_alive:
                address.custom_fields["lastseen"] = today
                address.tags.append({"name": "lastseen:today"})
            else:
                if address.custom_fields["lastseen"] != None:
                    lastseen = datetime.datetime.strptime(address.custom_fields["lastseen"], '%Y-%m-%d')
                    #lastseen = datetime.datetime.strptime("2021-01-01", '%Y-%m-%d')
                    delta = today_datetime - lastseen
                    delta = delta.days
                    if delta == 0:
                        address.tags.append({"name": "lastseen:today"})
                    elif delta == 1:
                        address.tags.append({"name": "lastseen:yesterday"})
                    elif delta > 1 and delta < 8:
                        address.tags.append({"name": "lastseen:week"})
                    elif delta > 7 and delta < 32:
                        address.tags.append({"name": "lastseen:month"})
                    elif delta > 31 and delta < 366:
                        address.tags.append({"name": "lastseen:year"})
                    else:
                        address.tags.append({"name": "lastseen:overayear"})
                else:
                    # Last seen is none, and we haven't been able to see it today either!
                    address.tags.append({"name": "lastseen:never"})
            address.save()
        elif ping_result.is_alive:
            # The address does not currently exist in Netbox, so lets add a reservation so somebody does not re-use it.
            new_address = {
                "address": ipy_address.strNormal(1) + "/32",
                "tags": [
                    {"name": "found"},
                    {"name": "lastseen:today"}
                ],
                "status": "reserved",
                "custom_fields": {
                    "lastseen": str(today)
                }
            }
            if rev is not None:
                new_address["dns_name"] = rev
            nb.ipam.ip_addresses.create(new_address)
    except Exception as e:
        # Lets just go to the next one
        print(e)

for prefix in prefixes:
    prefix_ip_object = IP(prefix.prefix)
    chunks = chunk(prefix_ip_object, config.NUM_PROCS) # split address pool into chunks, the number of chunks equaling the number of processes we're about to spawn
    if len(chunks) > 0:
        for i in range(config.NUM_PROCS):
            if len(chunks[i]) > 0: # Check we actually have an address in this chunk, if not, don't fire up a wasted process for it
                p = multiprocessing.Process(target=update_addresses, args=(chunks[i],))
                p.start() # actually spawn the process
