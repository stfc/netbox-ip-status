import config
import pynetbox
import requests
from icmplib import ping
import datetime
import multiprocessing
import socket

netbox_session = requests.Session()
netbox_session.verify = config.CA_CERTS_LOCATION
nb = pynetbox.api(
    config.NETBOX_URL,
    token=config.API_KEY,
    threading=True
)
nb.http_session = netbox_session

prefixes = nb.ipam.prefixes.all()

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

def update_address(address):
    ip, prefixlen = address.address.split("/")
    if prefixlen == "32": # if the prefix length is /32, otherwise we can't ping it anyway
        try:
            ping_result = ping(ip)
            address.custom_fields["reverse"] = reverse_lookup(ip)
            address.tags = [x for x in address.tags if "lastseen" not in x] # Remove any lastseen: tags, but keep others
            if ping_result.is_alive:
                address.custom_fields["lastseen"] = today
                address.tags.append("lastseen:today")
            else:
                if address.custom_fields["lastseen"] != None:
                    lastseen = datetime.datetime.strptime(address.custom_fields["lastseen"], '%Y-%m-%d')
                    #lastseen = datetime.datetime.strptime("2021-01-01", '%Y-%m-%d')
                    delta = today_datetime - lastseen
                    delta = delta.days
                    if delta == 1:
                        address.tags.append("lastseen:yesterday")
                    elif delta > 1 and delta < 8:
                        address.tags.append("lastseen:week")
                    elif delta > 7 and delta < 32:
                        address.tags.append("lastseen:month")
                    elif delta > 31 and delta < 366:
                        address.tags.append("lastseen:year")
                    else:
                        address.tags.append("lastseen:overayear")
                else:
                    # Last seen is none, and we haven't been able to see it today either!
                    address.tags.append("lastseen:never")
        except Exception as e:
            # Lets just go to the next one
            print(e)

addresses = nb.ipam.ip_addresses.all()
addresses = list(addresses)
chunks = chunk(addresses, config.NUM_PROCS) # split address pool into chunks, the number of chunks equaling the number of processes we're about to spawn
if len(chunks) > 0:
    for i in range(config.NUM_PROCS):
        if len(chunks[i]) > 0: # Check we actually have an address in this chunk, if not, don't fire up a wasted process for it
            p = multiprocessing.Process(target=update_addresses, args=(chunks[i],))
            p.start() # actually spawn the process