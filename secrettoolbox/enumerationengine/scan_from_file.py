""""Reads dnsrecon and amass output files for ip4 addresses.
    Scans for online hosts and Scans them using Nmap"""

from .datahandler.filehandler import InputHandler
from .datahandler.ip import sort_ips
from .scanners.nmap import Nmap
from . import logger

i = InputHandler()

all_ips = i.all_get_ip()
logger.info("Found {0} unique ip addresses".format(len(all_ips)))
logger.debug(all_ips)

ipv4_address = sort_ips(all_ips)["ipv4"]
logger.info("Found {0} ip4 addresses".format(len(ipv4_address)))
logger.debug(ipv4_address)

n = Nmap()
logger.info("Starting upcheck")
up_hosts = n.find_hosts(ipv4_address)
logger.info("Found {0} online hosts".format(len(up_hosts)))
logger.debug(up_hosts)

logger.info("Starting scan")
n.write_output = True
scan_results = n.scan_pool(up_hosts, "-A -Pn -p-")
logger.debug(scan_results)

# logger.info("Starting scan")
# n.write_output = True
# scan_results = n.scan_pool(ipv4_address, "-A -p-")
# logger.debug(scan_results)
