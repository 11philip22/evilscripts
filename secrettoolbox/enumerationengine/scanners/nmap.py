""""The nmap scanner"""

import nmap  # make working python3 port
import logging
from multiprocessing.pool import ThreadPool
from .. import conf
from pathlib import Path
from datetime import datetime
from ..datahandler.filehandler import OutputHandler


class Nmap(object):
    def __init__(self, write_output=False, logger=True, threads=50):
        self.write_output = write_output
        self.output_folder = Path(conf["output files"]["nmap_output_folder"])
        # Create output folder
        if self.write_output:
            if not self.output_folder.is_dir():
                self.output_folder.mkdir(parents=True)

        # Set logger
        self.keep_logs = logger
        if self.keep_logs:
            self.logger = logging.getLogger('toolbox.nmap')

        self.threads = threads
        self.nm = nmap.PortScanner()

    def scan_wrapper(self, target, args: str):
        """"Wrapper around nmap.PortScanner.scan function to keep logs and write data"""
        # If write output is true append -oN argument
        if self.write_output:
            normal_output_file = Path(self.output_folder, "{0}.txt".format(target))
            # If file already exists append current time
            if normal_output_file.is_file():
                normal_output_file = Path(self.output_folder, "{0}_{1}.txt".format(
                    target, datetime.now().strftime('%Y-%m-%d_%H-%M-%S')))

            # Append normal output parameter with output file
            args = args + " -oN {0}".format(normal_output_file)

        # Do the actual scan
        result = self.nm.scan(target, arguments=args)

        # Write result dict to file
        if self.write_output:
            json_file = Path(self.output_folder, "{0}.json".format(target))
            # If file already exists append current time
            if json_file.is_file():
                json_file = Path(self.output_folder, "{0}_{1}.json".format(
                    target, datetime.now().strftime('%Y-%m-%d_%H-%M-%S')))
            json_file.touch()
            OutputHandler.write_json(result, json_file)

        if self.keep_logs:
            self.logger.debug(result)
        return result

    def scan_pool(self, ips, args):
        """"Scan multiple targets in a multiprocessing pool"""
        arg_tuples = []
        for ip in ips:
            arg_tuples.append((ip, args))
        p = ThreadPool(self.threads)
        results = p.starmap(self.scan_wrapper, arg_tuples)

        # write output to json file
        if self.write_output:
            json_file = Path(self.output_folder, "pool_{0}.json".format(datetime.now().strftime('%Y-%m-%d_%H-%M-%S')))
            json_file.touch()
            OutputHandler.write_json(results, json_file)

        return results

    def is_alive(self, ip):
        """""Check if a host is up"""
        args = "-sn"
        result = self.scan_wrapper(ip, args)
        if result["scan"]:
            if result["scan"][ip]["status"]["state"] == "up":
                return True
        return False

    def is_alive_pool_wrapper(self, ip):
        if self.is_alive(ip):
            return {ip: "up"}
        return {ip: "down"}

    def up_check(self, ips: list):
        """"Checks the up status of a list of ip addresses"""
        p = ThreadPool(self.threads)
        pool_results = p.map(self.is_alive_pool_wrapper, ips)
        results = {}
        for result in pool_results:
            results.update(result)
        return results

    def find_hosts(self, ips: list):
        """""Returns all ip addresses of hosts that are online"""
        results = []
        check_results = self.up_check(ips)
        for address in check_results:
            status = check_results[address]
            if status == "up":
                results.append(address)
        return results


# n = Nmap()
# out = n.scan_pool(["192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.1", "192.168.1.5"], "-sn ")
# out = n.find_hosts(["192.168.1.2", "192.168.1.5", "192.168.1.233"])


# def outpout_json(self, input_func):
#     """"Wrapper that writes the result of a funtion to a json file"""
#     def timed(*args, **kwargs):
#         result = input_func(*args, **kwargs)
#
#         if self.write_output:
#             name = "_"
#             if isinstance(args[0], str):
#                 name = args[0]
#             elif isinstance(args[0], list):
#                 name = "pool"
#             json_file = Path(self.output_folder, "{0}_{1}.json".format(
#                 name, datetime.now().strftime('%Y-%m-%d_%H-%M-%S')))
#             json_file.touch()
#             with open(json_file, "w") as twitter_data_file:
#                 dump(result, twitter_data_file, indent=4, sort_keys=True)
#
#         return result
#     return timed
