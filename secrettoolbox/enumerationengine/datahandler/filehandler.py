""""Read and write stuff from files"""

from json import loads, load, dumps, dump
from os import linesep
from .. import conf
from pathlib import Path


class InputHandler(object):
    """""Get data from output files"""
    def __init__(self):
        self.amass_file = None
        self.dnsrecon_file = None
        self.update_file_paths()

    def update_file_paths(self):
        """"If output file exists set file path as class variable"""
        amass_file = conf["output files"]["amass_output"]
        if Path(amass_file).is_file():
            self.amass_file = conf["output files"]["amass_output"]

        dnsrecon_file = conf["output files"]["dnsrecon_output"]
        if Path(dnsrecon_file).is_file():
            self.dnsrecon_file = conf["output files"]["dnsrecon_output"]

    @classmethod
    def json_from_file(cls, file):
        with open(file) as json_file:
            data = load(json_file)
        return data
    
    @classmethod
    def make_unique(cls, seq):
        return {}.fromkeys(seq).keys()

    @staticmethod
    def amass_get_ip(file):
        """"reads from an amass output json file and returns all unique ip addresses"""
        ip_addresses = []
        with open(file) as json_file:
            for line in json_file:
                json_line = loads(line)
                ip4 = json_line["addresses"][0]
                result = ip4["ip"]
                ip_addresses.append(result)
        return ip_addresses

    @staticmethod
    def dns_recon_get_ip(file):
        """"reads from an dnsrecon output json file and returns all unique ip addresses"""
        ip_addresses = []
        with open(file) as json_file:
            data = load(json_file)
        del data[0]

        for result in data:
            first_key = next(iter(result))
            if first_key == "address":
                ip = result["address"]
                ip_addresses.append(ip)
        return ip_addresses

    def all_get_ip(self):
        """"Takes as input a dict with the filenames of the output files"""
        ips = self.amass_get_ip(self.amass_file) + self.dns_recon_get_ip(self.dnsrecon_file)
        un_ips = self.make_unique(ips)
        return list(un_ips)


class OutputHandler(object):
    """"Write to files"""
    @classmethod
    def write_file(cls, out_file, data: str):
        with open(out_file, "w") as file:
            file.write(data)

    @classmethod
    def write_json(cls, json_data, file):
        with open(file, "w") as twitter_data_file:
            dump(json_data, twitter_data_file, indent=4, sort_keys=True)

    @staticmethod
    def prepare_json(json):
        return dumps(json, indent=4)

    @staticmethod
    def insert_newlines(input_list: list):
        """"Inserts newlines in between list items"""
        return [x for y in (input_list[i:i + 1] + [linesep] * (i < len(input_list) - 2) for
                            i in range(0, len(input_list), 3)) for x in y]

    @staticmethod
    def generate_code_tags(code, code_type):
        """"Used for markdown"""
        return ['""""{0}'.format(code_type), code, '""""']

    def write_buffer(self, file, buffer: list):
        """"Prepares text blob from list each list item will be on a new line"""
        prepared_buffer = self.insert_newlines(buffer)
        self.write_file(file, "".join(prepared_buffer))
