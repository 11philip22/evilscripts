from .. import conf
from .filehandler import InputHandler, OutputHandler
from pathlib import Path
from os import listdir, remove


class NmapHandler(InputHandler, OutputHandler):
    output_folder = Path(conf["output files"]["nmap_output_folder"])

    """"Get data from nmap output"""
    def __init__(self):
        super().__init__()

        self.scan_data = []

    def read_from_file(self, file):
        """"Set input from a single file"""
        data = super().json_from_file(file)
        self.set_data(data)

    def read_from_dir(self):
        """"Use files from output dir defined in config"""
        data = []
        for file_name in listdir(self.output_folder):
            if file_name.endswith(".json"):
                file_path = Path(self.output_folder, file_name)
                data.append(super().json_from_file(file_path))
        self.set_data(data)

    def set_data(self, data):
        self.scan_data = data

    @classmethod
    def rm_empty_nmap_results(cls):
        """"Removes all empty nmap scan results"""
        removed_files = []
        for file in listdir(cls.output_folder):
            if file.endswith(".json"):
                json_file_path = Path(cls.output_folder, file)
                txt_file_path = Path(cls.output_folder, file.replace("json", "txt"))
                json_data = InputHandler.json_from_file(json_file_path)
                if not json_data["scan"]:
                    remove(json_file_path)
                    remove(txt_file_path)
                    removed_files.append([json_file_path, txt_file_path])
            return removed_files

    def find_port(self, target: int):
        """"Finds a port in self.scan_data.
            Outputs dict with ips where port is found with nmap data"""
        self.rm_empty_nmap_results()
        results = {}
        for scan in self.scan_data:
            for scan_key in scan["scan"]:
                scan_data = scan["scan"][scan_key]
                try:
                    ports = scan_data["tcp"]
                    for port in ports:
                        if int(port) == target:
                            result_ip = scan_data["addresses"]["ipv4"]
                            result_data = ports[port]
                            results[result_ip] = result_data
                            continue
                except KeyError:
                    continue
        return results

# from enumerationengine.datahandler.nmaphandler import NmapHandler
# n = NmapHandler()
# n.read_from_dir()
# n.find_port()
