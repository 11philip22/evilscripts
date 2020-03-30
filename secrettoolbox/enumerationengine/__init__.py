from requests import get
from time import sleep
from .config.config import get_config
from pathlib import Path
from datetime import datetime
import logging

""""Set global config"""
conf = get_config()

""""To make sure your vpn works"""
ip = get('https://api.ipify.org').text
print("Ip is: ", ip)

# Exit if wrong ip
if conf["vpn"]["vpn_check"] == "true":
    if ip == conf["vpn"]["wrong_ip"]:
        print("Wrong ip! Please check your vpn connection")
        exit(1)

print("Starting in 5 seconds")
sleep(5)

""""Create a logger"""
# Make log folder if it does not exist
log_folder = conf["log files"]["log_folder"]
log_folder_path = Path(log_folder)
if not log_folder_path.is_dir():
    log_folder_path.mkdir()

# make Log file
current_time = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
log_file_path = Path(log_folder_path, "ssdl_{0}.log".format(current_time))
if not log_file_path.is_file():
    log_file_path.touch()

# Create logger
logger = logging.getLogger('toolbox')
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler(str(log_file_path))
fh.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
ch.setFormatter(formatter)
logger.addHandler(fh)
logger.addHandler(ch)
