from configparser import ConfigParser
from pathlib import Path
from os.path import realpath, dirname


def get_config():
    script_folder = dirname(realpath(__file__))
    config_file = Path(script_folder, "config.ini")
    config = ConfigParser()
    config.read(str(config_file))

    return config
