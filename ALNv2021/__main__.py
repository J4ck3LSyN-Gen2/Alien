from datetime import datetime # type: ignore
import time, random, string, base64, requests # type: ignore
import json, os, colorama, re, shutil # type: ignore 
from typing import Union, List, Dict, Optional, Any, Callable, Tuple
from pathlib import Path as pathLibPath # type: ignore
import argparse

from . import core
from . import utils

__version__ = "0.0.7"

class alienApp:

    def __init__(self,app:bool=False):
        self.config = {

        }
        self.logger = core.loggerHandle("Alien-Gen2-021")
        self.confHandle = core.configHandle()
        self.proc = core.processHandle()
        # Internal mods
        self.atlas = None
        self.inter = None
        self.install = None
        # Utility
        self.transmit = utils.transmission
        self.misc = utils.misc
        self.sysInfo = utils.systemInfo
        self.compress = utils.compress
        self.cypher = utils.cypher
        self.psu = utils.PSU
        self.vars = utils.variables
        # Initlize Parsers 
        self.app = app
        self.parsCentral = None
        self.parsSubMode = None
        self.parsInterMode = None
        self.parsSockMode = None
        self.parsAtlasMode = None
        self.parsUtilMode = None
        


    def _initParsers(self):
        """"""
        self.parsCentral = argparse.ArgumentParser()
        # Add global arguments
        
        # Mode
        # subParserMode = self.parsCentral.add_subparsers(dest="mode",
        #                                                 description="Mode of Operation.",
        #                                                 required=True)
        ## ATLAS
        ## INTERPRETER
        ## INSTALL
        ## UTILS
        

        

if __name__ == "__main__":
    aApp = alienApp(app=True)