# Written for alien(G2V020)
# OG Author(Alien): J4ck3LSyN
# https://github.com/J4ck3LSyN-Gen2/Alien/
from typing import Callable, List, Any, Dict, Optional

__author__ = 'J4ck3LSyN'
__version__ = '0.0.1'

class hivemind:

    def __init__(self,iT:Callable):

        self.iT = iT

        print(True)

global hivemindObject

def setHivemindObject(self,iT):
    """"""
    hivemindObject = hivemind(iT)

__alienProgramLibraries__ = {
    "hivemind-Setup":{
        # "init":lambda iT: setHivemindObject(iT),
        "test":lambda: print(True)
    }
}
__alienProgramData__ = {
    "metadata": {
        "author": "J4ck3LSyN",
        "title": "hivemind-programData",
        "version": "0.0.0",
        "description": "Hivemind conceptual c2 communications.",
        "dependencies": []
    },
    "functions": {
    },
    "classes": {},
    "globals": {},
    "inline": [
        
    ]
}