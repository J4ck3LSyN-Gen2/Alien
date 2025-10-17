import os
import json
import argparse
import sys
import traceback
import time
import string
from typing import List, Any, Optional, Callable, Dict, Union
# Core
from .core import loggerHandle
from .core import configHandle
from .core import interpreterHandle
from .core import processHandle
from .core import memoryHandle

# Utils
from .utils import path
from .utils import variables
from .utils import transmission
from .utils import systemInfo


__version__ = "0.1.0"

class Alien:

    """
    *-- Main Alien Application --*

    Usage: py -m ALNv2020 ...

    Args:
        useLogging (bool, optional): Default = True
    """

    def __init__(self,useLogging:bool=True):

        self.logger = loggerHandle("Alien:Gen2 Version 0.2.0")
        self.spacer = f"\n*{str('-'*48)}*"
        self.config = {
            "logging":useLogging,
            "desc":{
                "mainDesc":str("\n").join([
                    'version: 2.0.2.0', 
                    'author:  J4ck3LSyN',
                    'python version: 3.14',
                    '', 
                    'Usage: py -m ALNv2020 <args> <mode> <args> ...',
                    '',
                    'Description:',
                    'The alien framework(ALNv2020) is a modular toolkit centered', 
                    'around a powerful, programmable JSON-based interpreter. It is', 
                    'engineered for a wide array of software engineering and', 
                    'cybersecurity-related tasks, enabling the execution of complex', 
                    'logic operations with libraries, executable scripts, pythonic', 
                    'operations, threading, LLM(ollama) communications, low-level', 
                    'memory/process management, and network communication.',
                    ''
                ]),
                "modes":str("\n").join([
                    "Interpreter(intr):",
                    "\tUsage: py -m ALNv2020 <args> intr '<file>/<data>' <args> <kwargs>",
                    ""
                ])
            },
            "verbose":False,
        }
        # Setup the parsers for argparse 
        self.parser = argparse.ArgumentParser(
            description=self.config['desc']['mainDesc'],
            formatter_class=argparse.RawDescriptionHelpFormatter
        )
        self.modeSubparser = self.parser.add_subparsers(
            dest="mode",
            help=self.config['desc']['modes']
        )
        # initialize
        self._initGlobalArgs()
        self._initParserIntr()
        self._initParserInstall()
        self.parsedArgs = self.parser.parse_args()
        if hasattr(self.parsedArgs,'func'):
            self.parsedArgs.func()
        else: self.parser.print_help()

    ## Parser inits
    # global
    def _initGlobalArgs(self):
        """"""
        self.parser.add_argument(
            "-v","--verbose",
            help="Enable verbose output, from logPipe.",
            action="store_true"
        )
    
    # intr, interpreter
    def _initParserIntr(self):
        """"""
        self.intrSubparser = self.modeSubparser.add_parser(
            "intr",
            # Use a short, single-line summary for the 'help' parameter.
            help="Run the Alien interpreter for file or data execution.",
            # Move the detailed, multi-line text to the 'description' parameter.
            description=str("\n").join([
                "Pre-Args:",
                "-l, --logging",
                "\tIf given then `logPipe` will be executed inside of,",
                "\t`interpreterHandle`.",
                "\tNOTE: Heavily impacts performance but gives good info.",
                "-n,--new",
                "\tCreates a new file under the given name inside of",
                "\tALNv2020/interpreterScripts/ with fresh program data.",
                "-e,--exec",
                "\tInstead of giving a `file` the internal string will be",
                "\thandled as JSON data for the interpreter. Were it will",
                "\tbe loaded & ran."
            ]),
            # This formatter will now correctly apply to your 'description'.
            formatter_class=argparse.RawDescriptionHelpFormatter
        )
        # new progrma
        # logging 
        self.intrSubparser.add_argument(
            "-l","--logging",
            help=str("\n").join([
                "If given then `logPipe` will be executed inside of,",
                "`interpreterHandle`.",
                "",
                "NOTE: Heavily impacts performance but gives good info."
            ]),
            action="store_true"
        )
        self.intrSubparser.add_argument(
            "-nP","--newProject",
            help=str("\n").join([
                "Creates a new file under the given name inside of",
                "ALNv2020/interpreterScripts/ with fresh program data."
            ]),
            action="store_true"
        )
        self.intrSubparser.add_argument(
            "-nPL","--newPythonicLibrary",
            help=str("\n").join([
                "Creates a new file under the given name inside of",
                "ALNv2020/libs/ with fresh pythonic alien library data."
            ]),
            action="store_true"
        )

        self.intrSubparser.add_argument(
            "-e","--exec",
            help=str("\n").join([
                "Instead of giving a `file` the internal string will be",
                "handled as JSON data for the interpreter. Were it will",
                "be loaded & ran.",
                "",
                "Along side `file` the `args` & `kwargs` will still be set",
                "inside of `globals`."
                "",
                "Example:",
                "\tpy -m ALNv2020 -e intr '[{..},..](Alien syntax)' ..."
            ]),
            action="store_true"
        )
        #self.intrSubparser.add_argument(
        #    "-pD","--preloadData",
        #    help=str("\n").join([
        #        "Data to load and run "
        #    ]),
        #    type=str
        #)
        # file
        self.intrSubparser.add_argument(
            "target",
            help=str("\n").join([
                "Input information (with no `-e` it will expect a file.)",
                "",
                "If a `file` it can be an absolute `path` or a `file`",
                "inside of 'ALNv2020/interpreterScripts/'.",
                "",
                "Example:",
                "\tpy -m ALNv2020 intr 'benchmark.json'"
            ]),
            type=str
        )
        # arguments
        self.intrSubparser.add_argument(
            "arguments",
            nargs=argparse.REMAINDER,
            help=str("\n").join([
                "Args & Keyword Args for the input file/data.",
                "",
                "Keyword arguments are given `arg=value` args are",
                "just `value`.",
                "",
                "Example:",
                "\tpy -m ALNv2020 intr 'target.json' 123 key=true"
            ])
        )
        self.intrSubparser.set_defaults(func=self.intrHandleExec)

    # install, remove & updates
    def _initParserInstall(self):
        """"""
        self.installSubparser = self.modeSubparser.add_parser(
            "install",
            help="Various installation operations, both remote and local. (Under-construction).",
            description="",
            formatter_class=argparse.RawDescriptionHelpFormatter
        )
        self.installSubparser.add_argument(
            "-rH","--remoteHost",
            help="Remote host to connect to.",
            type=str
        )
        self.installSubparser.add_argument(
            "-rP","--remotePort",
            help="Remote port to use.",
            type=int
        )
        self.installSubparser.add_argument(
            "-lH","--localHost",
            help="Local host address to use (default: localhost:127.0.0.1)",
            type=str
        )
        self.installSubparser.add_argument(
            "-lP","--localPort",
            help="Local port to use.",
            type=int
        )
        self.installSubparser.add_argument(
            "type",
            help="Type of installation operation to perform.",
            type=str
        )
        self.installSubparser.set_defaults(func=self.installHandleExec)
    # def _initParserServ
    # def _initParserHost
    # def _initParserConn

    ## Parser handles

    def installHandleExec(self):
        """"""
        iH = self.installHandle(self)

    # installers
    class installHandle:

        """
        *-- Installation Methods Via LAN --*

        NOTE: Mainly developed to properly install
              python 3.14 and Alien inside of Termux.
              However the end game would be a global
              installer.
        """

        def __init__(self,alienInstance:Alien):
            """"""
            self.alien = alienInstance
            self.proc = processHandle()
            self.sock = transmission.sock(self.proc)

            self.config = {
                "remote.netcat":[
                    "cd ~",
                    "termux-setup-storage"
                ],
                "timeout":60
            }

            self.type = self.alien.parsedArgs.type

        

    # interpreter
    def intrHandleExec(self):
        """"""
        iH = self.intrHandle(self)

    class intrHandle:
        def __init__(self,alienInstance:Alien):
            self.alien = alienInstance
            self.config = {

            }
            self.iT = interpreterHandle(
                logger=self.alien.logger
            )
            self.iT.config['allowLogPipe']=self.alien.parsedArgs.logging
            self.alien.logPipe("__init__","Initializing Interpreter Operations",f=self.alien.config['verbose'])
            # Validate only one is set
            if self.alien.parsedArgs.newProject and self.alien.parsedArgs.newPythonicLibrary:
                eM = "Cannot be given `-nP` & `-nPL`..."
                self.alien.logPipe("__init__",eM,l=2,f=self.alien.config['verbose'])
                self.alien.intrSubparser.print_help()
                self._clearAndExit()
            # newProject
            if self.alien.parsedArgs.newProject:
                if not self.alien.parsedArgs.target:
                    eM = "'target' was not given for `-nP`(--newProject)."
                    self.alien.logPipe("__init__",eM,l=2)
                    self.alien.intrSubparser.print_help()
                    self.alien._exit()
                self._writeRawProject(self.alien.parsedArgs.target)
                self._clearAndExit()
            if self.alien.parsedArgs.newPythonicLibrary:
                if not self.alien.parsedArgs.target:
                    eM = f"`target` was not given for `-nPL`(--newPythonicLibrary)."
                    self.alien.logPipe("__init__",eM,l=2,f=self.alien.config['verbose'])
                    self.alien.intrSubparser.print_help()
                    self._clearAndExit()
                self._writeRawPythonicLibrary(self.alien.parsedArgs.target)
                self._clearAndExit()
                
            # Load __args__ & __kwargs__ (if any)
            self._loadArgs()
            # exec
            if self.alien.parsedArgs.exec:
                if not self.alien.parsedArgs.target:
                    eM = "'target' was not given for `-e`(exec)."
                    self.alien.logPipe("_initParserIntr",eM,l=2)
                    self.alien.intrSubparser.print_help()
                    self._clearAndExit()
                try:
                    # Directly load the JSON string from the target argument.
                    # The shell handles the outer quotes, so we receive the raw JSON string.
                    data = json.loads(self.alien.parsedArgs.target)
                    # Load and run the data  (program)
                    self.iT.load(data)
                    self.alien.logPipe("__init__", f"Loaded data from exec string... Executing...", f=self.alien.config['verbose'])
                    self.iT.run()
                except Exception as E:
                    eM = f"Exception while attempting to load JSON-Alien data: {str(E)}."
                    self.alien.logPipe("_initParserIntr",eM,l=2,f=self.alien.config['verbose'])
                    self.alien.intrSubparser.print_help()
                    self._clearAndExit()
            else:
                data = self.alien.parsedArgs.target
                # Load the data
                self.iT.load(data)
                self.alien.logPipe("__init__",f"Loaded '{str(data)}'... Executing...",f=self.alien.config['verbose'])
                self.iT.run()
            self.alien.logPipe("__init__",f"Data '{str(data)}' finished execution.",f=self.alien.config['verbose'])
            self._clearAndExit()

        def _clearAndExit(self):
            """"""
            self.alien.logPipe("_clearAndExit","Exiting Alien...",f=self.alien.config['verbose'])
            self.iT._clearPyCache()
            self.alien._exit()

        def _loadArgs(self):
            """
            Loads `__args__` & `__kwargs__` into `self.iT.sessionData['globals']`.
            """
            preArgs = self.alien.parsedArgs.arguments
            args = []
            kwargs = {}
            for arg in preArgs:
                if str("=") in str(arg):
                    key,val = arg.split("=")
                    isDigit = True
                    for i in val:
                        if i not in string.digits:
                            isDigit = False
                            break
                    isBool = True
                    if val.lower() in ["true","false"]: val = True if val.lower() == "true" else False
                    elif isDigit: val = int(val)
                    kwargs[key] = val
                else: args.append(arg)
            self.iT.sessionData['globals']['__args__'] = args
            self.iT.sessionData['globals']['__kwargs__'] = kwargs
            self.alien.logPipe("_loadArgs","Loaded args & kwargs.",e={
                "args":str(args),
                "kwargs":str(kwargs)
            },f=self.alien.config['verbose'])

        def _writeRawProject(self,path:str,basePath:str=None):
            """
            Create a fresh file with raw alien program data for new projects.
            """
            data = self.iT._returnRawProgramData()
            basePath = basePath if basePath else self.iT.basePath / self.iT.config['scriptPath']
            if not self.iT.path.exist(basePath):
                eM = f"'{str(basePath)}' does not exist."
                self.logPipe("_writeRawProject",eM,l=2,f=self.alien.config['verbose'])
                raise FileNotFoundError
            fullPath = basePath / path
            json.dump(data,open(str(fullPath),'w',encoding='utf-8'),indent=4)
            self.alien.logPipe("_writeRawProject",f"Wrote new program data to '{str(fullPath)}'",f=self.alien.config['verbose'])

        def _writeRawPythonicLibrary(self,path:str,basePath:str=None):
            """
            Writes a frsh file with raw pythonic alien library data.
            """
            data = self.iT._returnRawPythonicLibraryData()
            basePath = basePath if basePath else self.iT.basePath / self.iT.config['moduleLibs']
            if not self.iT.path.exist(basePath):
                eM = f"'{str(basePath)}' does not exist."
                self.logPipe("_writeRawPythonicLibrary",eM,l=2,f=self.alien.config['verbose'])
                raise FileNotFoundError
            if not str(path).endswith('.py'): path = f"{str(path)}.py"
            fullPath = basePath / path
            if self.iT.path._existFile(str(fullPath)):
                eM = f"'{str(fullPath)}' is existant."
                self.logPipe("_writeRawPythonicLibrary",eM,l=2,f=self.alien.config['verbose'])
                self._clearAndExit()
            with open(fullPath,'w') as fW:
                fW.write(str(data))
                fW.close()
            self.alien.logPipe("_writeRawPythonicLibrary",f"Wrote new library data to '{str(fullPath)}'.",f=self.alien.config['verbose'])
            self._clearAndExit()


    # class servHandle
    # class connHandle

    def _exit(self):
        """"""
        self.logPipe("_exit","Exiting...",f=self.config['verbose'])
        sys.exit(0)

    ## Main
    # Log Pipe
    def logPipe(self,r,m,l=None,e=None,f=False): 
        """"""
        if self.config['logging'] == True and self.logger: self.logger.logPipe(r,m,loggingLevel=l,extendedContext=e,forcePrintToScreen=f)



if __name__ == "__main__":
    app = Alien()
