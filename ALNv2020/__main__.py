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

class Developer:

    def __init__(self):

        self.logger    = loggerHandle('Alien(2.0.2.0):MainApplication')
        self.path      = path.path(home='ALNv2020\\',logger=self.logger)
        self.variables = variables.variables(logger=self.logger)
        self.config    = configHandle()
        self.interpreter = interpreterHandle()

        self.applications = {
            'helloWorld':{
                'metadata':{
                    'author':'J4ck3LSyN',
                    'title':'Hello World!',
                    'version':'alpha-0.1',
                    'description':'Hello World, example program.',
                    'dependencies':[]
                },
                'functions':{},
                'classes':{},
                'globals':{},
                'inline':[
                    {
                        'type':'import',
                        'name':'io'
                    },
                    {
                        'type':'call',
                        'functionName':'io.print',
                        'arguments':[
                            {
                                'type':'literal',
                                'value':'Hello World!'
                            }
                        ]
                    }
                ]
            }
        }

        # interpreter tests 
        self.interTests = {
            # Print Logic test (input)
            
            # Print logic test (False)
            'testLogicPrint':[
                {
                    'type':'assign',
                    'target':{
                        'name':'userAge'
                    },
                    'value':{
                        'type':'literal',
                        'value':17
                    }
                },
                {
                    'type':'assign',
                    'target':{
                        'name':'maxAge'
                    },
                    'value':{
                        'type':'literal',
                        'value':21
                    }
                },
                {
                    'type':'import',
                    'moduleName':'io'
                },
                # Test of age (False)
                {
                    'type':'if',
                    'condition':{
                        'type':'binaryOp',
                        'operator':'<',
                        'left':{
                            'type':'varRef',
                            'name':'userAge'
                        },
                        'right':{
                            'type':'varRef',
                            'name':'maxAge'
                        }
                    },
                    'then':[
                        {
                            'type':'call',
                            'functionName':'io.print',
                            'arguments':[{
                                'type':'literal',
                                'value':'User Is Not 21!'
                            }]
                        }
                    ],
                    'else':[
                        {
                            'type':'call',
                            'functionName':'io.print',
                            'arguments':[{
                                'type':'literal',
                                'value':'User Is 21!'
                            }]
                        }
                    ]
                }
            ],
            # Works
            # Assign & varRef Test
            'assignAndVarRef':[
                {
                    'type':'assign',
                    'target':{
                        'name':'exampleVariable'
                    },
                    'value':{
                        'type':'literal',
                        'value':'Our variable value.'
                    }
                },
                {
                    'type':'return',
                    'value':{
                        'type':'varRef',
                        'name':'exampleVariable'
                    }
                }
            ],
            # Works
            # Test indexAccess
            'indexAccessTest':[
                {
                    'type':'return',
                    'value':{
                        'type':'indexAccess',
                        'container':{
                            'type':'literal',
                            'value':[1,2,3,4,5]
                        },
                        'index':{
                            'type':'literal',
                            'value':0
                        }
                    }
                }
            ],
            # works
            # attempt to import & print a string 
            'importAndTestIO':[
                {
                    'type':'import',
                    'moduleName':'io'
                },
                {
                    'type':'call',
                    'functionName':'io.print',
                    'arguments':[
                        {
                            'type':'literal',
                            'value':'Hello World!'
                        }
                    ]
                },
                {
                    'type':'return',
                    'value':{
                        'type':'call',
                        'functionName':'io.input'
                    }
                }
            ],
            # works
            # if True: return True
            'if':[
                {
                    'type':'if',
                    'condition':{
                        'type':'literal',
                        'value':True
                    },
                    'then':[
                        {
                            'type':'return',
                            'value':{
                                'type':'literal',
                                'value':True
                            }
                        }
                    ]
                }
            ],
            # works
            # if False:
            #   pass
            # elif True:
            #   return True
            'elseif':[
                {
                    'type':'if',
                    'condition':{
                        'type':'literal',
                        'value':False
                    },
                    'then':[],
                    'elseif':[
                        {
                            'condition':{
                                'type':'literal',
                                'value':True
                            },
                            'then':[
                                {
                                    'type':'return',
                                    'value':{
                                        'type':'literal',
                                        'value':True
                                    }
                                }
                            ]
                        }
                    ]
                }
            ],
            # works
            # if False:
            #   pass
            # elif False:
            #   pass
            # else:
            #   return True
            'else':[
                {
                    'type':'if',
                    'condition':{
                        'type':'literal',
                        'value':False
                    },
                    'then':[],
                    'elseif':[],
                    'else':[
                        {
                            'type':'return',
                            'value':{
                                'type':'literal',
                                'value':True
                            }
                        }
                    ]
                }
            ]
        }
        
        self.verbosity = False

        self.logPipe("__init__","Developer Instance Initialized.",f=True)
    

    ## self.interpreter._handleStatements
    # 
    ## self.logger Tests
    ## self.variables Tests
    ## self.config Tests
    # run index test 
    def testConfigIndex(self):
        ## Working ##
        self.config._loadData(self._configTestExampleData())
        tests = [ "root","root:stem","root:objetc","root:mapTest","root:mapTest.zero"]
        self.logPipe("testIndex","Starting test with test keys.",e={
            'test':str(tests)
        },f=True)
        for i in tests:
            print(f"Testing {str(i)}")
            v = self.config.index(i)
            print("*\t",str(v))


    # example data
    def _configTestExampleData(self):
        return {
            'root':{ # root
                'stem':True, # root:stem -> True
                'objetc':{ # root:objetc -> { ... }
                    'stem':'test' # root:objetc:stem -> 'test'
                },
                'mapTest.zero':0, # root:mapTest -> { ... } // root:mapTest.zero -> 0
                'mapTest.one':1,
                'testMap.example':'test'
            }
        }


    def logPipe(self,r,m,l=None,e=None,f=False): 
        """"""
        f = True if self.verbosity else False
        self.logger.logPipe(r,m,loggingLevel=l,extendedContext=e,forcePrintToScreen=f)

class Alien:

    """
    *-- Main Alien Application --*

    Args:
        setup (bool, optional): If true than run `self.setup` on initialization.
    """

    def __init__(self):

        self.logger = loggerHandle("Alien:Gen2 Version 0.2.0")

        self.config = {
            "configPath":'default.json',
            "initScript":"",
            "debugLevel":2,
            "logging":True,
            "verbosity":False
        }
        self.spacer = str(f"\n{str('-'*80)}\n")
        self.descriptions = {
            "main":"\n".join([
                "*-- Alien Framework --*",
                "version: 2.0.2.0",
                "author:  J4ck3LSyN",
                str(self.spacer),
                "\tUsage: py -m ALNv2020 <args> <mode> ...",
                str(self.spacer),
                "\tThe alien framework(ALNv2020) is a modular toolkit centered",
                "\taround a powerful, programmable JSON-based interpreter. It is",
                "\tengineered for a wide array of software engineering and",
                "\tcybersecurity-related tasks, enabling the execution of complex",
                "\tlogic operations with libraries, executable scripts, pythonic",
                "\toperations, threading, LLM(ollama) communications, low-level",
                "\tmemory/process management, and network communication.",
                "",
                "\tGlobal Arguments:",
                "",
                "\t\t(debugging)     py -m ALNv2020 -dL,--debugLevel (0,1,2,3) <args> <mode> ...",
                "\t\t - Debugging level.",
                "\t\t - type: int",
                "\t\t - default: 2",
                "",
                "\t\t(configuration) py -m ALNv2020 -cP --configPath 'targetFile.json' <args> <mode> ...",
                "\t\t - Configuration file path.",
                "\t\t - type: str",
                "\t\t - default: 'default.json'",
                str(self.spacer),
                "",
                "\tInterpreter:",
                "\t\tFile Execution:",
                "\t\tUsage: py -m ALNv2020 intr <args> 'targetFile.json' <args> <kwargs>",
                "",
                "\t\tIndepth Logging (slows performance):",
                "\t\tUsage: py -m ALNv2020 intr -lP <args> 'targetFile.json' <args> <kwargs>",
                "",
                "\t\tNew Projects:",
                "\t\tUsage: py -m ALNv2020 intr -n <args> 'targetFile.json' <args> <kwargs>",
                str(self.spacer)
            ]),
            "debugLevel":"\n".join([
                str(self.spacer),
                "\tUsage: py -m ALNv2020 -dL,--debugLevel (0,1,2,3) <args> <mode> ...",
                str(self.spacer),
                "\tDebugging level:",
                "\t\t0 - INFO",
                "\t\t1 - DEBUG",
                "\t\t2 - ERROR (default)",
                "\t\t3 - CRITICAL (silent)",
                str(self.spacer)
            ]),
            "configPath":"\n".join([
                str(self.spacer),
                "\tConfiguration file path.",
                str(self.spacer),
                "\tUsage: ",
                "\tpy -m ALNv2020 -cP,--configPath 'targetFile.json' <args> <mode> ...",
                "\tNOTE: If the given path is not absolute, it will attempt to locate",
                "\t      the file inside of the ALNv2020/etc/ diretcory.",
                str(self.spacer),
                "\tDefault diretcory: 'ALNv2020/etc/'",
                "\tDefault configuration file: 'default.json'",
                str(self.spacer)
            ]),
            "modes":"\n".join([
                str(self.spacer),
                "\tModes for alien for alien to operate with.",
                str(self.spacer),
                "Usage: py -m ALNv2020 <args> <mode> ...",
                str(self.spacer),
                "\tModes:",
                "\t\tintr  :: Interpreter functions",
                "\t\tUsage :: ..py <args> intr 'fileToExecute.json' <args> <kwargs>",
                "",
                str(self.spacer)
            ]),
            "interpreterNew":"\n".join([
                str(self.spacer),
                "Creates a `raw program` for alien inside of `ALNv2020/interpreterScripts/`."
                "Usage: `py -m ALNv2020 intr -n 'scriptName.json'`",
                str(self.spacer)
            ]),
            "interpreterLogPipe":"\n".join([
                str(self.spacer),
                "\tAllows for the `logPipe` to work. (The central point for all logging!)",
                "\tNote:",
                "\t\tWhen given operations will run slowly, this is a temporary patch for smoother operations.",
                str(self.spacer)
            ])
        }
        self.centralArgParser = argparse.ArgumentParser(
            description=str(self.descriptions['main']),
            formatter_class=argparse.RawDescriptionHelpFormatter
        )
        ## Set the global arguments to the main parser
        # defbugLevel
        self.centralArgParser.add_argument(
            "--debugLevel","-dL",help=str(self.descriptions['debugLevel']),type=int
        )
        # configure path
        self.centralArgParser.add_argument(
            "--configPath","-cP",help=str(self.descriptions['configPath']),type=str
        )
        ## Create the 'exec' parser
        self.execParser = self.centralArgParser.add_subparsers(
            dest="mode",help=str(self.descriptions['modes'])
        )
        ### intr, interpreter operations
        self.intrSubparsers = self.execParser.add_parser(
            "intr",help="",formatter_class=argparse.RawTextHelpFormatter
        )
        self.intrSubparsers.add_argument(
            "-lP",'--logPipe',help=self.descriptions['interpreterLogPipe'],action="store_true"
        )
        self.intrSubparsers.add_argument(
            "-n","--new",help=self.descriptions['interpreterNew'],action="store_true"
        )
        self.intrSubparsers.add_argument(
            "execFile",help="",type=str
        )
        self.intrSubparsers.add_argument(
            "extendedArgs",nargs=argparse.REMAINDER, help=""
        )
        self.intrSubparsers.set_defaults(func=self._intr)
        # Parse the args
        self.parsedArgs = self.centralArgParser.parse_args()
        # configure
        self.logPipe("__init__",f"Arguments have been processed: '{str(' '.join([str(i) for i in sys.argv]))}'")
        # Init
        self.logPipe("__init__",f"Alien parsers have finished initialization @ {str(time.asctime())}",f=self.config['verbosity'])
        if hasattr(self.parsedArgs,'func'):
            self.parsedArgs.func()
        else:
            print(str(self.descriptions['main']))


    ## argparse handles
    def _handleExtendedArgs(self):
        """"""
        # Handle extended args
        args = self.parsedArgs.extendedArgs
        kwList = [i.split("=") for i in args if "=" in i]
        kwargs = {k:v for k,v in kwList}
        args = [i for i in args if "=" not in i]
        # Validate types a resolve simple (int,str,bool)
        bools = ["True","False"]
        digits = string.digits
        for k,v in kwargs.items():
            isDigit = True
            for char in v:
                if char not in digits:
                    isDigit = False
                    break
            if isDigit: kwargs[k] = int(v)
            if v in bools: kwargs[k] = True if v == "True" else False
        for v in args:
            isDigit = True
            for char in v:
                if char not in digits:
                    isDigit = False
                    break
            if isDigit: args[args.index(v)] = int(v)
            if v in bools: args[args.index(v)] = True if v == "True" else False
        return [args,kwargs]

    # Server
    def _server(self):
        """
        ALNv2020 serve port

        Args:
            port (int): The port to listen on.
            -h,--host (str, optional): Host IP, defaults to 'localhost:127.0.0.1'.
            -l,--limit (int, optional): Amount of clients to allow
            -v,--verbose (bool, optional): Verbose mode, defaults to True.
                                           Note: Runs outside of `logPipe`.
            
        """
        pass 

    # Client
    def _client(self):
        """
        ALNv2020 conn host:port
        """
        
        pass

    # Interpreter
    def _writeRawFile(self,path:str,basePath:str=None):
        """"""
        data = self.iT._returnRawProgramData()
        basePath = basePath if basePath else self.iT.basePath / self.iT.config['scriptPath']
        if not self.iT.path.exist(basePath):
            eM = f"'{str(basePath)}' does not exist."
            self.logPipe("_writeRawFile",eM,l=2)
            raise FileNotFoundError
        fullPath = basePath / path
        json.dump(data,open(str(fullPath),'w',encoding='utf-8'),indent=4)
        self.logPipe("_writeRawFile",f"Wrote new program data to '{str(fullPath)}'",f=True)

    def _intr(self):
        """
        ALNv2020 '<file.json>' <args> <kwargs>
        """
        if not self.parsedArgs.execFile:
            eM = f"No file for execution: {str(self.parsedArgs)}."
            self.logPipe("_intr",eM,l=2)
            raise RuntimeError(eM)
        self.iT = interpreterHandle(logger=self.logger)
        if self.parsedArgs.logPipe:
            self.iT.config['allowLogPipe']=True
        if self.parsedArgs.new:
            self._writeRawFile(self.parsedArgs.execFile)
            return
        self.logPipe("_intr",f"Attempting to load file '{str(self.parsedArgs.execFile)}'...",f=self.config['verbosity'])
        try:
            # Only load if the --new flag wasn't used
            if not self.parsedArgs.new:
                self.iT.load(str(self.parsedArgs.execFile))
                self.logPipe("_intr",f"'{str(self.parsedArgs.execFile)}' loaded successfully!",f=self.config['verbosity'])
        except Exception as E:
            eM = f"Caught exception while attempting to load '{str(self.parsedArgs.execFile)}': {str(E)}"
            self.logPipe("_intr",eM,l=2)
            print(traceback.format_exc())
        ext = self._handleExtendedArgs()
        args = ext[0]
        kwargs = ext[1]
        # Log
        self.logPipe("_intr","Prepared arguments for global assignment.",e={
            "__args__":str(args),
            "__kwargs__":str(kwargs)
        },f=self.config['verbosity'])
        # Set global arguments
        self.iT._varCreateGlobal("__args__",args)
        self.iT._varCreateGlobal("__kwargs__",kwargs)
        # Run
        self.logPipe("_intr",f"Executing '{str(self.parsedArgs.execFile)}'.",e={
            "args":str(args),
            "kwargs":str(kwargs)
        },f=self.config['verbosity'])
        try:
            self.iT.run()
        except Exception as E:
            eM = f"Caught exception while attempt to run '{str(self.parsedArgs.execFile)}': {str(E)}"
            self.logPipe("_intr",eM,l=2)
            print(traceback.format_exc())

    ## Main
    # Log Pipe
    def logPipe(self,r,m,l=None,e=None,f=False): 
        """"""
        if self.config['logging'] == True and self.logger: self.logger.logPipe(r,m,loggingLevel=l,extendedContext=e,forcePrintToScreen=f)



if __name__ == "__main__":
    app = Alien()
