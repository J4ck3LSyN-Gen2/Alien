# ALNv2020(Generation 2 version 0.2.0)

![Python 3.14](https://img.shields.io/badge/python-3.14📡-magenta)

The alien framework is a modular toolkit centralized around a powerful JSON-based interpreter. It is engineered for a wide array of software engineering and cybersecurity-related tasks, enabling the execution of complex logic operations with
the capabilities of library importation (alien/pythonic), theading, LLM(ATLAS) ollama
communications, low-level memory/process management and different redteam(offsec) tools and network based operations.

## Index

> **NOTE:** I highly recommend using the index and making it good practice. (saves time)

- [Setup & Installation](#setup--installation)
- [Usage](#usage)
  - [Application](#application)
  - [Python Importation](#python-importation)
  - [J4ck3L's Scripts](#j4ck3ls-scripts)
- [Interpreter (Alien Syntax)](#interpreter-alien-syntax)
  - [Important Directories](#important-directories)
  - [Program Structure](#program-structure)
  - [Pythonic Library Structure](#pythonic-library-structure)
  - [Standard Library](#standard-library)
  - [Class Structure](#class-structure)
  - [Class Instance Creation](#class-instance-creation)
  - [Statements](#statements)
  - [Expressions](#expressions)
- [confHandle (Configuration)](#confhandle-configuration)
- [Logger (Logging)](#logger-logging)
- [Process (Process & Threads)](#process-process--threads)
  - [Starting, Stopping & Removing Processes](#starting-stopping--removing-processes)
  - [Appending Subprocesses](#appending-subprocesses)
  - [Retrieving Output From Finished Subprocess](#retrieving-output-from-finished-subprocess)
  - [Appending Threads](#appending-threads)
  - [Que & Thread Wrapper Function](#que--thread-wrapper-function)
- [Utils](#utils)
  - [utils.transmission](#utilstransmission)
    - [ssh](#ssh)
      - [Server](#server)
      - [Client](#client)
    - [curl](#curl)
    - [web](#web)
      - [api](#api)
      - [httpServe](#httpserve)
    - [sock](#sock)
      - [Serving](#serving-a-tcp-server)
      - [Connecting](#connecting--sending-data)
    - [nmap](#nmap)
    - [externalProxies](#externalproxies)
    - [browser](#browser)

# Setup & Installation

```sh
git clone https://github.com/J4ck3LSyN-Gen2/Alien.git
```

### Module installation:

```markdown
cd Alien/
pip install -r requirements.txt
py -m install -r requirements.txt
```

__NOTE :__ The current of alien is built in `python 3.14`

## Termux Installation

It is recommended to use a near default termux instance.

Preliminary commands:

```bash
pkg update -y && pkg upgrade -y
pkg install netcat-openbsd
termux-setup-storage
```

### Termux Manual Installation.

### Termux & Remote Installation.

* **Netcat**
    * __NOTE :__ Replace <port> with your desired port.
    - Remote machine: `ncat -l -p <port> -k | while read cmd; do [[ -z $cmd ]] || (timeout 30 bash -c "$cmd" 2>&1; echo $?); done`
    - Local Python: `py -c "import ALNv2020 as alien;iH=alien.installHandle(<host>,<port>);iH.connectTCP();iH.runInstallCallTCP('termux')"`


## Usage

`py -m ALNv2020 <args> <mode> <post-args> ...`

### Application

__NOTE__: The front end of `alien` if constantly under development and is under `constant` change, please be patient while I complete all the functionality. Some `modules` will be directly callable, however most functionality will be centralized around `py -m ALNv2020` itself.

__NOTE__: When using the `intr` functionality, the `-lP,--logPipe` flag when enabled will impact performance on script execution heavily. This is due to the amount of logging performed during operations, for most instances (unless you are debugging and want deeper information), `-lP` is not needed.

```markdown
usage: python.exe -m ALNv2020 [-h] [-v] {intr} ...

version: 2.0.2.0
author:  J4ck3LSyN
python version: 3.14

Usage: py -m ALNv2020 <args> <mode> <args> ...

Description:
The alien framework(ALNv2020) is a modular toolkit centered
around a powerful, programmable JSON-based interpreter. It is
engineered for a wide array of software engineering and
cybersecurity-related tasks, enabling the execution of complex
logic operations with libraries, executable scripts, pythonic
operations, threading, LLM(ollama) communications, low-level
memory/process management, and network communication.

positional arguments:
  {intr}                Interpreter(intr): Usage: py -m ALNv2020 <args> intr '<file>/<data>' <args> <kwargs>
    intr                Run the Alien interpreter for file or data execution.

options:
  -h, --help            show this help message and exit
  -v, --verbose         Enable verbose output, from logPipe.
```

### J4ck3L's Scripts

While all are under constant development, I have built some scripts that are aimed at assisting with the alien learning curve (e.g., examples), benchmarking (attempting to gain better optimization) and `alien` functionality itself.

__NOTE :__ Some scripts are not fully completed, this is due to my workflow and I appologize.

#### Example Scripts: `ALNv2020/interpreterScripts/exampleScripts.json`

__Usage__: `py -m ALNv2020 intr 'exampleScripts.json'`

Is a collection of scripts to help guide in Alien programming.

#### Alien: `ALNv2020/interpreterScripts/alien.json`

__Usage__: `py -m ALNv2020 intr 'alien.json'`

NOTE: Under Construction

Going to be an centralized alien program for alien operations...

#### Developer: `ALNv2020/interpreterScripts/developer.json`

#### Benchmark: `ALNv2020/interpreterScripts/benchmark.json`

### Python Importation

## Installation & Updating

> (**CRITICAL INFORMATION**)
 > (**CRITICAL INFORMATION & SECURITY WARNING**)
 > The remote installation features, particularly for `Termux`, are highly **experimental** and operate in a way that may be flagged by security software or seem suspicious if the process is not understood.
 >
 > **How it Works (Termux Netcat Method):**
 > The primary method for installing `Python 3.14` and `Alien` on a fresh Termux instance involves:
 > 1.  **Establishing a Remote Shell:** A `netcat` listener is started on the Termux device, which opens a port and pipes incoming data directly to a shell (like `bash`).
 > 2.  **Remote Connection:** The `installHandle` on your local machine connects to this open `netcat` port.
 > 3.  **Command Execution:** A series of installation commands are then sent from your local machine, through the `netcat` connection, and are executed directly on the Termux device.
 >
 > This process is powerful for automation but inherently insecure on untrusted networks. Anyone on the same network could potentially connect to the open `netcat` port and execute commands.
 >
 > **Future Methods & Risks:**
 > Higher-level installation methods will involve `SSH`, a dedicated `API`, or `HTTP` file hosting. While more secure than the basic `netcat` shell, these methods still involve opening ports. It is crucial to only perform these operations on a **secure, private network** where you trust all connected devices. Using these features on a public or untrusted network (like public WiFi) can expose your devices to unauthorized access.
 >
 > **USE WITH CAUTION AND ON SECURE NETWORKS ONLY.**


__Importation__

```python
import ALNv2020 as alien
iH = alien.installHandle(
    '0.0.0.0', # (optional) Default: '0.0.0.0' rHost
    9999, # (optional) Default: 9999 rPort
    process=processHandle, # Optional: For future threading use.
    logger=logger, # (optional) Default: None
    confHandle=confHandle # (optional) Default: None
)
```

__Configuration__

```python
self.config = {
"useLogging":False,
"timeout":300,
"sleepTimer":0.5,
"clientScripts":{
    "termux":{
        "ncat":'ncat -l -p 9997 -k | while read cmd; do [[ -z $cmd ]] || (timeout 300 bash -c "$cmd" 2>&1; echo $?); done'
    }
},
"installScripts": {
    "termux": {
        "init": [
            # "termux-setup-storage",  
            # "pkg update -y && pkg upgrade -y",  
            # "pkg install nmap wget curl proot-distro -y"  
        ],
        "body": [
            # Install & start Ubuntu 
            "proot-distro install ubuntu",  
            # Login & Exec
            'proot-distro login ubuntu -- bash -c "apt update && apt upgrade -y && apt install build-essential zlib1g-dev libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libreadline-dev libffi-dev wget git -y && cd /opt && wget https://www.python.org/ftp/python/3.14.0/Python-3.14.0.tgz && tar -xf Python-3.14.0.tgz && cd Python-3.14.0 && ./configure --enable-optimizations --with-ensurepip=install && make -j$(nproc) && make altinstall"',
            # Create symlinks & PATH (back in Termux)
            "ln -sf /data/data/com.termux/files/usr/var/lib/proot-distro/installed-root/ubuntu/opt/python3.14/bin/python3.14 /data/data/com.termux/files/usr/bin/python3.14",
            "ln -sf /data/data/com.termux/files/usr/var/lib/proot-distro/installed-root/ubuntu/opt/python3.14/bin/pip3.14 /data/data/com.termux/files/usr/bin/pip3.14",
            "echo 'export PATH=/data/data/com.termux/files/usr/bin:$PATH' >> ~/.bashrc",
            # Test Python 3.14
            "python3.14 --version"
        ]
    }
}

```

## Interpreter (Alien Syntax)

```python
import ALNv2020 as alien
iT = alien.interpreterHandle(
    basePath:str=".", # The base path to operate inside of
    logger:Any=None # the `logger` obejct if any
)
```

I have attempted to make file execution pretty easy, when working with files you can supply 2 different forms of input:

1. Absolute path
2. File Name

If given as a `File Name` it will attempt to file the file inside of the `current directory` and `ALNv2020/interpreterScripts/`.

`py -m ALNv2020 intr 'targetFile.json' args kwarg=value`

### Important Directories 

* **ALNv2020/etc/**

    - This is the central directory for any configuration files.
    - The default configuration file is `default.json`.

* **ALNv2020/libs/**

    - Libraries for `Alien` can be found here, while there are not many currently there are 2 existant ones...
    1. alienPythonicExample.py
    2. helloworld.json

    Where bother are different forms of libraries that can be imported, I will add more to them as time goes on.

* **ALNv2020/interpreterScripts/**

    - Any `executable` scripts go here, and can be called directly from python importation or the application.


### Program Structure

Create a raw program: `py -m ALNv2020 intr -n 'wantedScript.json'`
    - This will create a new file with raw program data to work with.

```JSON
{
    "metadata":{
        "author":"<anonymous>",
        "title":"<not-configured>",
        "version":"0.0.0",
        "description":"<not-configured>",
        "dependencies":[]
    },
    "globals":{},
    "classes":{},
    "functions":{},
    "inline":[]
}
```

* **metadata**
    - `author` being the author of the program ofc.
    - `title` being the title of the program.
    - `version` is the current version, planned to be used for `update` control.
    - `description`...
    - `dependencies` are any needed `libraries` this is `under construction` but as libraries are devloped and things grow, this will become more influenced.

* **globals**
    - Centralized global variables, anything in there can be referenced globally.
    - `__args__` & `__kwargs__` are supplied when `py -m ALNv2020 intr '...' args kwarg=value` is used.
* **classes**
    - Method/Class operations.
    - The default `method` name for `entry` on call is `main` or `__init__` depending on the configuration.
    
    When initialized the `constructor` will act as `__init__` setting the class varibles 
    and executing the `body`. 

* **functions**
    - Functions...

* **inline**
    - This is the first thing to execute when a program is `loaded`, allowing for any operations or triggers to happen.

* **Entry Points**
    - By default the main entry function is `main`: `(default.json):interpreter.entryPoint`
    - If existant, this will execute `POST` the `inline` executions.

    __Example__
    ```json
    {
        "metadata":{...},
        "classes":{...},
        "functions":{
            'main':{
                "parameters":[],
                "body":[<statements>]
            }
        },
        "globals":{...},
        "inlines":[
            {
                "type":"comment",
                "text":"Inline operation pre 'main'."
            }
        ]
    }
    ```

### Pythonic Library Structure

Pythonic libraries can be used to have python flexibility inside of your alien programs
without the possible slowness (and for now limited) functionality of alien. 

You can create `new` libraries with raw data via: `py -m ALNv2020 intr -nPL 'myLibrary.py'`

__Example__

```python
# Written for alien(G2V020)
# OG Author(Alien): J4ck3LSyN
# https://github.com/J4ck3LSyN-Gen2/Alien/
__author__ = '<anonymous>'
__version__ = '0.0.0'

from typing import Dict, List, Optional Any

class exampleCallableFunction(thisArg):
    return thisArg

class example:

    def __init__(self,iT:Callable=None):

        self.iT = iT 
        # Return from stdlib module `alien.getSelf` being the `interpreterHandle` object.
        # NOTE: This is good practice and will allow for faster alien operations 
        #       also avoids importation conflicts.

exampleObject  = None

def setExample(iT:Callable=None):
    """
    When building classes, it is best to build initializers for it.
    """
    exampleObject = example(iT=iT)

__alienProgramLibraries__ = {
    "exampleLib-init":{ # exampleLib-init.init
        "init":lambda iT: setExample(iT) 
    },
    "exampleLib-exampleCallableFunction":lambda x: thisArg(x) # exampleLib-exampleCallableFunction
    # The structure of your library is completly optional, however I highly recommend 
    # keeping the library names inside of here seperated from the program data title.
    # Reason: the `metadata.title` is used for the `library` alien data importation,
    # using the same string inside of `__alienProgramLibraries__` will nullify it. 
}
__alienProgramData__ = {
    "metadata": {
        "author": "<anonymous>",
        "title": "exampleLib-programData",
        "version": "0.0.0",
        "description": "This is an example....",
        "dependencies": []
    },
    "functions": {},
    "classes": {},
    "globals": {},
    "inline": [ # Runs on import
        {"type":"import","moduleName":"io"} # Example importations 
    ]
}
```

### Standard Library

While I am constantly appending new modules to this, here is a list of the ones so far and what they do.

__Importing Wanted Modules__

```JSON
{
    "type":"import",
    "moduleName":<target module>
}
```

__Calling Modules Methods__

```JSON
{
    "type":"call",
    "functionName":<target module>.<target method>,
    "arguments":[<expression>,...],
    "keywordArguments":{arg:<expression>}
}
```

#### Standard Libary List

```markdown
# io
    io.print
    io.input
    io.logPipe

# json
    json.load
    json.loads
    json.dump
    json.dumps

# time
    time.time
    time.sleep
    time.getTimeDifference
    time.asciiTime

# systemInfo
    systemInfo.sysInfo

# path
    path.isDir
    path.isFile
    path.exist
    path.rmDir
    path.rmFile
    file
        path.file.read
        path.file.writeStr
        path.file.writeBytes
        path.file.append

# cypher
    passwd
        cypher.passwd.tokenHex
        cypher.passwd.tokenBytes
        cypher.passwd.randomBytes

# memory
    init
        memory.init.struct
        memory.init.block

    bytes
        memory.bytes.read
        memory.bytes.write

# variables
    string
        variables.string.join
        variables.string.split
        variables.string.replace
        variables.string.reverse
        variables.string.tabSpace
        variables.string.newLine
        variables.string.empty
    list
        variables.list.append
        variables.list.pop
        variables.list.index
        variables.list.empty
    dict
        variables.dict.keyExists
        variables.dict.get
        variables.dict.dimAppend
        variables.dict.append
        variables.dict.removeKey
        variables.dict.empty
    bool
        variables.bool.flip
        variables.bool.empty
    float
        variables.float.empty
    intiger
        variables.intiger.empty
    bytes
        variables.bytes.encode
        variables.bytes.decode
        variables.bytes.empty

# huffman
    huffman.encode
    huffman.decode

# zip
    compress
        zip.compress.targetFiles

# sock
    sock.getSocketObject
    sock.connectEX

# curl
    curl.basicGet

# proc
    proc.shell
```

### Class Structure

```JSON
["classes"] "exampleClass":{
    "exampleClass":{
        "className":str,
        "classVariables":{},
        "constructor":{
            "parameters":[
                {
                    "name":"self" # reference self
                },
                {
                    "name":"name",
                    "default":{
                        "type":"literal",
                        "value":"exampleClass"
                    }
                }
            ]
        },
        "body":[ # General practice is returning self
            {
                "type":"return",
                "value":{
                    "type":"varRef",
                    "name":"self"
                }
            }
        ]
    }
}
```


### Class Instance Creation


When creating a `classInstance` we need to `assign` a variable for it, this is the same as using:
```python
class thisClass:

    def __init__(self,name:str=None):

        # contructor logic
        self.name = name if name else "thisClass"
        return self

import thisClass
newInstance = thisClass()
```

Consider `Class Structure` for further information.

```JSON
app = [
    {
        "type":"assign",
        "target":{"name":"newInstance"},
        "value":{
            "type":"new",
            "className":"exampleClass",
            "arguments":[], # If any
            "keywordArguments":{} # If any
        }
    }
]

```

Post creation of the instance you can call methods inside of it via:

```JSON
{
    "type":"methodCall",
    "target":{"type":"varRef","name":"newInstance"},
    "methodName":str,
    "arguments":[<expression>,...],
    "keywordArguments":{key:<expression>}
}
```

General good practice is returning the `self` object for further use.

```JSON
{
    "classes":{
        "exampleClass":{
            "className":"exampleClass",
            "constructor":{
                "parameters":[
                    {
                        "name":"self"
                }],
                "body":[
                    {
                        "type":"comment",
                        "text":"Class __init__ Exec"
                    },
                    {
                        "type":"return",
                        "value":{
                            "type":"varRef",
                            "name":"self"
                        }
                    }
                ]

            }
        }
    }
}
```


## Statememts

**comment**

```JSON
{
    "type":"comment"
}
```

**import**

```JSON
{
    "type":"import",
    "moduleName":str,
    "modulePath":str(optional),
    "alias":str(optional)
}
```

**call**

```JSON
{
    "type":"call",
    "functionName":str,
    "arguments":[<expression>],
    "keywordArguments":{'name':<expression>}
}
```

**assign**

```JSON
{
    "type":"assign",
    "target":{"name":str},
    "value":<expression>
}
```

**return**

```JSON
{
    "type":"return",
    "value":<expression>
}
```

**if**

```JSON
{
    "type":"if",
    "condition":<expression>,
    "then":<statements>,
    "elseif":[
        {
            "condition":<expression>,
            "then":<statements>
        }
    ](optional),
    "else":<statements>(optional)
}
```

**while**

```JSON
{
    "type":"while",
    "iterable":<expression>,
    "loopVar":str,
    "body":<statements>(optional)
}
```

**for**

```JSON
{
    "type":"for",
    "iterable":<expression>,
    "loopVar":str,
    "body":<statements>(optional)
}
```

**rIT**

Run functions in a thread..

```JSON
{
    "type":"rIT",
    "functionName":str,
    "arguments":[<expression>,...](optional),
    "keywordArguments":{key:<expression>}(optional)
}
```

**try**

```JSON
{
    "type":"try",
    "try":<statements>,
    "catch":[
        {
            "exceptionType":str,
            "exceptionVar":str(optional, 'e'),
            "body":<statements>
        }
    ]
}
```

**throw**

```JSON
{
    "type":"throw",
    "error":<expression>(optional)
}
```

**methodCall**

Passed on to expressions, `target` is a `new` instance reference.

```JSON
{
    "type":"methodCall",
    "target":<expression>,
    "methodName":str,
    "arugments":[<expression>,...],
    "keywordArguments":{key:<expression>}
}
```

**superCall**

```JSON
{
    "type":"superCall",
    "methodName":str,
    "arguments":[<expressions>,....],
    "keywordArguments":{key:<expression>,...}
}
```

**__break__**

```JSON
{
    "type":"__BREAK__"
}
```

**__continue__**

```JSON
{
    "type":"__CONTINUE__"
}
```

**async**

```JSON
{
    "type":"async"
}
```

**asnGlobal**

```JSON
{
    "type":"asnGlobal",
    "target":{"name":str},
    "value":<expression>
}
```

## Expressions

**comment**

```JSON
{
    "type":"comment"
}
```

**literal**

```JSON
{
    "type":"literal",
    "value":Any
}
```

**varRef**

```JSON
{
    "type":"varRef",
    "name":str
}
```

**binaryOp**



```JSON
{
    "type":"binaryOp",
    "operator":str,
    "left":<expression>,
    "right":<expression>
}
```

**call**

```JSON
{
    "type":"call",
    "functionName":str,
    "arguments":[<expression>,...],
    "keywordArguments":{key:<expression>}
}
```

**new**

```JSON
{
    "type":"new",
    "className":str,
    "arguments":[<expression>,...],
    "keywordArguments":{key:<expression>}
}
```

**methodCall**

```JSON
{
    "type":"methodCall",
    "target":<expression>(classInstance),
    "methodName":str,
    "arguments":[<expression>,...],
}
```

**index**

```JSON
{
    "type":"index",
    "container":<expression>,
    "index":<expression>
}
```

**slice**

NOTE: At least one of ('start','end', or 'step') cannot be None.

```JSON
{
    "type":"slice",
    "container":<expression>,
    "start":<expression>,
    "end":<expression>,
    "step":<expression>
}
```

**superCall**

```JSON
{
    "type":"superCall",
    "methodName":str,
    "arguments":[<expression>],
    "keywordArguments":{key:<expression>}
}
```

**range**

`start`, `end` or `step` can be either `integers` or `expression`.

```JSON
{
    "type":"range",
    "start":int(<expression>)(optional),
    "end":int(<expression>)(optional),
    "step":int(<expression>)(optional)
}
```

**in**

```JSON
{
    "type":"in",
    "left":<expression>,
    "right":<expression>
}
```

**isInstance**


```JSON
{
    "type":"isInstance",
    "value":<expression>,
    "varType":list[str] or str
}
```

**formatString**

Format strings.

Default Open & Close:
    - `%(` expression.openFmtStr
    - `)`  expression.closeFmtStr

```json
{
    "type":"formatString",
    // This is essentially f""
    "value":{
        "type":"literal",
        "value":"exmaple %(var) if var"
    }
}
```

**exprString**

Expression strings.

Default Open & Close:
    - `%{` expression.openExprStr
    - `}`  expression.closeExprStr

```json
{
    "type":"exprString",
    "target":{"value":"%{targetExpression}"},
    "expressions":{
        "targetExpression":<expression>
    }
}
```

## confHandle (Configuration)

```python
import ALNv2020 as alien
conf = alien.confHandle(
    data:Dict[str,Any]|str=None, # Data to initialize with
    noLogs:bool=False # No logs, used only on instances you want to avoid conflicts
)
```

This is used as the central configuration for alien, thus you can (and sometimes will need to) pass it to other objects inside of alien. This is encouraged, and allows you to change & customize where and what you wish to configure. 

- `confHandle.readConfig(path:str=None)`
    
    Reads a configuation file and loads it, if the `path` is None than it will default.
    Default is usually: `ALNv2020\\etc\\default.json`.

- `confHandle.dataRead` is a boolean and will return `True` if `readConfig` was loaded.

## Logger (Logging)

> (**CRITICAL-INFORMATION**)
> An identified performance bottleneck is related to the `loggerHandle` and its interaction with the `interpreterHandle`, especially concerning file I/O operations during script execution. While optimizations are in progress, it is highly recommended to use separate logger instances for the `interpreterHandle` and other modules to mitigate performance degradation.


```python
import ALNv2020 as alien
logger = alien.loggerHandle(
    loggerID:str,
    setupLogger:bool=True
)
```

The main pipe for the `logger` is `logPipe`

```python
logger.logPipe(
    r:str, # Root of the message (usually the calling function)
    m:str, # Message
    loggingLevel:int=None, # 0..3 logging module levels (default: 2)
    extendedContext:Dict[str,str], # Extended information for the message
    forcePrintToScreen:bool=False # Prints if true
)
```

Since the `logger` is the central logging object for alien, you can pass the object (and sometimes have to) other objects inside of alien. This allows for proper traceback inside
the logs. The default log directory it `ALNv2020\\logs\\`.



## Process (Process & Threads)

```python
import ALNv2020 as alien
pH = alien.processHandle(
    useLogs:bool=False
)
```

There are two types of `process` objects stored inside of `pH.processLibrary`:

1. __subprocess__
2. __thread__

However `shell` commands can be executed straight via:

```python
pH.shell(
    command:str|List[str]
)
```

The return will be a list `[stdout,stderr]`, I did this to assist with `interpreterHandle`.

### Starting, Stopping & Removing Processes


__Start__

```python
# Appended pID('test')
...
pH.startProcess('test')
```

__Stop__

```python
# Appended pID('test')
...
pH.stopProcess('test')
```

__remove__

```python
# Appended pID('test')
...
pH.removeProcess('test')
```


### Appending Subprocesses


```python
pH.appendSubprocess(
    processID:str, # Process ID
    command:List[str]|str, # Commands
    description:str="<No-Desc>", # Description
    **pOpenKWArgs # Extended pOpen arguments (if any)
)
```

### Retrieving Output From Finished Subprocess

```python
# Post exection of 'test'
...
output = pH.getProcessOutput('test')
```

### Appending Threads

NOTE: Threaded functions will need to wrapped in a `que` for the data to be retrieved via thread wrapper functions outside of `interpreterHandle` (since it will handle the que itself).

```python
def exampleCallable(): print("Do something...")
pH.appendThread(
    threadID:str, # Thread ID
    exampleCallable,
    args:tuple=(),
    kwargs:Dict=None,
    description:str="<No-Desc>"
)
```

### Que & Thread Wrapper Function

```python
import time, queue
from ALNv2020.core import processHandle
# Example function
def exampleCalculation(x, y):
    """A simple worker function that simulates work and returns a result."""
    time.sleep(3) # Sleep
    result = x * y + 100 # Calulate
    return result # Return result

# Thread wrapper
def threadWrapper(resultsQue, target, *args, **kwargs):
    """
    This wrapper executes the target function and puts its
    return value into the provided queue.
    """
    try:
        # Call the original worker function
        result = target(*args, **kwargs)
        # Put the result into the queue for the main thread to retrieve
        resultsQue.put(result)
    except Exception as e:
        # Exception catch
        eM = f"Unknown exception: {str(e)}"
        resultsQue.put(eM)

if __name__ == "__main__":
    # Initialize
    pH = processHandle(useLogs=True)
    # Create the `queue` object.
    resultsQue = queue.Queue()
    # Append
    pH.appendThread(
        processId="exampleThread",
        target=threadWrapper,
        args=(resultsQue, exampleCalculation, 10, 25), # (queue, realFunc, arg1, arg2)
        description="Performs a sample calculation in the background."
    )
    # Start
    pH.startProcess("exampleThread")
    # Continue main execution
    for i in range(2):
        # ....sleeeeeeep.... (how boring)
        time.sleep(1)

    # Wait for the results
    # NOTE: The .get() call will block here until the thread puts something in the queue.
    finalResult = resultsQue.get()
    # Handle the result (print in this case)
    print(f"Final Result: {finalResult}")
    # Clean up
    pH.removeProcess("exampleThread")
```

## Utils

### `utils.transmission`

Central for most network based communications.

__Importation__

```python
import ALNv2020 as alien
transmission = alien.utils.transmission
# From here you will need to set up your handles depending on the module you wish to use.
# Example:
proc = alien.processHandle()
logger = alien.loggerHandle('exampleUtilsLogger')
confHandle = alien.configHandle()
confHandle.readConfig()
# ...
```

* **Modules**
    - ssh
    - curl
    - web
    - sock
    - nmap **(Under-Construction)**
    - externalProxies   **(Under-Construction)**
    - browser **(Under-Construction)**

#### ssh

__Requirements__
    - `processHandle`

__Importation__

```python
ssh = transmission.ssh(
    processHandle,
    logger=logger,
    confHandle=confHandle
)
```

__Configuration__

```python
# From __init__
self.idrsa  = {
    # Server private & public keys
    "server":{
        "priv":"~/.ssh/id_rsaServer",
        "pub":"~/.ssh/id_rsaServer.pub"
    
    },
    # Client private & public keys
    "client":{
        "priv":"~/.ssh/id_rsaClient",
        "pub":"~/.ssh/id_rsaClient.pub"
    }
}
self.config = {
    "clientMax":5, # Client max.
    "timeout":1.0, # Timeout for clients. 
    "lPort":22,    # Server listen port
    "rPort":22,    # Client connection port
    "lHost":"0.0.0.0", # Server listen host
    "rHost":"0.0.0.0", # Client connection host
    "server":{
        "lifeSpan":300, # Default: 5 mins 
        # Global hosts to allow (if len(0) then any)
        "allowedHosts":[],
        # NOTE: If 'execHostWhitelist' and/or 'execHostPreload'
        #       is empty then any host will be allowed as long
        #       as it passes validation.
        # Whitelisted hosts for exec locally.
        "execHostWhitelist":[
            "10.0.0.1" # Example client
        ],
        # Hosts allowed to execute commands locally.
        # Usage: '<host>':[<command(s)>,...]
        "execHostPreload":{ 
            "10.0.0.1":[ # Example client 
                # List of commands to execute on the clients end
                # on connection...
            ]
        },
        # Only allow connections with this username.
        "authUsername":"AlienSSH"
    }
}
```

###### Server 

<a name="server"></a>SSH Server hosting with whitelisting & host validation.

__Note :__ Validate your `ssh.config` prior to launching.

```python
ssh.serve(
    '0.0.0.0', # (optional) Default: `lHost`
    22, # (optional) Default: `lPort`
    1.0, # (optional) Default: `timeout`
    5, # (optional) Default: `clientMax` Max clients allowed
    '~/.ssh/serverKey', # (optional) Default: `(idrsa)server.priv`
    {}, # (optional) Default: `server.execHostPreload`
    300 # (optional) Default: `server.lifeSpan` Time to live
)
```

###### Client

<a name="client"></a>SSH Client command execution.

```python
# -- Following under ssh instance creation --
ssh.client(
    'hostname', # hostname
    ['ls','pwd'], # Commands to execute
    '0.0.0.0', # (optional) Default: `rHost`
    22, # (optional) Default: `rPort`
    1, # (optional) Default: `timeout`
    '~/.ssh/thisKey', # (optional) Default: (idrsa)`client.priv`
    'username' # (optional) Default: `authUsername`
)
```

__Commands__

The 'command' can be given as a 'str' or 'list' and will be executed concurently.

__Return__

```json
{
    "time":{
        "start":1.0,
        "end":5.0,
        "difference":4.0
    },
    "command":{
        "ls":{
            "stdout":"",
            "stderr":""
        },
        "pwd":{
            "stdout":"",
            "stderr":""
        }
    }
}
```

#### curl

__importation__

```python
curl = transmission.curl(
    logger=logger, 
    confHandle=confHandle
)
```

##### basicGet

```python
out = curl.basicGet('http://thisWebSite.com')
```

#### web

__Requires__
    - `processHandle`

__Importation__

```python
web = transmission.web(
    processHandle, 
    logger=logger,
    confHandle=confHandle
)
```

__Configuration__

```python
self.config = {
    'timeout':15,
    "api":{
        "host":"0.0.0.0",
        "port":9998,
        "lifeSpan":300, # 5 minutes
        "allowedHosts":[],
        "validAPIKeys":[],
        "verbose":True
    },
    "httpServe":{
        "host":"0.0.0.0",
        "port":9090,
        "lifeSpan":300, # 5 minutes
        "allowedHosts":[],
        "validAPIKeys":[],
        "verbose":True,
        "html":{
            "root":"htmlServe"
        }
    },
    "userAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like GeckoChrome/116.0.0.0 Safari/537.36",
    "headers":{}
}
```

__API Paths__

The `web.apiPaths` variables from `web._returnDefaultAPIPaths` is the main handler for your api functionality:

```python
# Initialize the paths
def _returnDefaultApiPaths(self):
    """
    Initializes The Paths Used For `api`.
    Methodology:
        I needed a modular way to handle api requests & responses
        to do this I created a `self.apiPaths` variable. 
        Structure:
        
        {
            "get":{
                "/this/path":Callable
            },
            "post":{
                "/this/path":Callable
            }
        }
        When the internal handler is working, it will verify the 
        path given and handle accordingly.
        Responses from these functions should be a tuple:
        ( <statusCode>, <data> )
        This is passed on to `_sendJsonResponse`.
    """
    return {
        "get":{
            "/x/status":self._defaultStatus
        },
        "post":{
            "/x/return":self._defaultReturn
        }
    }
```

When creating your own paths, `get` paths do NOT take any input and will just return the result, 'post' paths will take 1 args `data`(f(data)) and return. All returns should be a `tuple`:

```python
(
    int, # status coce
    {}   # data to return
)
```

__HTTP Paths__

`web.httpPaths` is different from `web.apiPaths` in every way __DO NOT CONFUSE THE TWO!__. The handling of `http` paths are dependant on the existant of `httpServe.html.root` as a directory, if existant than this will be the default paths for your web server. However, if this directory is `non-existant` than the server will point to `web.httpPaths`.

```python
def _returnDefaultHTTPPaths(self):
        """
        Initializes The Paths USed For `httpServe`.

        ... ignore my lack of docstring here... i'm working on it...
        """
        paths = {
            "index.html":str("\n").join([
                "<html>",
                "<head>",
                "<title>Alien Generation 2 Verion 0.2.0 HTTP Server</title>",
                "</head>",
                "<body>",
                "<h1>Alien HTTP Web Server Is Running</h1>",
                "</body>"
                "</html>"
            ]),
            "404.html":"\n".join([
                "<html>",
                "<head>",
                "<title>Alien Generation 2 Verion 0.2.0 HTTP Server</title>",
                "</head>",
                "<body>",
                "<h1>Target Temporary/Static Path Is Non-Existant</h1>s",
                "</body>",
                "</html>"
            ])
        };return paths
```

When somone connects to the server and it identifies the `path` to be inside of the `paths`, the resulting code will be returned. You can customize this however you wish.

##### api

API Web hosting.

```python
# -- Post `web` instance creation --
# NOTE: Validate your `web.config(['api'])` & `web.apiPaths` prior to launch.
api = web.api(web) # Pass the web instance to the api server
api.serve()
```

##### http

<a name="httpserve"></a>```python
# -- Post `web` instance creation --
# NOTE: Validate your `web.config(['httpServer'])` & `web.httpPaths` prior to launch.
http = web.httpServe(web)
http.serve()
```

##### _get

Performs a `GET` request.

```python
resp = web._get(
    "http://thisSite.com",
    "GoogleBot/1.0", # (optional) Default: `userAgent`
    15, # (optional) Default: `timeout` Timeout
    {}, # (optional) Default: None
    False # (optional) Append default headers from `headers` 
)
```

##### _post

Performs a `POST` request.

```python
data = web._post(
    "http://thisSit.com/api/example", 
    {"content":"this content"}, # data
    "GoogleBot/1.0", # (optional) Default: `userAgent`
    15, # (optional) Defualt: `timeout`
    {}, # (optional) Default: None
    False # (optional) Append default headers from `headers`. 
)
```

#### sock

Socket based objects & operations, the most used function from here is `_socketGetType`.

__Requirements__
    - `processHandle`

__Extended Optionals__
    - `alien.utils.cypher` 
    - `alien.utils.compress`

__Importation__

```python
sock = transmission.sock(
    processHandle,
    logger=logger,
    confHandle=confHandle,
    cypher=cypher, # from alien.utils.cypher 
    compress=compress # from alien.utils.compress
)
```

While not fully implemented yet, `cypher` & `compress` will be used for encrypted, obfuscated & compress data through communication, however this is down the line and most likely will not be implemented for quite some time.

__Configuration__

```python
self.config = {
    "typeOperators":{  # Types of sockets (used in `_socketGetType`)
        "tcp":[0,"tcp"], 
        'tv4':[ 1, 'tcp4' ],
        'tv6':[ 2, 'tcp6',],
        'udp':[ 3, 'udp' ],
        'uv4':[ 4, 'udp4'],
        'uv6':[ 5, 'udp6'],
        'ipc':[ 6, 'ipc' ],
        'raw':[ 7, 'raw' ]
    },
    "connTypes":{ # Current socket connection type
        "server":[0,"s","server"], 
        "client":[1,"c","client"],
        "cross" :[2,"x","cross"] # For both client & server communications (under-construction)
    },
    "defaults":{
        "type":"tcp", 
        "handle":"c"
    },
    "libraryServer":{
        "allowedHosts":["*"], # Any host
        "clientMax":10, # Maximum clients to handle
        "host":"0.0.0.0", # Host
        "port":9999, # Port
        "lifespan":0, # 0=eternal, else in seconds (int)
        "alive":False, # Alive boolean for operation
        "handle":0 # Client handler (if 0 use default: )
    },
    "libraryClient":{
        "host":"0.0.0.0", # Host
        "port":9999, # Port
        "handle":0 # Server-connection handler (data send/recv handle, default: )
    },
    "timeout":5,
    "transportEncoding":"utf-8"
}
```

##### Library & History

While both are under-construction, it is semi-functional, the goal is to have a library of sockets giving the capability for repetitive/reusable servers/connects allowing for them to be spawned post-creation anytime.

```python
sock.library={}
sock.history={}
```

During operations through the internal `_connect`,`_serve` functions the `_historyAppend` function will be called, appending data to `history`. 

```python
sock._historyAppend(
    "0.0.0.0", # Connection host
    9999, # Connection port
    {} # Data to append
)
```

The following data object will be:

```python
sock.history['0.0.0.0:9999']={
    "connections":0, # Incriments per connection from the same host.
    "dataHistory":[] # The data list.
}
```

###### Library Functions

* **_libBuild**

Used to build & apped a `libObject` to `sock.library` for further oprations.

```python
libObject = sock._libBuild(
    "mySocket", # Lib ID
    0, # TCP // sockType (From `sock._socketGetType`:`sock._resolveSockType`) Ref: `typeOperators`
    1, # client // connType (From `sock._socketGetConnectionType`) Ref: `connTypes`
    '0.0.0.0', # (optional) Default: Dependent on `connType`
    9999, # (optional) Default: Dependent on `connType`
    15 # (optional) Default: `timeout`
)
```

__I plan on working on operational/practical functionality, these operations are not completed and will be changed!__

The resulting object will be:

```python
libObject = {
    "type":0,
    "connType":1,
    "host":"0.0.0.0",
    "port":9999,
    "timeout":15,
    "alive":False,
    "socket":sockObject # Result from `socket._socketGetType`
}
```

##### Sockets

To get a socket based off a type found inside of `typeOperators`.

```python
sockObject = sock._socketGetType() # Default: tcp (type: socket.socket)
```

```python
def _socketGetType(self,sockType:str|int=None):
        """"""
        sockType = sockType if sockType else self.config.get('defaults')['type']
        sockType = self._resolveSockType(sockType)
        # TCP IPv4
        if   sockType == "tv4": socketObject = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # TCP IPv6
        elif sockType == "tv6": socketObject = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        # UDP IPv4
        elif sockType == "uv4": socketObject = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # TCP IPv6
        elif sockType == "uv6": socketObject = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        # TCP (system)
        elif sockType == "tcp": socketObject = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # UDP (system)
        elif sockType == "udp": socketObject = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # IPC (linux only)
        elif sockType == "ipc": socketObject = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        # RAW (packets)
        elif sockType == "raw": socketObject = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        else:
            eM = f"'sockType'({str(sockType)}) was invalid."
            self.logPipe("_socketGetType",eM,l=2)
            raise ValueError(eM)
        return socketObject
```

* **Test If A Host:Port Is Alive**

```python
isAlive = sock._connectEX(
    sockObject, 
    "0.0.0.0", # Target host  
    9999, # Target port
    timeout=5 # Default: `timeout`
)
# `isAlive` will be `True` if the `0.0.0.0:9999` was available, else `False`
```

* **Connecting & Sending Data**

```python
sock._connect(
    sockObject,
    "0.0.0.0",
    9999,
    "This is the data I wish to send...", # This can be either bytes or str
    timeout=5 # Default: `timeout`
)
```

* **Closing A Connection (If Outside Of `_connect`,`_connectEX`,`_serve`)**

```python
sock._close(
    sockObject
)
```

* **Binding Sockets For Hosting (socket.socket.bind)**

```python
sockObject = sock._bindSocket(
    sockObject,
    "0.0.0.0",
    9999
)
```

* **Testing If A `sockObject` Is Bound**

```python
isBound = sock._isBound(
    sockObject
)
# True if bound else False
```

* **Serving A TCP Server**

<a name="serving-a-tcp-server"></a>__NOTE :__ Validate your `sock.config` prior to launch.

```python
server = sock._serve(
    sockObject,
    "0.0.0.0", # (optional) Default: `libraryServer.host`
    9999, # (optional) Default: `libraryServer.port`
    10, # (optional) Default: `libraryServer.clientMax`
    ["*"], # (optional) Default: `libraryServer.allowedHosts`
           # NOTE: This is going to change soon and will operate based off length...
    300, # (optional) Default: `libraryServer.lifeSpan` Time to keep the server alive
    clientHandle=None # (optional) Default: `libraryServer.handle`
                      # NOTE: We will go further into detail into building your own handlers as we go...
)
```

__NOTE :__ While this does work to do simple things like connect and send commands to a reverse shell, I find that the script will not terminate. I'm sure this is due to some threading/exception catch failure issue however it is not my main priority.

* **Creating Custom Client Handles**

<a name="connecting--sending-data"></a>```python
defaultHandleType = 0

def _exampleClientHandler(clientHandle:socket.socket,
                          clientAddress:tuple):
    # Your socket handle...
    try:
        data = clientHandle.recv(1024)
        if data:
            data = data.decode('utf-8')
            if defaultHandleType in [0,'r','return']: return data
            elif defaultHandleType in [1,'sB','sendBack']:
                # Send data back to the server
                clientHandle.sendall(data.encode('utf-8'))
                clientHandle.close()
            return data
        else:
            clientHandle.close()
            return None
    except Exception as E:
        # Your exception handler
        raise Exception(f"Unknown exception while handling client connection from {str(clientAddress)}.")

sockObject = sock._socketGetType()
server = sock.serve(
    sockObject,
    clientHandle=_exampleClientHandle
)
# Now every client the connects will be passed to `_exampleClientHandler` for further operations.
```

#### nmap 

__Under-Construction__

#### externalProxies

__Under-Construction__

#### browser

__Under-Construciton__
