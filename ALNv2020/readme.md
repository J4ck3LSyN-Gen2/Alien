# ALNv2020(Generation 2 version 0.2.0)

The alien framework is a modular toolkit centralized around a powerfull JSON-based interpreter. It is engineered for a wide array of software engineering and cybersecurity-related tasks, enabling the execution of complex logic operations with
the capabilities of library importation (alien/pythonic), theading, LLM(ATLAS) ollama
communications, low-level memory/process management and different redteam(offsec) tools and network based operations.

## Index

__NOTE__ I highly recommend useing the index and making it good practice. (saves time)

- [Setup & Installation](#setup--installation)
- [Usage](#usage)
  - [Application](#application)
  - [Python Importation](#python-importation)
- [Interpreter (Alien Syntax)](#interpreter-alien-syntax)
  - [Important Directories](#important-directories)
  - [Program Structure](#program-structure)
  - [Standard Library](#standard-library)
  - [Class Structure](#class-structure)
  - [Class Instance Creation](#class-instance-creation)
- [Statements](#statements)
- [Expressions](#expressions)
- [confHandle (Configuration)](#confhandle-configuration)
- [Logger (Logging)](#logger-logging)
- [Process (Process & Threads)](#process-process--threads)
-   [Starting, Stopping & Removing Processes](#starting-stopping--removing-processes)
-   [Appending Subprocesses](#appending-subprocesses)
-   [Retrieving Output From Finished Subprocess](#retrieving-output-from-finished-subprocess)
-   [Appending Threads](#appending-threads)
-   [Que & Thread Wrapper Function](#que--thread-wrapper-function)

## Setup & Installation

Module installation:

```markdown
pip install -r requirements.txt
py -m install -r requirements.txt
```

__NOTE :__ The current of alien is built in `python 3.14`

## Usage

`py -m ALNv2020`

### Application

__NOTE__: The front end of `alien` if constantly under development and is under `constant` change, please be patient while I complete all the functionality. Some `modules` will be directly callable, however most functionality will be centralized around `py -m ALNv2020` itself.

__NOTE__: When using the `intr` functionality, the `-lP,--logPipe` flag when enabled will impact performance on script execution heavily. This is due to the amount of logging performed during operations, for most instances (unless you are debugging and want deeper information), `-lP` is not needed.

```markdown
*-- Alien Framework --*
version: 2.0.2.0
author:  J4ck3LSyN

--------------------------------------------------------------------------------

        Usage: py -m ALNv2020 <args> <mode> ...

--------------------------------------------------------------------------------

        The alien framework(ALNv2020) is a modular toolkit centered
        around a powerful, programmable JSON-based interpreter. It is
        engineered for a wide array of software engineering and
        cybersecurity-related tasks, enabling the execution of complex
        logic operations with libraries, executable scripts, pythonic
        operations, threading, LLM(ollama) communications, low-level
        memory/process management, and network communication.

        Global Arguments:

                (debugging)     py -m ALNv2020 -dL,--debugLevel (0,1,2,3) <args> <mode> ...
                 - Debugging level.
                 - type: int
                 - default: 2

                (configuration) py -m ALNv2020 -cP --configPath 'targetFile.json' <args> <mode> ...
                 - Configuration file path.
                 - type: str
                 - default: 'default.json'

--------------------------------------------------------------------------------


        Interpreter:
                File Execution:
                Usage: py -m ALNv2020 intr <args> 'targetFile.json' <args> <kwargs>

                Indepth Logging (slows performance):
                Usage: py -m ALNv2020 intr -lP <args> 'targetFile.json' <args> <kwargs>

                New Projects:
                Usage: py -m ALNv2020 intr -n <args> 'targetFile.json' <args> <kwargs>

--------------------------------------------------------------------------------
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

## Interpreter (Alien Syntax)

<div style="border-left: 5px solid red; background-color: #180501; padding: 10px; margin: 10px 0;">
    <strong>Note:</strong> 
    
    Along side most operations, the `interpreter` is still heavily under construction, while it does allign with my objective, it dos not run as fast as I wish. As time goes on I will work on better optimizations... For now when attempting script executions, be AWARE that most will take some time. The operational difference is dependant on the amount of nested operations inside of your code...
</div>


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

#### Libary List

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
