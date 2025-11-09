from datetime import datetime # type: ignore
import time, random, string, base64, requests # type: ignore
import json, os, colorama, re, shutil # type: ignore 
from typing import Union, List, Dict, Optional, Any, Callable, Tuple
from pathlib import Path as pathLibPath # type: ignore


__version__ = "0.0.7"

def _clearPyCache(paths:str|List[str],base:str=None,logger:Optional[callable]=None):
    """"""
    def logPipe(logger:Optional[callable],m,l=None,e=None,f=False):
        if logger: logger.logPipe("_clearPyCache",
                                  m,
                                  loggingLevel=l,
                                  extendedContext=e,
                                  forcePrintToScreen=f)
    if isinstance(paths,str): paths = [str(paths)]
    base = base if base else pathLibPath.cwd()
    for relPath in paths:
        target = base.joinpath(relPath).resolve()
        try:
            logPipe(logger,f"Attempting to clear '{relPath}' : Base: '{base}''")
            if not target.exists(): 
                logPipe(logger,f"Skipped ('{str(target)}' Due to non-existant.")
                continue
            if target.is_dir():
                logPipe(logger,f"Attempting to clear directory '{target}'.")
                shutil.rmtree(target)
                logPipe(logger,f"Cleared directory '{target}'.")
            elif target.is_file():
                logPipe(logger,f"Attempting to clear file '{target}'.")
                os.remove(target)
                logPipe(logger,f"Cleared file '{target}'.")
            else:
                logPipe(logger,f"Skipped '{target}' path is not a regular file or directory.")
        except PermissionError:
            eM = f"Permission denied, could not delete {target}."
            logPipe(logger,eM,l=2)
            raise PermissionError(eM)
        except Exception as E:
            eM = f"Unknown exception while attempting to clear cache {str(base)} : {str(target)} : {', '.join(i for i in paths)}: {str(E)}."
            logPipe(logger,eM,l=2)
            raise Exception(eM)

class colorFormatter:

    def __init__(self,colorObject:Optional[Dict[str,Any]]=None):
        """"""
        self.cF = colorfullDisplay()
        self.cF.colorObject = colorObject if colorObject else self.cF.colorObject

    def __call__(self,text):
        return self.cF.colorize(text)
    
    def print(self,text):
        print(str(self.cF.colorize(text)))

    def format(self,text,**kwargs):
        if kwargs: text = text.format(**kwargs)
        return self.cF.colorize(text)

class colorfullDisplay:

    def __init__(self,logger:Any=None,confHandle:Any=None):

        self.logger = logger
        self.confHandle = confHandle

        self.config = {
        }

        self.colorObject = self._buildColorMap()

    # *--- Build Comparison Map ---*

    def _buildColorMap(self):
        """"""
        colorObject = {}
        fBAttrs = [
            (   
                "f",
                colorama.Fore,
                dir(colorama.Fore)
            ),
            (   
                "b",
                colorama.Back,
                dir(colorama.Back)
            )
        ]
        for o in fBAttrs:
            for attr in o[2]:
                if not str(attr).startswith("_"):
                    v = getattr(o[1],attr)
                    colorObject[f"{o[0]}.{attr.lower()}"]=v
                    if str(attr).lower() in [
                        "red",
                        "green",
                        "yellow",
                        "blue",
                        "magenta",
                        "cyan",
                        "white"]:
                        colorObject[f"{o[0]}.{attr.lower()[0]}"]=v
        for o in dir(colorama.Style):
            colorObject[f"s.{o.lower()}"]=getattr(colorama.Style,o)
        self.logPipe("_buildColorMap",f"Compiled Color Map, Keys: {', '.join([i for i in colorObject.keys()])}")
        return colorObject


    # *--- Main ---*

    def colorize(self,text:str,colorObject:Optional[Dict[str,Any]]=None):
        """"""
        colorObject = colorObject if colorObject else self.colorObject
        def replaceMatch(match):
            """"""
            code = match.group(1)
            return colorObject.get(code,match.group(0))
        def replaceBrace(match):
            """"""
            code = match.group(1)
            return colorObject.get(code,match.group(0))
        # For %(code) syntax
        text = re.sub(r'%$([\w\.]+)$', replaceMatch, text)
        # For ${code} syntax (optional)
        text = re.sub(r'\$\{([\w\.]+)\}', replaceBrace, text)
        # For {code} syntax (optional) 
        text = re.sub(r'\{([\w\.]+)\}', replaceBrace, text)

        return text

    def logPipe(self,r,m,l=None,e=None,f=False):
        if self.logger: self.logger.logPipe(r,m,loggingLevel=l,extendedContext=e,forcePrintToScreen=f)


class resources:
    

    def __init__(self,logger:Any=None,confHandle:Any=None):
        
        self.logger=logger
        self.confHandle=confHandle
        self.config = {
            "resourcePath":os.path.join("ALNv2021","etc","resources")
        }
        self.rescList = [os.path.join(self.config['resourcePath'],f) for f in os.listdir(self.config['resourcePath'])]


    def _validateFile(self,file:str):
        """"""
        return os.path.exists(file)
    
    def _loadData(self,file:str):
        """"""
        try:
            data = json.load(open(file,"r"))
            return data
        except json.decoder.JSONDecodeError as E:
            eM = f"Failed to open '{str(file)}' due to JSON Decode error: {str(E)}."
            self.logPipe("_loadData",eM,l=2)
            raise Exception(eM)
        except Exception as E:
            eM = f"Failed to open '{str(file)}' due to unknown error: {str(E)}."
            self.logPipe("_loadData",eM,l=2)
            raise Exception(eM)
    
    def _indexData(self,tags:List[str],keywords:List[str],data:List[Dict[str,Any]])->List[Dict[str,Any]]:
        """"""
        if (len(tags)==0 and len(keywords)==0): return data
        retVal = []
        for o in data:
            for t in tags:
                if str(t) in o['tags']: retVal.append(o)
            for k in keywords:
                if str(k) in str(o): retVal.append(o)
        return retVal
    
    def _prettyPrint(self,data:List[Dict[str,Any]])->List[str]:
        """"""
        return [ str(json.dumps(o,indent=2)) for o in data ]
    
    def _finalPrint(self,prettyPrintData:List[str],tags:List[str],keywords:List[str]):
        """"""
        return "\n".join([
            f"Resources:",
            f"Tags: {', '.join(tags)}",
            f"Keywords: {', '.join(keywords)}",
            "\n".join(prettyPrintData),
        ])

    def _search(self,tags:List[str],keywords:List[str]):
        """"""
        finalString = []
        for file in self.rescList:
            if not self._validateFile(file): continue
            data = self._loadData(file)
            if not data: continue
            indexedData = self._indexData(tags,keywords,data)
            prettyPrintData = self._prettyPrint(indexedData)
            finalString.append(prettyPrintData)
        return "\n".join(finalString)


    ## main
    # log pipe
    def logPipe(self,r,m,l=None,e=None,f=False):
        if self.logger: self.logger.logPipe(r,m,loggingLevel=l,extendedContext=e,forcePrintToScreen=f)

class misc:

    def encodeBase64(data:str|bytes,encoding:str="utf-16",decodeBytes:bool=True):
        """"""
        if not isinstance(data,(str,bytes)):
            pass
        if isinstance(data,str): str(data).encode(encoding)


    def decodeBase64(data:str|bytes,encoding:str="utf-16"):
        """"""
        pass

    def encodeInvisibleASCII(secretMessage:str,
                            coverText:str,
                            zeroChar:str='\u200b',
                            oneChar:str='\u200c',
                            delimiterChar:str='\u200d'):
        if not (isinstance(secretMessage,str) and isinstance(coverText,str)):
            eM = f"Argument(s) 'secretMessage'({str(secretMessage)[:5]}...) and/or 'coverText'({str(coverText)}) was not 'int' type, got: '{str(type(secretMessage).__name__)}','{str(type(coverText).__name__)}'."
            raise TypeError(eM)
        if len({zeroChar,oneChar,delimiterChar}) != 3:
            eM = "Either 'zeroChar'=='oneChar'=='delimiterChar'"
            raise ValueError(eM)
        try:
            binarySecret = ''.join(format(byte,"08b") for byte in str(secretMessage).encode("utf-8"))
            payload = binarySecret.replace('0',zeroChar).replace('1',oneChar)
            payload += delimiterChar
            smuggledText = coverText+payload
            return smuggledText
        except Exception as E:
            pass

    def decodeInvisibleASCII(smuggledText:str,
                             zeroChar:str='\u200b',
                             oneChar:str='\u200c',
                             delimiterChar:str='\u200d'):
        if not isinstance(smuggledText,str):
            pass
        if zeroChar == oneChar or zeroChar == delimiterChar or oneChar == delimiterChar:
            pass
        try:
            try:
                delimiterIndexInText = smuggledText.index(delimiterChar)
            except ValueError:
                return b""
            payloadChars = []
            currentIndex = delimiterIndexInText-1
            while currentIndex >= 0:
                char = smuggledText[currentIndex]
                if char == zeroChar or char == oneChar:
                    payloadChars.insert(0,char)
                    currentIndex-=1
                else: break
            invisiblePayload = "".join(payloadChars)
            if not invisiblePayload:
                return b""
            binarySecretList = []
            for char in invisiblePayload:
                if char == zeroChar: binarySecretList.append("0")
                elif char == oneChar: binarySecretList.append("1")
            binarySecret = "".join(binarySecretList)
            if len(binarySecret) % 8 != 0:
                return b""
            secretBytesList = []
            for i in range(0,len(binarySecret),8):
                byteChunk = binarySecret[i:i+8]
                if len(byteChunk) < 8:
                    pass
                try:
                    byteValue = int(byteChunk,2)
                    secretBytesList.append(byteChunk)
                except ValueError:
                    pass
            secretBytes = bytes(secretBytesList)
            return secretBytes
        except Exception as E:
            pass

    def isMarkdownInString(string:str):
        pass

    def getMarkdownFromString(string:str):
        pass

    def weatherGetForecast(self,zip:str,countryCode:str="US"):
        """"""
        pass