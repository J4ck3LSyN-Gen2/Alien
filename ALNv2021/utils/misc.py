import time, random, string, base64, requests , json, os # type: ignore
from typing import Union, List, Dict, Optional, Any, Callable, Tuple
from datetime import datetime # type: ignore


__version__ = "0.0.3"

class resources:
    

    def __init__(self,logger:Any=None,confHandle:Any=None):
        
        self.logger=logger
        self.confHandle=confHandle
        self.config = {
            "resourcePath":os.path.join("ALNv2021","etc","resources")
        }
        self.tags = []
        self.rescList = [os.path.join(self.config['resourcePath'],f) for f in os.listdir(self.config['resourcePath'])]
        self._loadTags()
    
    
    def _loadTags(self,file:str=None):
        """"""
        if file:
            data = self._loadData(file)
            for o in data:
                for i in o['tags']:
                    if i not in self.tags: self.tags.append(i)
            self.tags.sort()
        else:
            for f in self.rescList:
                data = self._loadData(f)
                for o in data:
                    for i in o['tags']:
                        if i not in self.tags: self.tags.append(i)
                self.tags.sort()


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

    def _search(self,tags:List[str],keywords:List[str],returnNoCombine:bool=False):
        """"""
        finalString = []
        for file in self.rescList:
            if not self._validateFile(file): continue
            data = self._loadData(file)
            if not data: continue
            iData = self._indexData(tags,keywords,data)
            if not iData: continue
            if returnNoCombine: 
                finalString.append(iData)
                continue
            finalString.append(self._finalPrint(self._prettyPrint(iData),tags,keywords))
        return finalString

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