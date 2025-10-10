from datetime import datetime # type: ignore
import time
from typing import Any, Dict
import random
import string
import base64
import requests # type: ignore (for resources getting)
import json

__version__ = "0.0.3"

class resources:
    

    def __init__(self,logger:Any=None,confHandle:Any=None):
        
        self.logger=logger
        self.confHandle=confHandle
        self.config = {
            "resourcePath":"ALNv2020\\resrc\\",
            "resources":[
                "cyberRes001.json"
            ]
        }
        self.resources = {}

    ## Initialization
    

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