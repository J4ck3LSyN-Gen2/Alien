import os
import json
from typing import Any, Optional

__version__ = "0.0.5"

class path:

    def __init__(self,
                 home:str=None,
                 logger:Any=None):
        self.appHome = True
        self.logger = logger
        self.home   = self.gCWD()
        if home: 
            self.home = self._appendHome(home)
        self.ls     = self.listDir()

        self.logPipe("__init__",f"path initialized with the home: {str(self.home)}")


    ## File/Dir existance

    def _existFile(self,path:str):
        """"""
        return os.path.isfile(path)

    def _existDir(self,path:str):
        """"""
        return os.path.isdir(path)
    
    ## Files

    def rmFile(self,path:str):
        """"""
        if not self._existFile(path):
            eM = f"File '{str(path)}' does not exist."
            self.logPipe("rmFile",eM,l=2)
            raise ValueError(eM)
        try:
            os.remove(str(path))
            self.logPipe("rmFile",f"Removed '{str(path)}'.")
        except Exception as E:
            eM = f"Unknown exception while attempting to remove '{str(path)}': {str(E)}."
            self.logPipe("rmFile",eM,l=2)
            raise Exception(eM)

    def _file(self,path:str,operand:str="r",data:Any=None):
        """
        Read, Write, Append & Check Existance Of A File.

        Args:
            path (str): File path.
            operand (str, optional): Operand.
                                     r  -> read
                                     w  -> write
                                     wb -> write bytes
                                     rw -> read&write
                                     a  -> append
                                     e  -> exist
        """
        if str(operand) not in ['r','w','rw','a','e']:
            eM = f"Argument 'operand'({str(operand)}) was invalid, expceted (r,w,rw,a,e)."
            self.logPipe("_file",eM,l=2)
            raise ValueError(eM)
        if not self._existFile(path) and operand != "e":
            eM = f"File '{str(path)}' does not exist."
            self.logPipe("_file",eM,l=2)
            raise ValueError(eM)
        if operand in ['r','rw']:
            if operand == 'rw' and not data:
                eM = f"Cannot perform('{str(operand)}') on '{str(path)}' due to the 'data' argument being missing."
                self.logPipe("_file",eM,l=2)
                raise ValueError(eM)
            try:
                with open(str(path),'r',encoding='utf-8') as f:
                    retVal = f.read()
                    f.close()
                self.logPipe("_file",f"Read '{str(len(retVal))}'/bytes from '{str(path)}'.")
                # Update & Write new data
                retVal = retVal + str(data)
                with open(str(path),'w',encoding='utf-8') as f:
                    f.write(retVal)
                    f.close()
                self.logPipe("_file",f"Wrote '{str(len(data))}'/bytes to '{str(path)}'.")
                return retVal
            except Exception as E:
                eM = f"Unknown exception while attempting to read '{str(path)}': {str(E)}"
                self.logPipe("_file",eM,l=2)
                raise Exception(eM)
            else:
                try:
                    with open(str(path),'r') as fileHandle:
                        retVal = fileHandle.read()
                        fileHandle.close()
                    self.logPipe('_file',f"Read '{str(len(retVal))}'/bytes from '{str(path)}'.")
                    return retVal
                except Exception as E:
                    eM = f"Unknown exception while attempting operand('{str(operand)}') on '{str(path)}': {str(E)}."
                    self.logPipe("_file",eM,l=2)
                    raise Exception(eM)
        elif operand in ['w']:
            if not data:
                eM = f"Cannot perform operand('w') on path('{str(path)}') due to the 'data' argument missing."
                self.logPipe("_file",eM,l=2)
                raise ValueError(eM)
            try:
                with open(str(path),'w',encoding='utf-8') as f:
                    f.write(str(data))
                    f.close()
                self.logPipe("_file",f"Wrote '{str(len(data))}'/bytes to '{str(path)}'.")
                return data
            except Exception as E:
                eM = f"Unknown exception while attempting to write to '{str(path)}': {str(E)}."
                self.logPipe("_file",eM,l=2)
                raise Exception(eM)
        elif operand in ['wb']:
            if not data:
                eM = f"Cannot perform operand('wb') on path(''{str(path)}') due to the 'data' argument missing."
                self.logPipe("_file",eM,l=2)
                raise ValueError(eM)
            try:
                if not isinstance(data,bytes): data = str(data).encode('utf-8')
                with open(str(path),'wb') as f:
                    f.write(data)
                    f.close()
                self.logPipe("_file",f"Wrote '{str(len(data))}'/bytes to '{str(path)}'.")
                return data
            except Exception as E:
                eM = f"Unknown exception while attempt to write bytes to '{str(path)}': {str(E)})'."
                self.logPipe("_file",eM,l=2)
                raise Exception(eM)
        elif operand in ['a']:
            if not data:
                eM = f"Cannot perform operand('a') on path('{str(path)}') due to the 'data' argument missing."
                self.logPipe("_file",eM,l=2)
                raise ValueError
            try:
                with open(str(path),'a',encoding='utf-8') as f:
                    f.write(str(data))
                    f.close()
                self.logPipe("_file",f"Appended '{str(len(data))}'/bytes to '{str(path)}'.")
                return data 
            except Exception as E:
                pass
        elif operand in ['e']:
            return self.exist(path)
        else:
            eM = f""
    
    ## Directory
    def rmDir(self,path:str):
        """"""
        if not self.exist(path):
            eM = f"Directory '{str(path)}' does not exist."
            self.logPipe("rmDir",eM,l=2)
            raise ValueError(eM)
        try:
            os.rmdir(path)
        except Exception as E:
            eM = f"Unknown exception while attempting to remove directory '{str(path)}': {str(E)}."
            self.logPipe("rmDir",eM,l=2)
            raise Exception(eM)

    def mkDir(self,dirName:str,path:str=None):
        """"""
        path = path if path else self.home
        target = os.path.join(path.strip(os.sep),dirName)
        if self._existDir(target):
            eM = f""
            raise ValueError(eM)
        try:
            os.mkdir(target)
        except Exception as E:
            eM = f"Unknown exception while attempting to create '{str(target)}': {str(E)}."
            raise Exception(eM)

    def _appendHome(self,path:str):
        """"""
        if self.appHome: 
            retVal = os.path.join(self.home.strip(os.sep),path);return retVal
            
    ## Main
    # Read File As JSON
    def readJSONData(self,path:str):
        """"""
        path = self._appendHome(path)
        self.logPipe("readJSONData",f"Attempting to read JSON file '{str(path)}'")
        if self.identify(str(path)) == 1:
            retVal = None
            try:
                with open(str(path),'r',encoding='utf-8') as f: 
                    retVal = json.load(f)
                self.logPipe("readJSONData",f"Read {str(len(str(retVal)))}/bytes of data from path '{str(path)}'")
            except (IOError, json.JSONDecodeError) as E:
                self.logPipe("readJSONData",f"Failed to load path '{str(path)}' due to IOError or JSONDecodeError: {str(E)}",l=2)
                retVal = None
            return retVal
        else:
            self.logPipe("readJSONData",f"Failed to read JSON data from path '{str(path)}' due to path not being a file or being non-existant.",l=2)
            return None

    # List directory contents
    def listDir(self,path:str=None):
        """
        Lists Contents In A Directory.

        Args:
            path (str): Target path.

        Returns: tuple/None
                 ( <contents>, path )
                 None on error.
        """
        path = self._appendHome(path) if path else str(self.home)
        pathID = self.identify(str(path))
        if pathID == 2:
            retVal = (os.listdir(str(path)),str(path))
            self.logPipe("listDir",f"Returning: {str(retVal)}")
            return retVal
        else: 
            self.logPipe("listDir",f"Failed to list path '{str(path)}' due to non-existance or not being a directory. pathID: {str(pathID)}",l=2)
            return None

    # Path Identity
    def identify(self,path:str):
        """
        Identifies Existance & File/Directory.

        Identities:
            - 0 :: Non-Existant
            - 1 :: Directory
            - 2 :: File

        Args:
            path (str): Target path.

        Returns: identifier.
        """
        path = self._appendHome(path)
        self.logPipe("identify",f"Attempting to identify '{str(path)}'.")
        retVal = 0
        if self.exist(str(path)):
            if os.path.isfile(str(path)): retVal = 1
            elif os.path.isdir(str(path)): retVal = 2
        self.logPipe("identify",f"Returning: {str(retVal)}")
        return retVal

    # Path exists
    def exist(self,path:str):
        """
        Path Existance.
        """
        path = self._appendHome(path)
        self.logPipe("exist",f"Checking the existance of path '{str(path)}'")
        retVal = os.path.exists(str(path))
        self.logPipe("exist",f"Path '{str(path)}' resulted in {str(retVal)}")
        return retVal

    # Get current working directory
    def gCWD(self): return os.getcwd()

    # Log Pipe
    def logPipe(self,r,m,l=None,e=None,f=False):
        if self.logger != None: self.logger.logPipe(r,m,loggingLevel=l,extendedContext=e,forcePrintToScreen=f)