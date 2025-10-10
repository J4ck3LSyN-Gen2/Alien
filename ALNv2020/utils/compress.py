import huffman as huffmanHandle # type: ignore
import zipfile # type: ignore
from collections import Counter # type: ignore
from typing import Any, List, Dict
import os
import sys

__version__ = "0.0.2"

class zipCompress:
    
    """
    *-- Zip Compression --*
    """

    def __init__(self,
                 logger:Any=None,
                 confHandle:Any=None):
        self.logger = logger
        self.confHandle = confHandle 
        self.zipfile = zipfile.ZipFile
        self.config = {
            "defaultOutputPath": os.getcwd()
        }

    ## Compression
    def _compressSpecifiedFiles(self, outputZipName:str, fileList:List[str], zipPath:str=None):
        """"""
        if not (isinstance(outputZipName,str) and isinstance(fileList,list)):
            eM = f"Argument(s) 'outputZipName'({str(outputZipName)}) and/or 'fileList'({str(fileList)}) was not 'str' and 'list' types, got: '{str(type(outputZipName).__name__)}','{str(type(fileList).__name__)}'."
            self.logPipe("_compressSpecifiedFiles",eM,l=2)
            raise TypeError(eM)
        
        # If an explicit zipPath is given, use it. Otherwise, construct it.
        if not zipPath:
            if not outputZipName.lower().endswith('.zip'):
                outputZipName += '.zip'
            zipPath = os.path.join(self.config['defaultOutputPath'], outputZipName)

        try:
            with self.zipfile(zipPath,'w') as zipHandle:
                for file in fileList:
                    zipHandle.write(file)
        except Exception as E:
            eM = f"Unknown exception during operation: {str(E)}"
            self.logPipe("_compressSpecifiedFiles",eM,l=2,e={
                "outputZipName":str(outputZipName),
                "fileList":str(fileList),
                "zipPath":str(zipPath)
            })
            raise Exception(eM)

    def _compressDirectory(self,directoryPath:str,zipPath:str=None):
        """"""
        if not isinstance(directoryPath,str):
            eM = f"Argument 'directoryPath'({str(directoryPath)}) was not 'str' type, got: '{str(type(directoryPath).__name__)}'."
            self.logPipe("_compressDirectory",eM,l=2)
            raise TypeError(eM)
        
        if not os.path.isdir(directoryPath):
            eM = f"Source path '{str(directoryPath)}' is not a directory."
            self.logPipe("_compressDirectory",eM,l=2)
            raise ValueError(eM)

        try:
            zipPath = zipPath if zipPath else f"{os.path.basename(directoryPath.rstrip('/\\'))}.zip"
            with self.zipfile(zipPath,'w',compression=zipfile.ZIP_DEFLATED) as zipHandle:
                for root,_,files in os.walk(directoryPath):
                    for file in files:
                        filePath = os.path.join(root,file)
                        zipHandle.write(filePath,os.path.relpath(filePath,directoryPath))
        except Exception as E:
            eM = f"Unknown exception during operation: {str(E)}"
            self.logPipe("_compressDirectory",eM,l=2,e={
                "directoryPath":str(directoryPath),
                "zipPath":str(zipPath)
            })
            raise Exception(eM)
        
    # cry stuff is gonna be through pyminizip

    ## Decompression
    def _getContents(self,targetPath:str):
        """"""
        if not os.path.exists(targetPath):
            eM = f"Argument 'targetPath'({str(targetPath)}) was not a valid file path."
            self.logPipe("_getContents",eM,l=2)
            raise ValueError(eM)
        zipInfo = {}
        fileList = []
        try:
            with zipfile.ZipFile(targetPath,'r') as zipHandle:
                fileInfo = [i for i in zipHandle.namelist()]
                fileList = fileInfo
                dataInfo = [{'fileName':str(i.filename),'size':i.file_size,'date':i.date_time} for i in zipHandle.infolist()]
                for i in dataInfo:
                    if i['fileName'] in fileInfo:
                        zipInfo[i['fileName']]=i
                
            return [fileList,zipInfo]
        except Exception as E:
            eM = f"Unknown exception while attempting to read the contents of '{str(targetPath)}'."
            self.logPipe("_getContents",eM,l=2)
            raise Exception(eM)

    def _decompressDirectory(self,targetPath:str,outputPath:str=None,outputDirectory:str=None):
        """"""
        outputPath = outputPath if outputPath else self.config['defaultOutputPath']
        outputDirectory = outputDirectory if outputDirectory else str(targetPath).split('.')[0]
        if not os.path.exists(targetPath):
            eM = f"Argument 'targetPath'({str(targetPath)}) was not a valid file path."
            self.logPipe("_decompressDirectory",eM,l=2)
            raise ValueError(eM)
        try:
            with zipfile.ZipFile(targetPath,'r') as zipHandle:
                outputFinal = os.path.join(outputPath,outputDirectory)
                zipHandle.extractall(outputFinal)
        except Exception as E:
            eM = f"Unknown exception while attempting extraction of '{str(targetPath)}': {str(E)}."
            self.logPipe("_decompressDirectory",eM,l=2)
            raise Exception(eM)
        
    # def _decompressEncryptedZip

    # def _decompress(self,filePath:str)
    ## Main
    # Log pipe
    def logPipe(self,r,m,l=None,e=None,f=False):
        if self.logger: self.logger.logPipe(r,m,loggingLevel=l,extendedContext=e,forcePrintToScreen=f)

class huffman:

    """
    *-- Huffman Encoding --*
    """

    def __init__(self,
                 logger:Any=None):
        self.logger = logger
        self.codeBook = {}
        self.huffman = huffmanHandle
        self.counter = Counter

    # Build the codeBook
    def _buildCodeBook(self,fList:List[tuple],setCodeBook:bool=True):
        """
        Builds The CodeBook For Huffman Compression.

        Args:
            fList (List[tuple]): Output from self._getFrequencyList
            setCodeBool (bool, optional): If True set self.codeBook to value.
        """
        try:
            codeBook = self.huffman.codebook(fList)
            self.logPipe("_buildCodeBook",f"Built the 'CodeBook' based off given frequency list: '{str(fList)}'.")
            if setCodeBook == True: self.codeBook = codeBook
            return codeBook
        except Exception as E:
            eM = f"Unknown exception during operation: {str(E)}"
            self.logPipe("_buildCodeBook",eM,l=2,e={
                'fList':str(fList),
                'setCodeBook':str(setCodeBook)
            })
            raise Exception(eM)

    # Get frequency list
    def _getFrequencyList(self,data:str):
        """
        Returns A 'Frequency' List Off 'data'.
        """
        if not isinstance(data,str) or len(data) == 0:
            eM = f"Argument 'data'({str(data)}) was either not a string or carried a length of 0. (Type: {str(type(data).__name__)})."
            self.logPipe("_getFrequencyList",eM,l=2)
            raise ValueError(eM)
        freq = self.counter(str(data))
        fList = [(sym,frq) for sym,frq in freq.items()]
        self.logPipe("_getFrequencyList",f"Returning frequency list from data: '{str(data)}'.",e={
            'frequency list':str(fList)
        })
        return fList

    ## Main
    # reset
    def reset(self):
        """Resets The Current codeBook."""
        self.codeBook = {}
        
    # run 
    def run(self,data:str,setCodeBook:bool=True,encodePost:bool=True):
        """
        Runs The Full Encoding Operation `self._buildCodeBook(self._getFrequencyList)`.
        
        Notes:
            - If `setCodeBook` is True it will set `self.codeBook`.
            - If `encodePost` is True than it will setup, than encode.

        Args:
            data (str):
            setCodeBool (bool, optional):
            encodePost (bool, optional):

        Returns: dict
                {
                    'data':<input string>,
                    'codeBook':<built codeBook>,
                    'encoded':<encoded data (if encodePost)>
                }
        """
        if not isinstance(data,str) or len(data) == 0:
            eM = f"Argument 'data'({str(data)}) was either not a string or carried a length of 0. (Type: {str(type(data).__name__)})."
            self.logPipe("setup",eM,l=2)
            raise ValueError(eM)
        fList = self._getFrequencyList(data)
        codeBook = self._buildCodeBook(fList,setCodeBook=setCodeBook)
        if encodePost:
            dataEncoded = self.encode(data)
            return {
                'data':str(data),
                'codeBook':codeBook,
                'encoded':dataEncoded
            }
        return {
            'data':str(data),
            'codeBook':codeBook
        }        

    # encode
    def encode(self,data:str,codeBook:Dict[str,Any]=None):
        """
        Encodes (compresses) A String Of Data.
        """
        self.logPipe("encode",f"Attempting to encode {str(len(data))}/bytes...")
        # Data validation
        if not isinstance(data,str) or len(data) == 0:
            eM = f"Argument 'data'({str(data)}) must be a string and carry a length greater than 0. (Type: {str(type(data).__name__)})."
            self.logPipe("encode",eM,l=2)
            raise ValueError(eM)
        codeBook = codeBook if codeBook else self.codeBook
        # CodeBook validation
        if codeBook is None:
            eM = f"Argument 'codeBook' was not provided and the internal 'self.codeBook' is not configured... Please run `self._buildCodeBook(self._getFrequencyList)`."
            self.logPipe("encode",eM,l=2)
            raise ValueError(eM)
        if not isinstance(codeBook,dict) or len(codeBook) == 0:
            eM = f"'codeBook'({str(codeBook)}) was either not a dictionary or carried a length of 0. (Type: {str(type(codeBook).__name__)})."
            self.logPipe("encode",eM,l=2)
            raise ValueError(eM)
        # Attempt encoding
        try:
            retVal = str("").join(codeBook[char] for char in data)
            self.logPipe("encode",f"Data ({str(len(data))}/bytes) has been encoded: '{str(retVal)}'.")
            return retVal
        except Exception as E:
            eM = f"Unknown exception during operation: {str(E)}."
            self.logPipe("encode",eM,l=2,e={
                "data":str(data),
                "codeBook":str(codeBook)
            })
            raise Exception(eM)
    # decode
    def decode(self,data:str,codeBook:Dict[str,Any]=None):
        """
        Decodes (decompresses) A Encoded String Of Data.
        """
        self.logPipe("decode",f"Attempting to decode {str(len(data))}/bytes of data...")
        codeBook = codeBook if codeBook else self.codeBook
        if codeBook is None: # CodeBook validation
            eM = f"Argument 'codeBook' was not provided and the internal 'self.codeBook' is not configured... Please run `self._buildCodeBook(self._getFrequencyList)`."
            self.logPipe("decode",eM,l=2)
            raise ValueError(eM)
        if not isinstance(data,str) or len(data) == 0:
            eM = f"Argument 'data'({str(data)}) must be a string and carry a length greater than 0. (Type: {str(type(data).__name__)})."
            self.logPipe("decode",eM,l=2)
            raise ValueError(eM)
        if not isinstance(codeBook,dict) or len(codeBook) == 0:
            eM = f"'codeBook'({str(codeBook)}) was either not a dictionary or carried a length of 0. (Type: {str(type(codeBook).__name__)})."
            self.logPipe("decode",eM,l=2)
            raise ValueError(eM)
        codeBookReversed = {v:k for k,v in codeBook.items()}
        decodedData = ""
        currentCode = ""
        try:
            for bit in data:
                currentCode += bit
                if currentCode in codeBookReversed:
                    decodedData += codeBookReversed[currentCode]
                    currentCode = ""
            # After the loop, check if there are any leftover bits.
            # A valid encoded string should resolve completely.
            if currentCode:
                eM = f"Decoding finished with leftover, unmappable code: '{currentCode}'. The data may be corrupt or the codebook is incorrect."
                self.logPipe("decode", eM, l=2)
                # Depending on desired strictness, you could raise an error here.
                # For now, we'll log it as an error and return what we have.
            self.logPipe("decode",f"Decoded {str(len(decodedData))}/bytes...")
            return decodedData
        except Exception as E:
            eM = f"Unknown exception during operation: {str(E)}"
            self.logPipe("decode",eM,l=2,e={
                "data":str(data),
                "codeBook":str(codeBook)
            })
            raise Exception(eM)

    # Log Pipe
    def logPipe(self,r,m,l=None,e=None,f=False):
        if self.logger: self.logger.logPipe(r,m,loggingLevel=l,extendedContext=e,forcePrintToScreen=f)
