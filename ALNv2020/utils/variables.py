from typing import Any, Dict, Any, Optional, List
import random
import string 
import base64

__version__ = "0.0.1"

class variables:

    def __init__(self,logger:Any=None):

        self.logger = logger

    ## Base64

    def decodeBase64(self,encodedString:str|bytes):
        """"""
        if not isinstance(encodedString,bytes): encodedString = str(encodedString).encode('utf-8')
        try:
            return base64.b64decode(encodedString).decode('utf-8')
        except Exception as E:
            eM = f"Unknown exception while attempting to decode '{str(encodedString)}': {str(E)}."
            self.logPipe("decodeBase64",eM,l=2)
            raise Exception(eM)

    def encodeBase64(self,targetString:str|bytes):
        """"""
        if not isinstance(targetString,bytes): targetString=str(targetString).encode('utf-8')
        try:
            return base64.b64encode(targetString).decode('utf-8')
        except Exception as E:
            eM = f"Unknown exception while attempting to encode '{str(targetString)}': {str(E)}."
            self.logPipe("encodeBase64",eM,l=2)
            raise Exception(eM)
    
    ## Char Map
    # Get default char map
    
    ## Empty variables

    def getString(self):
        return ""
    
    def getDict(self):
        return {}
    
    def getList(self):
        return []
    
    def getBool(self):
        return False
    
    def getFloat(self):
        return 0.0
    
    def getInt(self):
        return 0
    
    def getBytes(self):
        return b""
    
    def getNone(self):
        return None
    
    
    ## Float

    def floatRound(self,var:float,decimals:int=None):
        """"""
        if not isinstance(var,float):
            eM = f"Argument 'var'({str(var)}) was not 'float' type, got: {str(self.getType(var))}."
            self.logPipe("floatRound",eM,l=2)
            raise TypeError(eM)
        return round(var,decimals)
    
    ## List

    def listIndex(self,index:int,data:List[Any]):
        """
        Gets An Item From A List.
        """
        if not isinstance(data,list) or not isinstance(index,int):
            eM = f"Argument 'index'({str(index)}) and 'data'({str(data)}) were not 'int' and 'list', got: {str(self.getType(index))} and {str(self.getType(data))}."
            self.logPipe("listIndex",eM,l=2)
            raise TypeError(eM)
        if index >= len(data):
            eM = f"Index '{str(index)}' out of range: {str(len(index)-1)}."
            self.logPipe("listIndex",eM,l=2)
            raise IndexError(eM)
        return data[index]

    def listPop(self,data:List[Any]):
        """
        Pops From A List.
        """
        if not isinstance(data,list):
            eM = f"Argument 'data'({str(data)}) was not 'list', got: {str(self.getType(data))}."
            self.logPipe("listPop",eM,l=2)
            raise TypeError(eM)
        return data.pop()

    def listAppend(self,var:Any,data:List[Any]):
        """
        Appends To A List.
        """
        if not isinstance(var,list):
            eM = f"Argument 'var'({str(var)}) was not 'list', got: {str(self.getType(var))}."
            self.logPipe("listAppend",eM,l=2)
            raise TypeError(eM)
        return data.append(var)
    
    ## bools

    def boolFlip(self,var:bool):
        """"""
        if not isinstance(var,bool):
            eM = f"Argument 'var'({str(var)}) was not 'bool' type, got: {str(self.getType(var))}."
            self.logPipe("boolFlip",eM,l=2)
            raise TypeError(eM)
        return True if var == False else False
    
    ## intigers

    def intigerShiftLeft(self,var:int,shift:int):
        """"""
        if not (isinstance(var,int) and isinstance(shift,int)):
            eM = f"Argument(s) 'var'({str(var)}) and/or 'shift'({str(shift)}) was not 'int' type(s), got: '{str(self.getType(var))}','{str(self.getType(shift))}'."
            self.logPipe("intigerShiftLeft",eM,l=2)
            raise TypeError(eM)
        return var << shift

    def initigerShiftRight(self,var:int,shift:int):
        """"""
        if not (isinstance(var,int) and isinstance(shift,int)):
            eM = f"Argument(s) 'var'({str(var)}) and/or 'shift'({str(shift)}) was not 'int' type(s), got: '{str(self.getType(var))}','{str(self.getType(shift))}'."
            self.logPipe("initigerShiftRight",eM,l=2)
            raise TypeError(eM)
        return var >> shift
    

    def intigerChangeBase(self,var:int,base:int):
        """"""
        if not (isinstance(var,int) and isinstance(base,int)):
            eM = f"Argument(s) 'var'({str(var)}) and/or 'base'({str(base)}) was not 'int' type(s), got: '{str(self.getType(var))}','{str(self.getType(base))}'."
            self.logPipe("intigerChangeBase",eM,l=2)
            raise TypeError(eM)
        try:
            retVal = int(var,base)
            return retVal
        except Exception as E:
            eM = f"Unknown exception while attempting to change base: {str(E)}"
            self.logPipe("intigerChangeBase",eM,l=2,e={
                "var":str(var),
                "base":str(base)
            })

    ## Bytes

    def encodeBytes(self,value:str,encoding:str=None):
        """"""
        if self.isType(value,'bytes'): return value
        if not self.isType(value,'str'): value = str(value)
        if not encoding: encoding = "utf-8"
        try:
            retVal = bytes(value,encoding=encoding)
            return retVal
        except Exception as E:
            eM = f"Unknown exception while attempting bytes encoding: {str(E)}"
            self.logPipe("encodeBytes",eM,l=2,e={
                'value':str(value),
                'encoding':encoding if encoding else "<Non-Given>"
            })
            raise Exception(eM)

    def decodeBytes(self,object:bytes,encoding:str=None):
        """"""
        if not self.isType(object,'bytes'):
            eM = f"Argument 'object'({str(object)}) was not 'bytes' type, got: {str(self.getType(object))}."
            self.logPipe("decodeBytes",eM,l=2)
            raise TypeError(eM)
        encoding = encoding if encoding else "utf-8"
        try:
            retVal = object.decode(encoding)
            return retVal
        except Exception as E:
            eM = f"Unknown exception while attempting bytes decoding: {str(E)}"
            self.logPipe("decodeBytes",eM,l=2,e={
                'object':str(object),
                'encoding':encoding if encoding else "<Non-Given>"
            })
            raise Exception(eM)
    

    ## Strings
    def stringDigits(self):
        """"""
        return string.digits
    
    def stringPrintable(self):
        """"""
        return string.printable

    def stringLetters(self):
        """"""
        return string.ascii_letters
    
    def stringLowerChars(self):
        """"""
        return string.ascii_lowercase
    
    def stringUpperChars(self):
        """"""
        return string.ascii_uppercase
    
    def stringPunctuation(self):
        """"""
        return string.punctuation
    
    def stringWhitespace(self):
        """"""
        return string.whitespace
    
    def stringHexDigits(self):
        """"""
        return string.hexdigits
    
    def stringUpper(self,var:str):
        """"""
        return str(var).upper()
    
    def stringLower(self,var:str):
        """"""
        return str(var).lower()

    def stringReverse(self,var:str):
        """
        Reverses A String.
        """
        return str(var)[::-1]

    def stringReplace(self,var:str,target:str,replacer:str=""):
        """
        Replace A String Inside Of Another String With A String...
        """
        return str(var).replace(str(target),str(replacer))

    # String to int (if int)
    def stringToInt(self,var:str):
        """
        Converts A String To A Integer If Possible.
        """
        try:
            retVal = int(var)
            return retVal
        except Exception as E:
            eM = f"Argument `var`({str(var)}) was not a valid 'int'... Exception: {str(E)}"
            self.logPipe("stringToInt",eM,l=2)
            raise TypeError(eM)
    
    def stringNewLine(self): 
        """
        New Line Escape Char.
        """
        return str("\n")
    
    def stringTab(self):
        """
        Tab Escape Char.
        """
        return str("\t")

    # Split string.
    def stringSplit(self,target:str,seperator:str):
        """
        Does str().split(seperator).

        Args:
            target (str): Target.
            seperator (str): String to seperate by.

        Returns: tuple
                 (True,list) # Seperated string
                 (False,str) # Failed seperation due to non-existance.
        """
        target = target if isinstance(target,str) else str(target)
        seperator = seperator if isinstance(seperator,str) else str(seperator)
        seperated = target.split(seperator)
        if len(seperator) > 1: return (True, seperated)
        else: return (False, target)

    # Join string
    def stringJoin(self,target:list[str],seperator:str=""):
        """
        Joins A String Based Off A Seperator. str().join([...])
        """
        if not isinstance(target,list): target = [str(target)]
        return str(seperator).join(target)

    ## Dict Operations
    def dictDimensionalAppend(self,keys:List[Any],data:Dict[str,Any],allowOverwrite:bool=False):
        """
        Appends Multiple Key/Value Pairs To A Dict.

        Args:
            keys (list[list[str,any]]): Key/Pairs.
            data (dict): Dictionary to operate on.
            allowOverwrite (bool, optional): If True allow for keys the are existant to be overwritten.
                                             Default is False.

        Returns: dict
        """
        if not isinstance(keys,list) or not isinstance(data,dict):
            eM = f"Arguments 'keys'({str(keys)}) and 'data'({str(data)}) were not 'list' and 'dict', got: {str(self.getType(keys))} and {str(self.getType(data))}."
            self.logPipe("dictDimensionalAppend",eM,l=2)
            raise TypeError(eM)
        for key in keys:
            if isinstance(key,list) and len(key) == 2:
                if str(key[0]) not in data: data[str(key[0])]=key[1]
                elif allowOverwrite: data[str(key[0])]=key[1]
                else: 
                    self.logPipe("dictDimensionalAppend",f"key '{str(key[0])}' failed due to being existant and `allowOverwrite` is False.")
                    continue
            else:
                self.logPipe("dictDimensionalAppend",f"key '{str(key)}' was not a list or did not carry a length of 2.")
                continue
        return data

    def dictListKeys(self,data:Dict[str,Any]):
        """
        Lists Keys Inside Of A Dict.
        """
        if not isinstance(data,dict):
            eM = f"Argument 'data'({str(data)}) was not 'dict', got: {str(self.getType(data))}."
            self.logPipe("dictListKeys",eM,l=2)
            raise TypeError(eM)
        return [k for k in data.keys()]

    def dictRemove(self,key:str,data:Dict[str,Any]):
        """
        Removes Keys From A Dict.
        """
        if not isinstance(data,dict):
            eM = f"Argument 'data'({str(data)}) was not 'dict', got: {str(self.getType(data))}."
            self.logPipe("dictRemove",eM,l=2)
            raise TypeError(eM)
        if str(key) not in data:
            eM = f"Data({str(data)}) is missing target key '{str(key)}'."
            self.logPipe("dictRemove",eM,l=2)
            raise KeyError(eM)
        del(data[str(key)])
        return data       

    def dictCopy(self,data:Dict[str,Any]):
        """
        Returns A Copy Of A Dict.
        """
        if not isinstance(data,dict):
            eM = f"Argument 'data'({str(data)}) was not 'dict', got: {str(self.getType(data))}."
            self.logPipe("dictCopy",eM,l=2)
            raise TypeError(eM)
        return data.copy() 

    def dictAppend(self,key:str,value:Any,data:Dict[str,Any]):
        """
        Sets Or Creates Key Data Pairs In A Dict.
        """
        if not isinstance(data,dict):
            eM = f"Arugment 'data'({str(data)}) was not 'dict', got: {str(self.getType(data))}."
            self.logPipe("dictAppend",eM,l=2)
            raise TypeError(eM)
        data[str(key)]=value
        return data

    # dict()[key]
    def dictGet(self,key:str,data:Dict[str,Any],elseOption:Any=None):
        """
        Does `dict().get(key,elseOption)`.

        Args:
            key (str): Key.
            data (data): Data.
            elseOption (any, optional): If key is non-existant return this instead.

        Returns: any/None
                 None on error (non-existance.)
        """
        if isinstance(data,dict):
            if elseOption: return data.get(str(key),elseOption)
            else: return data.get(str(key))
        else:
            eM = f"Argument 'data'({str(data)}) was not 'dict', got: {str(self.getType(data))}."
            self.logPipe("dictGet",eM,l=2)
            raise TypeError(eM)
    # If key in dict
    def dictKeyExist(self,key:str,data:Dict[str,any]):
        """
        Returns bool On Key Existance Inside Of Dict.

        Args:
            key (str): Key.
            data (dict): Data.

        Returns: bool/None
                 None on error.
        """
        if isinstance(data,dict):
            if str(key) in data: return True
            else: return False
        else:
            eM = f"Argument 'data'({str(data)}) was not 'dict', got: {str(self.getType(data))}."
            self.logPipe("dictKeyExist",eM,l=2)
            raise TypeError(eM)

    ## Type Operations
    def getType(self,var:Any):
        """
        Returns Variable Type As String.

        Args:
            var (any): Variable.

        Returns: str
                 IE: str,int,bool,...
        """
        return str(type(var).__name__)
    
    def isType(self,var:Any,targetType:str|List[str]):
        """
        Is A Variable A Type.

        Args:
            var (any): Variable.
            targetType (str): Target variable type (result from self.getType)

        Returns: bool
        """
        if not isinstance(targetType,list): targetType = [str(targetType)]
        if self.getType(var) in targetType: return True
        else: return False

    # Log Pipe
    def logPipe(self,r,m,l=None,e=None,f=False):
        if self.logger: self.logger.logPipe(r,m,loggingLevel=l,extendedContext=e,forcePrintToScreen=f)