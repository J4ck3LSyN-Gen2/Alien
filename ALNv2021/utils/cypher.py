import hashlib, os, base64, string, secrets, getpass
from typing import Any
# Crypts
from cryptography.fernet import Fernet  # type: ignore
from cryptography.hazmat.primitives import hashes, padding  # type: ignore
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding # type: ignore
from cryptography.hazmat.primitives import serialization # type: ignore
from cryptography.hazmat.backends import default_backend # type: ignore


__version__ = "0.0.1"

class passwd:

    """
    *-- Password Operations --*

    NOTE: May include linux `.passwd` operations, for now its mainly
          password vlidation, generation and operations.
    """

    def __init__(self,
                 logger:Any=None):
        self.logger=logger

    def getSecurePasswd(self,prompt:str=""):
        """"""
        try:
            passwd = getpass.getpass(prompt=prompt)
        except Exception as E:
            eM = f""
            raise Exception(eM)

    def _tokenHex(self,length:int):
        """
        
        """
        if not isinstance(length,int):
            eM = f"Argument 'length'({str(length)}) was not 'int' type, got: {str(type(length).__name__)}."
            self.logPipe("_tokenHex",eM,l=2)
            raise TypeError(eM)
        if length == 0:
            eM = "'length' cannot be 0..."
            self.logPipe("_tokenHex",eM,l=2)
            raise ValueError(eM)
        try:
            retVal = secrets.token_bytes(length)
            self.logPipe("_tokenHex",f"Token hex length({str(length)}) evaluated to '{str(retVal)}'.")
            return retVal
        except Exception as E:
            eM = f"Unknown exception during operation on tokenHex"

    def _tokenBytes(self,length:int):
        """"""
        if not isinstance(length,int):
            eM = f"Argument 'length'({str(length)}) was not 'int' type, got: {str(type(length).__name__)}."
            self.logPipe("_tokenBytes",eM,l=2)
            raise TypeError(eM)
        if length == 0:
            eM = "'length' cannot be 0..."
            self.logPipe("_tokenBytes",eM,l=2)
            raise ValueError(eM)
        try:
            retVal = secrets.token_bytes(length)
            self.logPipe("_tokenBytes",f"Token bytes length({str(length)}) evaluated to '{str(retVal)}'.")
            return retVal
        except Exception as E:
            eM = f"Unknown exception during operation on tokenBytes: {str(E)}."
            self.logPipe("_tokenBytes",eM,l=2)
            raise Exception(eM)
    
    def _randomBytes(self,length:int):
        """"""
        if not isinstance(length,int):
            eM = f"Argument 'length'({str(length)}) was not 'int' type, got: {str(type(length).__name__)}."
            self.logPipe("_randomBytes",eM,l=2)
            raise TypeError(eM)
        if length == 0:
            eM = "'length' cannot be 0..."
            self.logPipe("_tokenHex",eM,l=2)
            raise ValueError(eM)
        try:
            retVal = os.urandom(length)
            self.logPipe("_randomBytes",f"Random bytes length({str(length)}) evaluated to '{str(retVal)}'.")
            return retVal
        except Exception as E:
            eM = f"Unknown exception during operation on randomBytes: {str(E)}"
            self.logPipe("_randomBytes",eM,l=2)
            raise Exception(eM)
    
    # _randomIntByRandomBytes
    # _buildPurelyRandom
    # _randInt

    ## Main
    # Log pipe
    def logPipe(self,r,m,l=None,e=None,f=False):
        if self.logger: self.logger.logPipe(r,m,loggingLevel=l,extendedContext=e,forcePrintToScreen=f)

class charDisplacementMap:

    """
    *-- Character Map Displacement --*

    Concept:
        - Older versions of alien carried this functionality, chances are 
          (even if it seems pointless) we will still bring it over.
    """

    def __init__(self,logger:Any):

        self.logger=logger

class steno:

    class paddingInject:

        def __init__(self,logger:Any=None):

            self.logger = logger

    class exifData:

        def __init__(self,logger:Any=None):

            self.logger = logger

    class encodeInImage:

        def __init__(self,logger:Any=None):

            self.logger = logger 

    def __init__(self,logger:Any=None):

        self.logger = logger



class hashing:

    """
    
    *-- Hashing Operations --*

    NOTE: May not stay, however due to personal preference with `hashlib` and 
          familiarity with it, I may add funcitonality while also using 
          functionality from `cryptography`
    
    """

    def __init__(self):


        pass

class crypto:

    """
    
    *-- Cryptography --*
    
    """

    def __init__(self,logger:Any=None):        
        
        self.symKey = Fernet.generate_key()
        self.fernet = Fernet(self.symKey)
        self.backend = default_backend()
        self.config = {
            "encoding":"utf-8"
        }

    ## Symmetric encryption
    # _symmEncrpyt
    # _symmDecrypt
    
    ## Asymmetric encyption
    # def _asymGenerateRSAKeyPair
    # def _asymLoadPrivateKey
    # def _asymLoadPublicKey
    # def _asymEncrypt
    # def _asymDecrypt
    
    ## Signing
    # def _signData
    # def _signVerify
    
    ## AES
    # _aesEncrypt
    # _aesDecrypt

    ## Main
    # Log pipe
    def logPipe(self,r,m,l=None,e=None,f=False):
        if self.logger: self.logger.logPipe(r,m,loggingLevel=l,extendedContext=e,forcePrintToScreen=f)


class cypher:

    """
    
    *-- Obfuscation & Ciphers --*
    
    """

    def vigenereCypher(
            data:str|bytes,
            key:str|bytes,
            mode:str='e')->str|bytes:
        pass

    def rot13(data:str|bytes):
        pass

    def ceasar(
            data:str|bytes,
            shift:int):
        pass

    def xor(
            data:str|bytes,
            key:bytes):
        pass


class shellCode:

    """
    Concept:
        - Customized shellcode
            * Reasearch more into `donut` asm
            NOTE: https://gitlab.com/kalilinux/packages/donut-shellcode/-/blob/kali/master/README.md?ref_type=heads
    """

    def __init__(self,logger:Any=None):

        self.logger = logger 
