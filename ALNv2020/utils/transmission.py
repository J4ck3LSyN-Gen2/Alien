import socket
import http
import re
import requests # type: ignore
import struct 
import select
import queue
from typing import Any, Dict, Optional, Callable, List
import psutil # type: ignore
import pycurl # type: ignore
from io import BytesIO, StringIO
import certifi

__vession__ = "0.0.3"

class curl:

    """
    *-- cURL Functions --*
    """

    def __init__(self,
                 logger:Callable=None,
                 confHandle:Callable=None):
        self.config = {}
        self.logger = logger 
        self.confHandle = confHandle

    ## Requests
    # basic
    def _basicGet(self,url:str):
        """"""
        c = pycurl.Curl()
        c.setopt(pycurl.URL,str(url))
        buffer = BytesIO()
        c.setopt(pycurl.WRITEDATA,buffer)
        c.setopt(pycurl.CAINFO,certifi.where())
        retVal = None
        failed = None
        try:
            c.perform()
            body = buffer.getvalue()
            respCode = c.getinfo(pycurl.RESPONSE_CODE)
            retVal = {
                "status":respCode,
                "body":body
            }
        except pycurl.error as E:
            eM = f"pycURL exception('{str(url)}'): {str(E)}."
            self.logPipe("_basicGet",eM,l=2)
            failed = eM
        finally:
            c.close()
        if not retVal:
            raise Exception(failed if failed else "Unkonwn!!")
        return retVal
    
    # _advancedGet(self,url:str,headers:List[str],timeout:int=None)
    # _postRequestData(self,url:str,header:List[str],data:Dict[str,Any],timeout:int=None)
    # _downloadFile(self,url:str,outputDir:str,outputName:str=None,timeout:int=None)
    # _resolveDNS
    # _proxyGet

    ## Main
    # Log pipe
    def logPipe(self,r,m,l=None,e=None,f=False):
        if self.logger: self.logger.logPipe(r,m,loggingLevel=l,extendedContext=e,forcePrintToScreen=f)

class nmap:
    
    """
    *-- NMAP Scans --*
    """

    def __init__(self,
                 logger:Any=None):
        self.logger = logger

    ## Main
    # Log Pipe
    def logPipe(self,r,m,l=None,e=None,f=False):
        if self.logger: self.logger.logPipe(r,m,loggingLevel=l,extendedContext=e,forcePrintToScreen=f)

class externalProxies:

    """
    *-- Procy Operations --*

    Concept:

        - proxychain configuration,
        - proxy sourcing.
        - proxy testing.
        - local proxy (mitm).
    """

    def __init__(self,
                 process:Any,
                 logger:Any=None):
        self.logger = logger
        self.process = process

    ## Main
    # Log Pipe
    def logPipe(self,r,m,l=None,e=None,f=False):
        if self.logger: self.logger.logPipe(r,m,loggingLevel=l,extendedContext=e,forcePrintToScreen=f)

# class manInTheMiddle (further down the line)

class browser:

    """
    *-- Simulated Browser Operations --*

    Concept:

        - Handles any operations the need a emulated browser.
        - burpsuite type functionality.
        - AI/LLM implementation.
        - Runs through selenium
    """

    def __init__(self,
                 process:Any,
                 logger:Any=None):
        self.logger = logger
        self.process = process

    ## Main
    # Log Pipe
    def logPipe(self,r,m,l=None,e=None,f=False):
        if self.logger: self.logger.logPipe(r,m,loggingLevel=l,extendedContext=e,forcePrintToScreen=f)

class web:

    """
    *-- Raw HTTP/HTTPS Operations --*

    Concept:

        - Handles any basic operations that do not need a full emulated browser (browser)
        - Performs http/http GET/POST requests
        - Directory brute forcing/path traversal
        - Page scraping (links & other information)
        - API Requests
        - API pentesting (basic)
        - Webpage download
        - Spider
        - Clone
    """

    def __init__(self,
                 process:Any,
                 confHandle:Any,
                 logger:Any=None):
        self.logger = logger
        self.process = process
        self.confHandle = confHandle
        self.config = {
            'timeout':3000
        }

    ## Requests
    # Get
    # Post
    def post(self,uri:str,headers:Dict,payload:Dict=None,timeout:int=None):
        """
        Post Requests.

        Args:
            uri (str):
            headers (dict):
            payload (dict, optional):
            timeout (int, optional):

        Returns: tuple
                 (bool,dict|resp)
                 (False,dict) on error.
                 (True, resp) on success.
        """
        timeout = timeout if timeout else self.config.get('timeout')
        payload = payload if payload else {}
        self.logPipe("post",f"Attempting POST request to '{str(uri)}'.",e={
            'headers':str(headers),
            'payload':str(payload),
            'timeout':str(timeout)
        })
        retVal = (False,None)
        try:
            resp = requests.post(str(uri),headers=headers,json=payload)
            resp.raise_for_status()
            retVal = (True,resp)
        except requests.exceptions.ConnectionError as E:
            self.logPipe("post",f"Connection error during operation: {str(E)}",l=2)
            retVal = (False,{'exception':str(E)})
        except requests.exceptions.Timeout:
            self.logPipe("post","Connection timed out.",l=2)
            retVal = (False,{'exception':"Timeout."})
        except requests.exceptions.RequestException as E:
            self.logPipe("post",f"Request exception during operation: {str(E)}",l=2)
            retVal = (False,{'exception':str(E)})
        except Exception as E:
            self.logPipe("post",f"Unknown exception during operation: {str(E)}",l=2)
            retVal = (False,{'exceptino':str(E)})
        self.logPipe("post",f"POST operation finished.",e={
            'return':str(retVal)
        })
        return retVal
    ## Main
    # Log Pipe
    def logPipe(self,r,m,l=None,e=None,f=False):
        if self.logger: self.logger.logPipe(r,m,loggingLevel=l,extendedContext=e,forcePrintToScreen=f)

class sock:

    """
    *-- Socket Operations --*

    Needed Alien Objects:
        proccessHandle

    Optional Alien Objects:
        configHandle
        utils.compress
        utils.cypher
        logger
    """

    def __init__(self,
                process:Any, # Mandatory for threading connections
                confHandle:Any=None,
                compress:Any=None,
                cypher:Any=None,
                logger:Any=None):
        self.process = process # For threading
        self.confHandle = confHandle # configuration
        self.compress = compress # compression (zip/huffman)
        self.cypher = cypher # crypto, encoding, ect...
        self.logger = logger # logger
        self.config = {
            "typeOperators":{
                "tcp":[0,"tcp"],
                'tv4':[ 1, 'tcp4' ],
                'tv6':[ 2, 'tcp6',],
                'udp':[ 3, 'udp' ],
                'uv4':[ 4, 'udp4'],
                'uv6':[ 5, 'udp6'],
                'ipc':[ 6, 'ipc' ],
                'raw':[ 7, 'raw' ]
            },
            "connTypes":{
                "server":[0,"s","server"],
                "client":[1,"c","client"],
                "cross" :[2,"x","cross"]
            },
            "defaults":{
                "type":"tcp",
                "handle":"c"
            },
            "server":{
                "host":"127.0.0.1",
                "port":9999,
                "allowedHosts":[], # Hosts to allow (if empty than any)
                "clientMax":1, # Max clients
                "lifeSpan":0, # Lifespan (datetime.datetime) if 0 than infite
                    "status":{
                    "running":False, # Running bool
                    "currentClients":0, # Amount of connected clients
                    "clientHistory":{}, # Client history
                    "timeStart":0 # Time started (set when started)
                }
            },
            "client":{
                "host":"127.0.0.1",
                "port":9999
            },
            "timeout":5,
            "transportEncoding":"utf-8"
        };self.config['cross']={'server':self.config['server'],'client':self.config['client']}
        # Que
        self.que = queue.Queue()
        # Library
        self.library = {} # Socket storage
        # We need to establish a connection handlers
        
    ## Connection handlers

    ### Server

    def _serverHost(self,
                    socketObject:socket.socket,
                    clientHandle:Callable=None,
                    host:str=None,
                    port:int=None,
                    clientMax:int=None,
                    allowedHosts:List[str]=None,
                    lifeSpan:int=None):
        """"""
        # Set our configurations
        clientHandle = clientHandle if clientHandle else self._serverClientHandle
        host = host if host else self.config['server']['host']
        port = port if port else self.config['server']['port']
        clientMax = clientMax if clientHandle else self.config['server']['clientMax']
        allowedHosts = allowedHosts if allowedHosts else self.config['server']['allowedHosts']
        lifeSpan = lifeSpan if lifeSpan else self.config['server']['lifeSpan']
        # Validate
        if not (isinstance(socketObject,socket.socket) and isinstance(clientHandle,callable)
                and isinstance(host,str) and isinstance(port,int) and isinstance(clientMax,int)
                and isinstance(allowedHosts,list) and isinstance(lifeSpan,int)):
            eM = "Argument(s) '...' carried an invalid type somewhere... Please validate."
            self.logPipe("_serverHost",eM,l=2)
            raise TypeError(eM)
        

    # def _serverThreadedHost
    def _serverClientHandle(self):
        """"""
        pass 

    ## Library
    # def _libraryIndex(self,libID:str,target:str=None):
    # def _libraryRemove
    def _libraryExist(self,libID:str):
        """"""
        return True if str(libID) in self.libary.keys() else False

    def _libraryCreate(self,
                       libID:str,
                       sockType:str|int,
                       connType:str|int,
                       host:str=None,
                       port:int=None,
                       threaded:bool=False):
        """"""
        if not isinstance(threaded,bool): threaded = False
        if self._libraryExist(libID):
            eM = f"'libID'({str(libID)}) is existant"
            raise
        sockHandle = self._socketGetType(sockType)
        connType = self._socketGetConnectionType(connType)
        if connType[0] in [0,1]:
            host = host if host else connType[1]['host']
            port = port if port else connType[1]['port']
        else:
            # Cross functionality (tbd)
            self.logPipe("_libraryCreate","Cross functionality is under construction!",f=True)
            return
        libObject = {
            "sockType":sockType,
            "sockObject":sockHandle,
            "connType":connType[0],
            "host":host if host else "...",
            "port":port if port else 0,
            "threaded":threaded
        };self.library[str(libID)]=libObject
        self.logPipe("_libraryCreate",f"Created libID '{str(libID)}' inside of the library.",e={
            "libObject":str(libObject)
        });return libObject
        

    ## Sockets
    def _isBound(self,socketObject:socket.socket):
        """"""
        try:
            lA = socketObject.getsockname()
            return True
        except Exception as E:
            return False

    def _connect(self,socketObject:socket.socket,host:str,port:int,data:bytes|str,timeout:int=None):
        """
        Connects To A Server And Sends Data.
        """
        if not isinstance(socketObject,socket.socket):
            raise
        timeout = timeout if timeout else self.config['timeout']
        try:
            socketObject.connect((host,port))
            self.logPipe("_connect",f"Successfully connected to '{host}:{port}'.")
            if isinstance(data,str): data = str(data).encode(self.config['transportEncoding'])
            socketObject.settimeout(self.config['timeout'])
            socketObject.sendall(data)
            socketObject = self._close(socketObject)
            return socketObject
        except TimeoutError:
            self.logPipe("_connect",f"'{host}:{port}' timed out ({str(self.config['timeout'])}).")
            return socketObject
        except Exception as E:
            eM = f"Unknown exception while attempting to connect to '{host}:{port}': {str(E)}."
            self.logPipe("_connect",eM,l=2)
            raise Exception(eM)

    def _close(self,socketObject:socket.socket):
        """
        Custom Close For Bother The Server & Client Sockets.
        """
        if not isinstance(socketObject,socket.socket):
            eM = f"Argument 'socketObject'({str(socketObject)}) was not 'socket.socket' type, got: {str(type(socketObject).__name__)}."
            self.logPipe("_close",eM,l=2)
            raise ValueError(eM)
        try:
            socketObject.close()
        except Exception as E:
            eM = f"Failed to close socketObjet: <{str(socketObject)}> due to: {str(E)}."
            self.logPipe("_close",eM,l=2)
            raise Exception(eM)

    def _connectEX(self,socketObject:socket.socket|str|int,host:str,port:int,timeout:int=None):
        """"""
        timeout = timeout if timeout else self.config['timeout']
        # Validate types
        if not isinstance(socketObject,socket.socket):
            eM = f"Argument 'socketObject' was not 'socket.socket' type, got: {str(type(socketObject).__name__)}."
            self.logPipe("_connectEX",eM,l=2)
            raise TypeError(eM)
        if not (isinstance(host,str) and isinstance(port,int)):
            eM = f"Argument(s) 'host'({str(host)}) and/or 'port'({str(port)}) was not 'str','int' got: '{str(type(host).__name__)}','{str(type(port).__name__)}'."
            self.logPipe("_connectEX",eM,l=2)
            raise TypeError(eM)
        if not isinstance(timeout,int):
            eM = f"Argument 'timeout'({str(timeout)}) was not 'int' type, got: {str(type(timeout).__name__)}."
            self.logPipe("_connectEX",eM,l=2)
            raise TypeError(eM)
        # Connect
        try:
            socketObject.settimeout(timeout)
            result = socketObject.connect_ex((host,port))
            # Return True if connected (0) else False (on failure)
            return result == 0
        except Exception as E:
            eM = f"Unknown exception during operation: {str(E)}"
            self.logPipe("_connectEX",eM,l=2)
            raise Exception(eM)
        

    def _resolveSockType(self,sockType:str|int):
        """"""
        typeOperators = self.config.get('typeOperators')
        operator = None
        for k,v in typeOperators.items():
            if sockType in v: 
                operator = k
                break
        return operator
    
    def _bindSocket(self,socketObject:Any|str,host:str,port:int):
        """"""
        # Validate types
        if not isinstance(socketObject,socket.socket):
            eM = f"Argument 'socketObject'({str(socketObject)}) was not 'socket.socket' type, got: {str(type(socketObject).__name__)}."
            self.logPipe("_bindSocket",eM,l=2)
            raise TypeError(eM)
        if not (isinstance(host,str) and isinstance(port,int)):
            eM = f"Argument(s) 'host'({str(host)}) and/or 'port'({str(port)}) was not 'str','int' type(s), got: '{str(type(host).__name__)}','{str(type(port).__name__)}'."
            self.logPipe("_bindSocket",eM,l=2)
            raise TypeError(eM)
        try:
            socketBound = socketObject.bind((host,port))
            self.logPipe("_bindSocket",f"Successfully bound socket(({str(host),{str(port)}}).")
            return socketBound
        except Exception as E:
            eM = f"Unknown exception while attempting to bind socket(({str(host),{str(port)}})): {str(E)}"
            self.logPipe("_bindSocket",eM,l=2)
            raise Exception(eM)
        
    
    def _socketGetConnectionType(self,connType:str|int=None):
        """"""
        connTypes = self.config.get('connTypes')
        if connType in connTypes['server']: return [0,self.config['server']]
        elif connType in connTypes['client']: return [1,self.config['client']]
        elif connType in connTypes['cross']: return [2,self.config['cross']]
        else: 
            eM = f"Argument 'connType'({str(connType)}) was invalid..."
            self.logPipe("_socketGetConnectionType",eM,l=2)
            raise ValueError(eM)

    def _socketGetType(self,sockType:str|int=None):
        """"""
        sockType = sockType if sockType else self.config.get('defaults')['type']
        sockType = self._resolveSockType(sockType)
        if   sockType == "tv4": socketObject = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        elif sockType == "tv6": socketObject = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        elif sockType == "uv4": socketObject = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        elif sockType == "uv6": socketObject = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        elif sockType == "tcp": socketObject = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        elif sockType == "udp": socketObject = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        elif sockType == "ipc": socketObject = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        elif sockType == "raw": socketObject = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        else:
            eM = f"'sockType'({str(sockType)}) was invalid."
            self.logPipe("_socketGetType",eM,l=2)
            raise ValueError(eM)
        return socketObject
    
    ## Main
    # serve(self)
    # send(self)
    # Log Pipe
    def logPipe(self,r,m,l=None,e=None,f=False):
        if self.logger: self.logger.logPipe(r,m,loggingLevel=l,extendedContext=e,forcePrintToScreen=f)
