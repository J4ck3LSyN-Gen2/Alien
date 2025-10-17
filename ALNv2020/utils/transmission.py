import socket # sock, proxy
import http # browser, web, proxy
from http.server import BaseHTTPRequestHandler, HTTPServer, SimpleHTTPRequestHandler # web
import socketserver # web
from urllib.parse import urlparse, parse_qs # web
from functools import partial # web
import json # *
import re # planned: web, sock, & browser
import os # *
import requests # type: ignore # web, browser
import struct # sock
import select # Planned: browser 
import queue # process threading que
from typing import Any, Dict, Optional, Callable, List 
import psutil # type: ignore # processes
import pycurl # type: ignore # curl
from io import BytesIO, StringIO # curl
import certifi # curl, browser
import time # * 
import random # web, sock, ssh, browser 
import base64 # web, sock, browser
import importlib # ssh
import sys # ssh
import paramiko # ssh
import threading # For extended threading outsidef of processHandle

__vession__ = "0.0.3"

class ssh:

    def __init__(self,
                 proc:Callable,
                 idrsaPath:str=None,
                 idrsaPass:str=None,
                 logger:Callable=None,
                 confHandle:Callable=None):
        
        self.process = proc
        self.logger = logger
        self.sock = sock(proc,
                         logger=logger,
                         confHandle=confHandle)
        self.idrsa  = {
            "server":{
                "priv":"~/.ssh/id_rsaServer",
                "pub":"~/.ssh/id_rsaServer.pub"
            
            },
            "client":{
                "priv":"~/.ssh/id_rsaClient",
                "pub":"~/.ssh/id_rsaClient.pub"
            }
        }
        self.config = {
            "clientMax":5,
            "timeout":1.0,
            "lPort":22,
            "rPort":22,
            "lHost":"0.0.0.0",
            "rHost":"0.0.0.0",
            "server":{
                "lifeSpan":300,
                # Global hosts to allow (if len(0) then any)
                "allowedHosts":[],
                # Whitelisted hosts for exec locally.
                "execHostWhitelist":[],
                # Hosts allowed to execute commands locally.
                # Usage: '<host>':[<command(s)>,...]
                "execHostPreload":{},
                # Only allow connections with this username.
                "authUsername":"AlienSSH"
            }
        }

    
    def _validateParamiko(self):
        """"""
        return False if not self.ssh else True 

    def generateKeys(self,privateKeyPath:str=None,bits:int=4096,passwd:Optional[str]=None):
        """"""
        pass

    class server(paramiko.ServerInterface):

        """
        SSH Server.
        """

        def __init__(self,sshInstance:Callable):

            self.ssh = sshInstance
            self.event = threading.Event()
            self.clientAddress = None

        def check_auth_publickey(self, username, key):
            """
            Username validation (for simple extra security).

            Concept:
                - We only accept any key if the `username` is `self.ssh.config['server']['authUsername']`.
            """
            if username == self.ssh.config['server']['authUsername']:
                return paramiko.AUTH_SUCCESSFUL
            return paramiko.AUTH_FAILED
        
        def get_allowed_auths(self, username):
            """
            Specifies the only allowed authentication method.
            Hardcoding 'publickey' is safer than relying on the superclass implementation.
            """
            return 'publickey'
        
        def check_channel_request(self, kind, chanid):
            """
            Specifies allowed authentication methods.
            Hardcoding 'session' is safer than relying on the superclass implementation. 
            """
            if kind == 'session':
                return paramiko.OPEN_SUCCEEDED
            return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        
        def check_channel_exec_request(self, channel, command):
            """
            Handles command execution requests with whitelisting.
            """
            commandStr = command.decode('utf-8').strip()
            hostIP = self.clientAddress[0] if self.clientAddress else "<anonymous>"
            output = []
            commandsToRun = []
            # Check whitelist
            if (len(self.ssh.config['server']['execHostWhitelist']) > 0 and hostIP in self.ssh.config['server']['execHostWhitelist']):
                commandsToRun.append(commandStr)
                self.ssh.logPipe("check_channel_exec_request",f"Whitelisted Host '{str(hostIP)}' appended command '{str(commandStr)}' for execution.")
                output.append(f"[Whitelisted Host ({str(hostIP)}) Command: '{str(commandStr)}']")
            # Check preload
            if (len(self.ssh.config['server']['execHostPreload']) > 0 and hostIP in self.ssh.config['server']['execHostPreload']):
                commandsToRun.extend(self.ssh.config['server']['execHostPreload'][hostIP])
                self.ssh.logPipe("check_channel_exec_request",f"Preloaded Host '{str(hostIP)}' appended commands '{str(commandsToRun)}' for execution.")
                output.append("[Preloaded Host ({str(hostIP)}) Commands: '{str(commandsToRun)}']")
            # Block Unauthorized arbitrary commands
            if (len(self.ssh.config['server']['execHostWhitelist']) > 0 and hostIP not in self.ssh.config['server']['execHostWhitelist']) and str(commandStr) not in commandsToRun:
                output = f"Error: Host '{str(hostIP)}' is NOT whitelisted for command execution. Ignoring arbitrary command: '{str(commandStr)}'."
                self.ssh.logPipe("check_channel_exec_request",f"Security-Risk: {str(output)}",l=2)
                channel.sendall(output.encode('utf-8'))
                channel.send_exit_status(1)
                return True
            
            # If no commands are given
            if len(commandsToRun) == 0:
                output = f"({time.time():.2f}) No commands to run for host '{str(hostIP)}'."
                self.ssh.logPipe("check_channel_exec_request",f"Whitelisted host '{str(hostIP)}' gave no commands for execution...")
            # Process commands
            for command in commandsToRun:
                execOut = self.ssh.process.shell(command)
                dataStr = str(json.dumps({"stdout":execOut[0],"stderr":execOut[1]},indent=2))
                output.append(dataStr)
            # Compile output string
            output = "\n".join(output) if len(output) > 1 else output[0]
            # Send, exit & return
            channel.sendall(output.encode('utf-8'))
            channel.send_exit_status(0)
            return True

    ## Main
    def serve(self,
              host:str=None,
              port:int=None,
              timeout:int=None,
              clientMax:int=None,
              keyPath:str=None,
              whitelist:List[str]=None,
              preload:Dict[str,List[str]]=None,
              lifeSpan:int=None):
        """"""
        # Set needed variables
        host = host if host else self.config['lHost']
        port = port if port else self.config['lPort']
        timeout = timeout if timeout else self.config['timeout']
        clientMax = clientMax if clientMax else self.config['clientMax']
        keyPath = keyPath if keyPath else self.idrsa['server']['priv']
        if whitelist: self.config['server']['execHostWhitelist'].extend(whitelist)
        if preload: self.config['server']['execHostPreload'].update(preload)
        lifeSpan = lifeSpan if lifeSpan else self.config['server']['lifeSpan']
        try:
            # Create socket
            serveSock = self.sock._socketGetType('tcp')
            serveSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            serveSock.bind((host,port))
            serveSock.listen(clientMax)
            # Set rsa key
            hostKey = paramiko.RSAKey(filename=keyPath)
            startTime = time.time()
            self.alive = True
            self.logPipe("serve",f"Server started on ({str(host)},{str(port)}):'{str(hostKey)}' @ {str(startTime)}...")
            while self.alive == True and time.time() - startTime < lifeSpan:
                try:
                    # Handle clients
                    clientHandle,clientAddress = serveSock.accept()
                    self.logPipe("serve",f"Accepted connection from ({str(clientAddress)}) @ {str(time.time())}.")
                    # Setup transport and handling
                    transport = paramiko.Transport(clientHandle)
                    transport.add_server_key(hostKey)
                    server = self.server(self)
                    server.clientAddress = clientAddress
                    transport.start_server(server=server)
                    channel = transport.accept(timeout=timeout)
                    # Close
                    if channel is not None: channel.close()
                    transport.close()
                except socket.timeout:
                    eM = f"Client timedout({str(timeout)})."
                    self.logPipe("serve",eM,l=2)
                    continue
                except Exception as E:
                    self.logPipe("serve",f"Unknown exception during operation: {str(E)}.",l=2)
                    continue
            eM = f"({time.time():.2f}):({str(host):{str(port)}}) Fatal error while attempting to start server: {str(E)}."
            self.logPipe("_serve",eM,l=2)
        finally:
            try: serveSock.close()
            except NameError: pass

    def client(self,
               hostname:str,
               command:str|List[str],
               host:str=None,
               port:int=None,
               timeout:int=None,
               keyPath:str=None,
               username:str=None):
        """"""
        host = host if host else self.config['rHost']
        port = port if port else self.config['rPort']
        timeout = timeout if timeout else self.config['timeout']
        keyPath = keyPath if keyPath else self.idrsa['client']['priv']
        username = username if username else self.config['server']['authUsername']
        sshClient = paramiko.SSHClient()
        sshClient.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        failed = [False]
        if not isinstance(command,list): command = [str(command)]
        try:
            privKey = paramiko.RSAKey.from_private_key_file(keyPath)
            sshClient.connect(hostname=hostname,port=port,username=username,pkey=privKey,timeout=timeout)
            commandOutput = {k:{'stdout':'','stderr':''} for k in command}
            stdin, stdout, stderr = sshClient.exec_command(command)
            timeStart = time.time()
            for cmd in command:
                out,err = stdout.read().decode('utf-8').strip(),stderr.read().decode('utf-8').strip()
                if err:
                    self.logPipe("client",f"({str(host)},{str(port)}): Command({str(command)}) failed:{str(err)}.",l=2)
                commandOutput[cmd]['stdout'] = out
                commandOutput[cmd]['stderr'] = err
            timeEnd = time.time()
            failed.append({
                "time":{
                    'start':timeStart,
                    'end':timeEnd,
                    'difference':timeEnd-timeStart
                },
                "command":command,
                "output":commandOutput
            })
            self.logPipe("client",f"({str(host)},{str(port)}): Command({str(command)} Completed.",e=failed[1])
        except paramiko.AuthenticationException:
            eM = f"Authentication failure on host ({str(host)},{str(port)}). Check username & key file path."
            self.logPipe("client",eM,l=2)
            failed = [True,eM]
        except Exception as E:
            eM = f"Unknown exception while attempting to connect to ({str(host)},{str(port)}): {str(E)}."
            self.logPipe("client",eM,l=2)
            failed = [True,eM]
        finally:
            sshClient.close()
            self.logPipe("client",f"Closed connection on ({str(host)},{str(port)}).")

        if failed[0]:
            raise Exception(failed[1])
        else: return failed[1]

    # Log pipe 
    def logPipe(self,r,m,l=None,e=None,f=False):
        if self.logger: self.logger.logPipe(r,m,loggingLevel=l,extendedContext=e,forcePrintToScreen=f)


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
    *-- Proxy Operations --*

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

    API:
        Usage:

        ```python
        import ALNv2020 as alien
        proc = alien.processHandle()
        web  = alien.utils.transmission.web(proc)
        api  = web.api(web)
        # From here you can serve via
        api.serve()
        ```

        Configuring the paths:

        * Paths are stored inside of `web.apiPaths` which is default from 
          `web._returnDefaultApiPaths()`.

        web.apiPaths = {
            "get":{
                "/x/status":self._defaultStatus
            },
            "post":{
                "/x/return":self._defaultReturn
            }
        }

        ^ You can add your own handlers here, corrisponding with the correct
          path and type. If `get` then it will simply return the data, if `post`
          then it will expect data.

          - 'get':f()
          - 'post':f(data)

        * The expected return value for these functions should be a tuple:

          ( <statusCode>, <data> )
    """

    def __init__(self,
                 process:Any,
                 confHandle:Any=None,
                 logger:Any=None):
        self.logger = logger
        self.process = process
        self.confHandle = confHandle
        self.config = {
            'timeout':15,
            "api":{
                "host":"127.0.0.1",
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
            "userAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
            "headers":{}
        }
        self.apiPaths = self._returnDefaultApiPaths()
        self.httpPaths = self._returnDefaultHTTPPaths()
    # --- API ---
    ## Default path executables
    def _defaultStatus(self):
        """"""
        return (200,{"status":"operational","message":"Internal API is running."})
    
    def _defaultReturn(self,data):
        """"""
        return (200,{"data":data})
    
    
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
        
    def _returnDefaultHTTPPaths(self):
        """
        Initializes The Paths USed For `httpServe`
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
    
    class api:

        """
        *-- API Hosting --*
        """

        def __init__(self,webInstance:Callable):

            self.web = webInstance
            self.alive = False

        class internalAPIHandler(BaseHTTPRequestHandler):

            # By adding __init__, we can pass in custom objects like a logger
            # or a configuration dictionary when the handler is created.
            def __init__(self, *args, webInstance=None, **kwargs):
                """
                Custom initializer to accept extra arguments.
                It's critical to call the parent's __init__ with *args and **kwargs.
                """
                if webInstance == None: raise Exception(f"Critical error: 'web' instance was not passed to the handler. ({str(args)},{str(kwargs)}).")
                self.web = webInstance
                self.paths = self.web.apiPaths
                # The parent's __init__ must be called to set up the request handling
                super().__init__(*args, **kwargs)

            def _sendJsonResponse(self,statusCode,data):
                """"""
                self.send_response(statusCode)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(data).encode('utf-8'))

            def _validate(self):
                """"""
                clientAddress = self.client_address[0]
                if len(self.web.config['api']['allowedHosts']) > 0:
                    if clientAddress not in self.web.config['api']['allowedHosts']:
                        return False
                if len(self.web.config['api']['validAPIKeys']) > 0:
                    if self.headers.get('X-API-Key') not in self.web.config['api']['validAPIKeys']:
                        return False
                return True
            
            def do_GET(self):
                """"""
                if not self._validate():
                    return
                parsedUrl = urlparse(self.path)
                path = parsedUrl.path
                for p,f in self.paths['get'].items():
                    if path == p:
                        if isinstance(f,Callable):
                            resp = f()
                            if isinstance(resp,tuple):
                                self._sendJsonResponse(resp[0],resp[1])
                                return
                            
            def do_POST(self):
                """"""
                if not self._validate():
                    return
                parsedUrl = urlparse(self.path)
                path = parsedUrl.path
                contentLength = int(self.headers.get('Content-Length',0))
                body = self.rfile.read(contentLength)
                for p,f in self.paths['post'].items():
                    if path == p:
                        if isinstance(f,Callable):
                            resp = f(body)
                        if isinstance(resp,tuple):
                            self._sendJsonResponse(resp[0],resp[1])
                            return

        class threadingAPIServer(socketserver.ThreadingMixIn,HTTPServer):
            deamon_threads = True
            allow_reuse_address = True

        def serve(self):
            """"""
            serverAddress = (self.web.config['api']['host'],self.web.config['api']['port'])
            customHandler = partial(self.internalAPIHandler,webInstance=self.web)
            self.alive = True
            startTime = time.time()
            while self.alive == True and time.time() - startTime < self.web.config['api']['lifeSpan']:
                with self.threadingAPIServer(serverAddress,customHandler) as httpd:
                    try:
                        httpd.serve_forever()
                    except KeyboardInterrupt:
                        self.alive=False
                        break


    # --- HTTP Hosting --- 

    class httpServe:

        def __init__(self,webInstance:Callable):
            """"""
            self.web = webInstance
            self.alive = False


        class internalHTTPRequestHandler(SimpleHTTPRequestHandler):

            def __init__(self, *args, webInstance=None, **kwargs):

                self.web = webInstance
                super().__init__(*args, **kwargs)

            def _sendHtmlResponse(self,statusCode:int,htmlContentBytes:str|bytes):
                """"""
                if not isinstance(htmlContentBytes,bytes):
                    htmlContentBytes = str(htmlContentBytes).encode('utf-8')
                self.send_response(statusCode)
                self.send_header('Content-type',"text/html")
                self.send_header('Content-Length',str(len(htmlContentBytes)))
                self.end_headers()
                self.wfile.write(htmlContentBytes)

            def _validate(self):
                """"""
                return True
            
            def do_GET(self):
                """"""
                if not self._validate():
                    return
                # Get the local filesystem path for the request
                translatedPath = self.translate_path(self.path)
                # Get the base filename (e.g., 'index.html') from the path
                requestedFile = os.path.basename(translatedPath)
                rootPath = self.web.config['httpServe']['html']['root']
                fullPath = os.path.join(rootPath, translatedPath)
                if not os.path.exists(fullPath): # Check if a physical file exists
                    # If not, check if it's a special in-memory path like 'index.html'
                    if requestedFile in self.web.httpPaths:
                        self._sendHtmlResponse(200, self.web.httpPaths[requestedFile])
                        return
                    else:
                        self._sendHtmlResponse(404,self.web.httpPaths['404.html'])
                        return
                super().do_GET() # If the physical file exists, let the parent handler serve it.
            
            
            def do_POST(self):
                """"""
                if not self._validate():
                    return

        class threadingHTTPServer(socketserver.ThreadingMixIn,HTTPServer):

            daemon_threads = True
            allow_reuse_address = True

        def serve(self):
            """"""
            self.alive = True
            startTime = time.time()
            while (self.alive and time.time() - startTime < self.web.config['httpServe']['lifeSpan']):
                serverAddress = (self.web.config['httpServe']['host'],self.web.config['httpServe']['port'])
                customHandler = partial(self.internalHTTPRequestHandler,webInstance=self.web)
                with self.threadingHTTPServer(serverAddress,customHandler) as httpd:
                    try:
                        httpd.serve_forever()
                    except Exception as E: self.web.logPipe("serve",f"Unknown exception during operation (Address: {str(serverAddress)}): {str(E)}.",l=2)
                    except KeyboardInterrupt: self.web.logPipe("serve",f"Keyboard Interrupt during operation (Address: {str(serverAddress)}): (Lifespan: {str(self.web.config['httpServe']['lifeSpan'])})/{str(time.time() - startTime)}.",l=2)
                    finally:
                        httpd.shutdown()
                        httpd.server_close()
                        self.alive = False
                    break
    
    ## Requests
    def _postData(self,
                  uri:str,
                  data:Dict[str,Any],
                  userAgent:str=None,
                  timeout:int=None,
                  headers:Dict[str,Any]=None,
                  appendInternalHeaders:bool=False):
        """"""
        userAgent = userAgent if userAgent else self.config['userAgent']
        timeout = timeout if timeout else self.config['timeout']
        headers = headers if headers else self.config['headers']
        if appendInternalHeaders:
            if len(self.config['headers']) > 0: headers.update(self.config['headers'])
        if "User-Agent" not in headers: headers['User-Agent'] = self.config['userAgent']
        try:
            resp = requests.post(uri,data=data,headers=headers,timeout=timeout)
            return (resp.status_code,resp.text)
        except requests.exceptions.ConnectTimeout:
            eM = f"Connection to '{str(uri)}' timed out ({str(timeout)})."
            self.logPipe("_postData",eM,l=2)
            raise TimeoutError(eM)
        
    def _get(self,
             uri:str,
             userAgent:str=None,
             timeout:int=None,
             headers:Dict[str,Any]=None,
             parameters:Dict[str,Any]=None,
             appendInternalHeaders:bool=False):
        """"""
        pass 


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
        };self.config['cross']={'server':self.config['libraryServer'],'client':self.config['libraryClient']}
        # Que
        self.que = queue.Queue()
        # Library
        self.library = {} # Socket storage
        self.history = {} # Connection history
        # We need to establish a connection handlers
        self.defaultConnectionConfig = {
            "procType":"shell",
            "availableTypes":[
                "return","shell"
            ]
        }
        

    ## History 
    def _historyAppend(self,host:str,port:int,data:Dict[str,Any]):
        """"""
        historyID = f"{str(host)}:{str(port)}"
        if str(historyID) not in self.history:
            self.history[historyID] = {
                "connections":0,
                "dataHistory":[]
            }
        self.history[str(historyID)]["connections"]+=1
        self.history[str(historyID)]["dataHistory"].append(data)

    ## Connection handles
    def _handleConnectionDefault(self,clientHandle:socket.socket,clientAddress:tuple):
        """"""
        try:
            data = clientHandle.recv(1024)
            if data:
                if self.defaultConnectionConfig['procType'] == "return": return data.decode(self.config['transportEncoding'])
                elif self.defaultConnectionConfig['procType'] == "shell":
                    shellCommand = data.decode(self.config['transportEncoding'])
                    shellOut = self.process.shell(shellCommand)
                    returnData = {
                        "stdout":shellOut[0],
                        "stderr":shellOut[1]
                    }
                    clientHandle.sendall(str(returnData).encode(self.config['transportEncoding']))
                    clientHandle.close()
                    return returnData
            else:
                clientHandle.close()
                return None
        except Exception as E:
            eM = f"Unknown exception while handling client '{str(clientAddress)}': {str(E)}."
            self.logPipe("_handleConnectionDefault",eM,l=2)
            raise Exception(eM)

    ## Library

    def _libStart(self,
                  libID:str,
                  data:str|bytes=None,
                  host:str=None,
                  port:int=None,
                  threaded:bool=False,
                  clientHandle:Callable=None,
                  connectHandle:Callable=None,
                  pID:int=None):
        """
        Starts A Processes Depending On The Preset Connection Type.

        """
        if not self._libExist(libID):
            eM = f"Argument 'libID'({str(libID)}) is non-existant."
            self.logPipe("_libStart",eM,l=2)
            raise ValueError(eM)
        if self._libIsAlive(libID):
            eM = f"Argument 'libID'({str(libID)}) is already alive."
            self.logPipe("_libStart",eM,l=2)
            raise ValueError(eM)
        libObject = self.library[str(libID)]
        

    def _libRemove(self,libID:str):
        """
        Removes `libID` From `self.library`.
        """
        if not self._libExist(libID):
            eM = f"Argument 'libID'({str(libID)}) is non-existant."
            self.logPipe("_libRemove",eM,l=2)
            raise ValueError(eM)
        if self._libIsAlive(libID):
            eM = f"Argument 'libID'({str(libID)}) is still alive."
            self.logPipe("_libRemove",eM,l=2)
            raise ValueError(eM)
        try:
            del(self.library[str(libID)])
        except Exception as E:
            eM = f"Unknown exception while attempting to remove '{str(libID)}': {str(E)}."
            self.logPipe("_libRemove",eM,l=2)
            raise Exception(eM)

    def _libExist(self,libID:str):
        """
        Validates If `libID` Is Existant Inside Of `self.library`.
        """
        return True if str(libID) in [i for i in self.library.keys()] else False
    
    def _libIsAlive(self,libID:str):
        """"""
        if not self._libExist(libID):
            eM = f"Argument 'libID'({str(libID)}) is non-existant."
            self.logPipe("_libIsAlive",eM,l=2)
            raise ValueError(eM)
        return self.library[str(libID)]['alive']
    
    def _libBuild(self,
                  libID:str,
                  sockType:str|int,
                  connType:str|int,
                  host:str=None,
                  port:int=None,
                  timeout:int=None):
        """
        Builds & Appends Sockets To `self.library` Under `libID`.

        Args:
            libID (str): Target library ID to append as.
            sockType (str|int): Socket type (according to self._socketGetType())
            connType (str|int): Connection type (according to self._socketGetConnectionType())
            host (str, optional): Host to use. Dependendant on connection type, however usually is `127.0.0.1`
            port (int, optional): Port to use. Dependendant on connection type, however usually is `9999`
            timeout (int, optional): Timeout. (Default: `self.config['timeout']`)

        Returns: dict
        """
        if self._libExist(libID):
            eM = f"Argument 'libID'({str(libID)}) is already existant."
            self.logPipe("_libBuild",eM,l=2)
            raise ValueError(eM)
        sockObject = self._socketGetType(sockType)
        connType = self._socketGetConnectionType(connType)
        timeout = timeout if timeout else self.config['timeout']
        if connType[0] == 0: sockConfig = self.config['server']
        elif connType[0] == 1: sockConfig = self.config['client']
        elif connType[0] == 2: 
            self.logPipe("_libBuild","Cross Connection Types Are Not Developed Yet... Returning...")
            return 
        libObject = {
            "type":sockType,
            "connType":connType,
            "host":host,
            "port":port,
            "timeout":timeout,
            "alive":False,
            "socket":sockObject
        }
        self.library[str(libID)]=libObject;self.logPipe("_libBuild",f"Appended '{str(libID)}' to the library.",e=libObject);return libObject

    ## Sockets
    def _serveThreadWrapper(self,
                            clientHandle:Callable,
                            clientSocket:socket.socket,
                            clientAddress:tuple):
        """"""
        try:
            res = clientHandle(clientSocket,clientAddress)
            self.que.put(res)
        except Exception as E:
            eM = f"Unknown exception during client handling: {str(E)}."
            self.que.put(eM)

    def _serve(self,
               socketObject:socket.socket,
               host:str=None,
               port:int=None,
               clientMax:int=None,
               allowedHosts:List[str]=None,
               lifeSpan:int=None,
               clientHandle:Callable=None):
        """"""
        host = host if host else self.config['libraryServer']['host']
        port = port if port else self.config['libraryServer']['port']
        clientMax = clientMax if clientMax else self.config['libraryServer']['clientMax']
        allowedHosts = allowedHosts if allowedHosts else self.config['libraryServer']['allowedHosts']
        lifeSpan = lifeSpan if lifeSpan else self.config['libraryServer']['lifespan']
        clientHandle = clientHandle if clientHandle else self.config['libraryServer']['handle']
        if clientHandle == 0: clientHandle = self._handleConnectionDefault 
        if not (isinstance(socketObject,socket.socket) and isinstance(host,str)
                and isinstance(port,int) and isinstance(clientMax,int)
                and isinstance(allowedHosts,list) and isinstance(lifeSpan,int)
                and isinstance(clientHandle,Callable)):
            eM = "An argument was invalid... Please validate..."
            self.logPipe("_serve",eM,l=2)
            raise ValueError(eM)
        # Set status, startTime & start listening
        alive = True
        startTime = time.time()
        if not self._isBound(socketObject):
            self._bindSocket(socketObject,host,port)
        socketObject.listen(clientMax)
        try:
            while alive:
                if lifeSpan != 0:
                    currentTime = time.time()
                    if currentTime - startTime > lifeSpan:
                        alive = False
                        print(True)
                        break
                connectionInfo = socketObject.accept()
                clientSocket = connectionInfo[0]
                clientAddress = connectionInfo[1]
                self.logPipe("_serve",f"Revieved connection from '{str(clientAddress)}'.")
                pID = str(random.randint(199999,199999999)) # Ensure random pID
                self.process.appendThread(
                    pID,
                    target=self._serveThreadWrapper,
                    args=(clientHandle,clientSocket,clientAddress),
                    description=f"Connected Client Thread Wrapper: {str(clientAddress)}."
                );self.process.startProcess(pID)
                returnData = self.que.get()
                self._historyAppend(clientAddress[0],clientAddress[1],returnData)
                self._close(clientSocket)
                self.logPipe("_serve",f"Closed connection to '{str(clientAddress)}'.")
        except Exception as E:
            eM = f"Unknown exception during operation: {str(E)}."
            self.logPipe("_serve",eM,l=2)
            raise Exception(eM)
        except KeyboardInterrupt:
            eM = f"Keyboard Interrupt during operation."
            self.logPipe("_serve",eM,l=2)
            raise Exception(eM)
        finally:
            socketObject.close()
        self.logPipe("_serve","Connection closed.")

    # def _connectRecv

    def _isBound(self,socketObject:socket.socket):
        """Validates If A Socket Is Binded."""
        try:
            lA = socketObject.getsockname()
            del(lA)
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
            socketObject.close()
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
