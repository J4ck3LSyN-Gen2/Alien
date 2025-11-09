import aiosqlite, requests, json, os # type: ignore
from typing import Optional, Dict, Union, List, Callable, Any
from pathlib import Path

__version__ = "0.0.1"

class dbHandle:

    def __init__(self,
                 dbPath:str, # Target directory path of the database 
                 schema:Optional[str]=None, # Schema (default: `schema.sql`) 
                 dbFile:Optional[str]=None, # Database (default: `database.db`)
                 logger:Optional[Callable]=None, 
                 confHandle:Optional[Callable]=None):
        """"""
        self.logger = logger
        self.confHandle = confHandle
        if Path(dbPath).exists(): self.dbPath = dbPath
        else:
            eM = f"Argument 'dbPath'('{str(dbPath)}') was non-existant."
            self.logPipe("__init__",eM,l=2)
            raise Exception(eM)
        
        self.database = None
        self.config = {
            "databaseDirectory":self.dbPath,
            "databasePath": dbFile if dbFile else os.path.join(self.dbPath,"database.db"),
            "databaseSchema": schema if schema else os.path.join(self.dbPath,"schema.sql")
        }

    def _buildDBPath(self):
        """"""
        return str(os.path.join(self.config['databaseDirectory'],self.config['databasePath']))
    
    def _buildSchemaPath(self):
        """"""
        return str(os.path.join(self.config['databaseDirectory'],self.config['databaseSchema']))

    def _connectDB(self):
        """"""
        dbPath = self._buildDBPath()
        schemaPath = self._buildSchemaPath()
        if not os.path.exists(dbPath):
            if not os.path.exists(schemaPath):
                eM = f""
                raise Exception(eM)
            
            # Schema
        else:
            # Check for schema and update?
            # Connect to database
            pass

    def logPipe(self, r: str, m: str, l: Any = None, e: Any = None, f: bool = False):
        """Logs a message if a logger instance is available."""
        if self.logger: self.logger.logPipe(r,m,loggingLevel=l,extendedContext=e,forcePrintToScreen=f)