import logging
import os
from typing import Optional

class ColoredFormatter(logging.Formatter):
    """A logging formatter that adds color to the output."""
    black = "\x1b[30m"; red = "\x1b[31m"; green = "\x1b[32m"; yellow = "\x1b[33m"
    blue = "\x1b[34m"; gray = "\x1b[38m"; reset = "\x1b[0m"; bold = "\x1b[1m"
    COLORS = {logging.DEBUG: gray+bold,logging.INFO: blue+bold,logging.WARNING:yellow+bold,logging.ERROR:red,logging.CRITICAL:red+bold,}

    def __init__(self, fmt: str = "(black){asctime}(reset) (levelcolor){levelname:<8}(reset) (green){name}(reset) {message}", datefmt: str = "%Y-%m-%d %H:%M:%S", style: str = "{"):
        super().__init__()
        self.default_format = fmt
        self.datefmt = datefmt
        self.style = style

    def format(self, record):
        logColor = self.COLORS.get(record.levelno, self.reset)
        fmtStr = self.default_format.replace("(black)", self.black + self.bold)
        fmtStr = fmtStr.replace("(reset)",self.reset)
        fmtStr = fmtStr.replace("(levelcolor)",logColor)
        fmtStr = fmtStr.replace("(green)",self.green+self.bold)
        formatter = logging.Formatter(fmtStr,self.datefmt,self.style)
        return formatter.format(record)

class SimpleFormatter(logging.Formatter):
    """A simple logging formatter for file output."""
    def __init__(self,fmt:str="[{asctime}] [{levelname:<8}] {name}: {message}",datefmt:str="%Y-%m-%d %H:%M:%S",style:str="{"):
        super().__init__(fmt,datefmt,style)

class Logger:
    """A comprehensive logger class that simplifies logging setup and usage."""
    
    def __init__(self, 
                 loggerID: str, 
                 consoleLevel: int = logging.INFO, 
                 filePath: Optional[str] = None, 
                 fileLevel: int = logging.DEBUG,
                 consoleFormatter: logging.Formatter = ColoredFormatter(),
                 fileFormatter: logging.Formatter = SimpleFormatter()):
        """
        Initializes and configures a logger.

        Args:
            loggerID (str): The name for the logger.
            consoleLevel (int): The logging level for console output.
            filePath (Optional[str]): Path to the log file. If None, file logging is disabled.
            fileLevel (int): The logging level for file output.
            consoleFormatter (logging.Formatter): The formatter for console logs.
            fileFormatter (logging.Formatter): The formatter for file logs.
        """
        self.logger = logging.getLogger(loggerID)
        self.logger.setLevel(logging.DEBUG) # Set logger to lowest level to capture all messages
        # Prevent duplicate handlers if logger is initialized multiple times
        if self.logger.hasHandlers():self.logger.handlers.clear()
        # Console Handler
        consoleHandle = logging.StreamHandler()
        consoleHandle.setLevel(consoleLevel)
        consoleHandle.setFormatter(consoleFormatter)
        self.logger.addHandler(consoleHandle)
        # File Handler
        if filePath:
            try:
                # Ensure directory exists
                logDir = os.path.dirname(filePath)
                if logDir: os.makedirs(logDir, exist_ok=True)
                fileHandler = logging.FileHandler(filePath, mode='a', encoding='utf-8')
                fileHandler.setLevel(fileLevel)
                fileHandler.setFormatter(fileFormatter)
                self.logger.addHandler(fileHandler)
            except (OSError, PermissionError) as e:
                self.logger.error(f"Failed to create file handler for '{filePath}': {e}", exc_info=True)

        # Level mapping for the log method
        self.log_map = {
            0: self.logger.debug, 'd': self.logger.debug, 'debug': self.logger.debug,
            1: self.logger.info, 'i': self.logger.info, 'info': self.logger.info,
            2: self.logger.warning, 'w': self.logger.warning, 'warning': self.logger.warning,
            3: self.logger.error, 'r': self.logger.error, 'error': self.logger.error,
            4: self.logger.critical, 'c': self.logger.critical, 'critical': self.logger.critical,
        }
        self.prefix_map = {1: "[*] ", 3: "[!] ", 'output': "[^] "}

    def logPipe(self,message:str,level:any=1,exc_info:bool=False):
        """Logs a message with a specified level and optional prefix."""
        log_func = self.log_map.get(level, self.logger.info)
        prefix = self.prefix_map.get(level, "")
        log_func(f"{prefix}{message}", exc_info=exc_info)
    
