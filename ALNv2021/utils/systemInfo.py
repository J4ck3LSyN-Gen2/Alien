import sys, os, platform, psutil, getpass # type: ignore 
from typing import Any, Dict, Tuple

class systemInfo:
    """
    *-- System Information --*

    Provides a comprehensive set of methods to retrieve system hardware,
    operating system, and environment details.
    """

    def __init__(self, logger: Any = None):
        """
        Initializes the systemInfo class.

        Args:
            logger (Any, optional): A logger instance for logging messages. Defaults to None.
        """
        self.logger = logger
        self.platform = self.getPlatform()
        self.pID = self.getPID()
        self.username = self.getUsername()
        self.logPipe("__init__", "systemInfo initialized.")

    ## Main
    def getPlatform(self) -> str:
        """Returns the system's platform identifier (e.g., 'win32', 'linux')."""
        return sys.platform

    def getPID(self) -> int:
        """Returns the current process ID."""
        return os.getpid()

    def getUsername(self) -> str:
        """Returns the current user's username."""
        try:
            return getpass.getuser()
        except Exception as e:
            self.logPipe("getUsername", f"Could not get username: {e}", l=2)
            return "unknown"

    ## Python Information
    def getPythonVersion(self) -> str:
        """Returns the Python version string."""
        return sys.version

    def getPythonExecutablePath(self) -> str:
        """Returns the absolute path of the Python executable."""
        return sys.executable

    ## CPU Information
    def getCpuInfo(self) -> Dict[str, Any]:
        """
        Retrieves detailed CPU information.

        Returns:
            Dict[str, Any]: A dictionary containing CPU details like
                            physical cores, total cores, usage, and frequency.
        """
        try:
            return {
                "physicalCores": psutil.cpu_count(logical=False),
                "totalCores": psutil.cpu_count(logical=True),
                "maxFrequencyMHZ": psutil.cpu_freq().max if psutil.cpu_freq() else 'N/A',
                "currentFrequencyMHZ": psutil.cpu_freq().current if psutil.cpu_freq() else 'N/A',
                "totalCPUUsagePercent": psutil.cpu_percent(interval=1),
            }
        except Exception as e:
            self.logPipe("getCpuInfo", f"Failed to get CPU info: {e}", l=2)
            return {}

    ## Memory Information
    def getMemoryInfo(self) -> Dict[str, Any]:
        """
        Retrieves system memory (RAM) information.

        Returns:
            Dict[str, Any]: A dictionary with memory details in bytes,
                            including total, available, and used memory.
        """
        try:
            svmem = psutil.virtual_memory()
            return {
                "totalBytes": svmem.total,
                "availableBytes": svmem.available,
                "usedBytes": svmem.used,
                "percentageUsed": svmem.percent,
            }
        except Exception as e:
            self.logPipe("getMemoryInfo", f"Failed to get memory info: {e}", l=2)
            return {}

    ## Disk Information
    def getDiskInfo(self) -> Dict[str, Any]:
        """
        Retrieves disk usage information for the root partition.

        Returns:
            Dict[str, Any]: A dictionary with disk usage details in bytes.
        """
    # Log Pipe
        try:
            partition = psutil.disk_usage('/')
            return {
                "totalBytes": partition.total,
                "usedBytes": partition.used,
                "freeBytes": partition.free,
                "percentageUsed": partition.percent,
            }
        except Exception as e:
            self.logPipe("getDiskInfo", f"Failed to get disk info: {e}", l=2)
            return {}

    ## Operating System Information
    def getOsInfo(self) -> Dict[str, str]:
        """
        Retrieves detailed operating system information.

        Returns:
            Dict[str, str]: A dictionary containing OS details.
        """
        return {
            "system": platform.system(),
            "node_name": platform.node(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
        }

    def getAllSystemInfo(self) -> Dict[str, Any]:
        """
        Compiles and returns a dictionary of all available system information.

        Returns:
            Dict[str, Any]: A comprehensive dictionary of system details.
        """
        self.logPipe("getAllSystemInfo", "Gathering all system information.")
        return {
            "os": self.getOsInfo(),
            "cpu": self.getCpuInfo(),
            "memory": self.getMemoryInfo(),
            "disk": self.getDiskInfo(),
            "python": {
                "version": self.getPythonVersion(),
                "executable": self.getPythonExecutablePath(),
            },
            "process": {
                "pid": self.pID,
                "user": self.getUsername(),
            }
        }

    def logPipe(self, r: str, m: str, l: Any = None, e: Any = None, f: bool = False):
        """Logs a message if a logger instance is available."""
        if self.logger: self.logger.logPipe(r,m,loggingLevel=l,extendedContext=e,forcePrintToScreen=f)