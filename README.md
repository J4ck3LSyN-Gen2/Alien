# Alien
![HEAD](https://github.com/J4ck3LSyN-Gen2/Alien/blob/main/src/imgs/alien.jpg)

# Alien Framework (ALNv2017)
## Script Coming Soon!
## Additional Installs:
`wsl`
`wsl kali-linux`
`git clone https://github.com/00xBAD/kali-wordlists.git`
`git clone https://github.com/ffuf/ffuf.git`

*Note: These additional tools enhance the capabilities of specific modules like WSL, DIRBUSTER, and PASSWDBRUTER.*

## Overview

The Alien Framework (ALNv2017) is a comprehensive Python-based toolkit designed to encapsulate a wide range of functionalities. It serves as a versatile platform for various operations, including network analysis, data manipulation, AI-assisted tasks, user interaction via TUI and CLI, web interaction, and more.

A core design principle of Alien is **lazy initialization**. Modules (e.g., NMAP, SQL) consume resources only upon their first access, promoting efficient performance and resource management.

## Core Features

Alien provides a rich set of built-in modules, each catering to specific tasks:

*   **Networking, Reconnaissance & Security:**
    *   `NMAP`: Interface for Nmap port scanning and network discovery.
    *   `SHODAN`: Integration with the Shodan search engine for device and service discovery.
    *   `DORKER`: Tools for crafting and executing Google dorks.
    *   `DIRBUSTER`: Directory and file brute-forcing for web servers.
    *   `WIKISEARCH`: Fetching and processing data from Wikipedia.
*   **Data Handling & Manipulation:**
    *   `SQL`: SQLite database management (creation, querying, etc.).
    *   `PASSWDBRUTER`: Tools for password brute-forcing (details inferred from logs, expand as needed).
    *   `MEMORY`: In-memory data block manipulation, including structured data and symbol management.
    *   `VARTOOLSET`: A suite of utilities for variable inspection, type conversion, and manipulation.
    *   `HUFFMANENCODING`: Huffman encoding and decoding for data compression.
*   **Interaction & Automation:**
    *   `ATLAS`: AI-powered assistance using local LLMs (via Ollama) for tasks like command generation, script creation, and contextual chat.
    *   `TUI (Text User Interface)`: An interactive terminal interface for accessing Alien's functionalities.
    *   `CLI (Command Line Interface)`: Allows execution of Alien methods directly from the command line.
    *   `PIPE`: A central communication and execution module for Alien's internal operations.
    *   `LOGIC`: Provides conditional execution capabilities (if-elif-else).
*   **System & Web Interaction:**
    *   `NETWORKPROXY`: Management of network proxies and tools for making HTTP/S requests.
    *   `BROWSER`: Basic browser-related operations (currently foundational).
    *   `TRANSMISSION`: Socket communication functionalities (TCP, UDP, IPC).
    *   `WSL`: Windows Subsystem for Linux interaction (Windows-specific, foundational).
    *   `DOCKER`: Docker container management (foundational).
*   **Core Utilities:**
    *   Configuration Management: Centralized `self.configure` dictionary with helper methods.
    *   Logging: Robust logging via `logPipe` to console, TUI, and files.
    *   Error Handling: Standardized error raising via `self.error`.
    *   Encoding/Decoding: Utilities for Base64, Hex, URL-safe tokens, and invisible ASCII steganography.
    *   Cryptography: Basic ciphers (Caesar, Vigenere, XOR) and secure token generation.

## Prerequisites

*   Python 3.x
*   The script attempts to import several external libraries. Ensure they are installed in your Python environment. You can typically install them using pip:
    ```bash
    pip install blessed googlesearch-python requests beautifulsoup4 shodan huffman wikipedia selenium
    ```
    *   **Note on `selenium`**: While imported, its direct usage in the provided core might be minimal. If you intend to expand browser automation, ensure you also have the appropriate WebDriver (e.g., ChromeDriver) installed and configured.
    *   **Note on `Ollama`**: For the `ATLAS` module to function, you need a running Ollama instance with models like Llama3 or Codellama pulled. Refer to Ollama's official documentation for installation.

## Getting Started

1.  **Save the Code**: Save the script as `ALNv2017.py`.
2.  **Run the Script**:
    *   **TUI Mode (Default)**: Execute the script without any command-line arguments.
        ```bash
        python ALNv2017.py
        ```
        This will launch the Text User Interface.
    *   **CLI Mode**: Provide specific Alien methods and arguments via the command line.
        ```bash
        python ALNv2017.py <METHOD_PATH> --args '[...]' --kwargs '{...}'
        ```
        (See CLI Usage section for details).

## Usage

Alien can be utilized in three primary ways: as a Python library in your own scripts, through its interactive Text User Interface (TUI), or via its Command Line Interface (CLI).

### 1. Python Scripting

You can import and use the `Alien` class in your Python projects to leverage its modules.

```python
# example_script.py
from ALNv2017 import Alien

# Initialize Alien. By default, this also initializes system info and logging.
# To prevent default initializations (e.g., if managing config externally):
# alien = Alien(noInit=1) # Then manually call alien.initSystemInfoPaths(), etc.
alien = Alien()

# --- Configure Logging (Optional Example) ---
# By default, verbose logging might be off and file logging might be on.
# Let's enable verbose console logging for this script example.
alien.setConfigureValue("logPipe-configure.verbose", 1)
alien.setConfigureValue("logPipe-configure.filePipe", 0) # Disable file logging for this example

alien.logPipe("MyScript", "Alien instance created and configured for verbose logging.")

# --- Example: Using the NMAP module ---
alien.logPipe("MyScript", "Attempting NMAP scan...")
# Ensure Nmap is installed and in your system's PATH
# The NMAP module might require sudo/admin privileges for some scan types.
# The scan method returns a dictionary with parsed results.
nmap_results = alien.NMAP.scan(targets="127.0.0.1", ports=[80, 443], arguments="-sV -T4")
if nmap_results and nmap_results.get("hosts"):
    alien.logPipe("MyScript", f"Nmap scan found hosts: {list(nmap_results['hosts'].keys())}")
else:
    alien.logPipe("MyScript", "Nmap scan did not return host information or failed.")

# --- Example: Using the SQL module ---
alien.logPipe("MyScript", "Working with SQL module...")
db_name = "example_app.sqlite"
if alien.SQL.createDatabase(db_name, overwrite_if_exists=True):
    alien.logPipe("MyScript", f"Database '{db_name}' created/ensured.")
    alien.SQL.executeQuery(db_name, "CREATE TABLE IF NOT EXISTS items (id INTEGER PRIMARY KEY, name TEXT, price REAL)")
    alien.SQL.executeQuery(db_name, "INSERT INTO items (name, price) VALUES (?, ?)", ("Laptop", 1200.50))
    alien.SQL.executeQuery(db_name, "INSERT INTO items (name, price) VALUES (?, ?)", ("Mouse", 25.99))
    
    items = alien.SQL.fetchData(db_name, "SELECT * FROM items WHERE price > ?", (100,))
    alien.logPipe("MyScript", f"Items with price > 100: {items}")
    
    alien.SQL.closeDatabaseConnection(db_name)
    # alien.SQL.removeDatabase(db_name) # Optionally remove the DB file
else:
    alien.logPipe("MyScript", f"Failed to create database '{db_name}'.")

# --- Example: Using the DORKER module ---
# DORKER module requires 'googlesearch-python', 'requests', 'bs4'
alien.logPipe("MyScript", "Initializing DORKER module...")
alien.DORKER.initImports() # Important for modules with external dependencies

dork_query = alien.DORKER.buildDork(
    keywords=["intitle:\"Dashboard\"", "intext:\"Login\""],
    operators={"site": "example.com"} # Replace with a domain for actual testing
)
alien.logPipe("MyScript", f"Constructed dork: {dork_query}")
# Be mindful of Google's rate limiting when using the query function.
# search_results = alien.DORKER.query(dork_query, searchConfig={"num": 5, "pause": 2.0})
# alien.logPipe("MyScript", f"Dork found {len(search_results)} results (first 5): {search_results[:5]}")

# --- Example: Using the MEMORY module ---
alien.logPipe("MyScript", "Working with MEMORY module...")
alien.MEMORY.initImports() # For struct, binascii
alien.MEMORY.initMemory()  # Initialize the memory block

offset_msg = alien.MEMORY.allocate("message_block", 64)
alien.MEMORY.writeString(offset_msg, "Hello from Alien Memory!", nullTerminate=True)
read_msg = alien.MEMORY.readString(offset_msg, nullTerminated=True)
alien.logPipe("MyScript", f"Read from memory symbol 'message_block': {read_msg}")

# --- Example: Using ATLAS (AI Assistant) ---
# Ensure Ollama is running and configured with a model like 'llama3:8b' or 'codellama'
# alien.logPipe("MyScript", "Initializing ATLAS module...")
# alien.ATLAS.initImports()
# if alien.ATLAS.isOllamaRunning() == 1:
#     alien.logPipe("MyScript", "Ollama is running. Asking ATLAS a question...")
#     # Simple question
#     # response = alien.ATLAS.ask("Explain the concept of a buffer overflow in simple terms.")
#     # alien.logPipe("MyScript", f"ATLAS response: {response}")
#
#     # Command generation
#     # suggested_cmd = alien.ATLAS.generateCommand(request="list all python files in the current directory", platform="linux")
#     # alien.logPipe("MyScript", f"ATLAS suggested command: {suggested_cmd}")
#
#     # Script generation
#     # script_dict = alien.ATLAS.generateScript(request="Create a Python script to ping a host and print if it's up", language="python")
#     # alien.logPipe("MyScript", f"ATLAS generated script (markdown): \n{script_dict['content']}")
# else:
#     alien.logPipe("MyScript", "Ollama is not running. ATLAS features requiring Ollama will not work.")

alien.logPipe("MyScript", "Script execution finished.")
