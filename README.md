# Alien
![HEAD](https://github.com/J4ck3LSyN-Gen2/Alien/blob/main/src/imgs/alien.jpg)
# Alien Framework (ALNv2017.py)

[![Python Version](https://img.shields.io/badge/python-3.x-blue.svg)](https://www.python.org/)
[![Alien Version](https://img.shields.io/badge/Alien_Gen2_017)]

## Overview

The Alien Framework (ALNv2017) is a comprehensive and versatile Python-based toolkit engineered for a wide array of software engineering and cybersecurity-related tasks. It encapsulates a rich suite of functionalities, accessible through distinct modules, designed for network analysis, data manipulation, AI-assisted operations, user interaction (TUI/CLI), web automation, and more.

A cornerstone of Alien's design is **lazy initialization**. Modules are loaded and resources are consumed only upon their first access (e.g., `alien_instance.NMAP`). This approach ensures efficient performance and judicious resource management, making the framework lightweight and responsive.

## Key Features

*   **Modular Architecture:** Functionality is organized into distinct, lazily-loaded modules.
*   **Network Operations:** Robust tools for network scanning (`NMAP`), device discovery (`SHODAN`), and web reconnaissance (`DORKER`, `DIRBUSTER`, `WIKISEARCH`).
*   **Data Management:** In-memory data manipulation (`MEMORY`), SQLite database interaction (`SQL`), variable inspection and conversion (`VARTOOLSET`), and data compression (`HUFFMANENCODING`).
*   **AI-Powered Assistance (`ATLAS`):** Integration with local Large Language Models (LLMs) via Ollama for tasks like command/script generation, contextual chat, and pentesting assistance.
*   **User Interfaces:**
    *   **TUI (Text User Interface):** An interactive terminal interface for easy access to Alien's capabilities, featuring command history, suggestions, and session variable management.
    *   **CLI (Command Line Interface):** Enables direct execution of Alien methods from the system shell.
*   **System & Web Interaction:** Proxy management (`NETWORKPROXY`), foundational browser automation (`BROWSER`), socket-level communication (`TRANSMISSION`), and interfaces for `WSL` and `DOCKER` (foundational).
*   **Core Utilities:** Centralized configuration, flexible logging (`logPipe`), standardized error handling, and various encoding/decoding utilities (Base64, Hex, invisible ASCII steganography, basic ciphers).
*   **Process Management:** Tools for managing background threads and subprocesses.

## Core Modules

The Alien Framework is composed of several specialized modules:

### Networking & Reconnaissance
*   **`NMAP`**: An interface for the Nmap network scanner, allowing for port scanning, service detection, and OS fingerprinting.
*   **`SHODAN`**: Integrates with the Shodan API to discover internet-connected devices and services.
*   **`DORKER`**: Facilitates the construction and execution of Google dorks for targeted information retrieval.
*   **`DIRBUSTER`**: Performs directory and file brute-forcing against web servers to uncover hidden resources.
*   **`WIKISEARCH`**: Fetches and processes data from Wikipedia, enabling programmatic access to its vast information.

### Data Handling & Manipulation
*   **`SQL`**: Provides an interface for managing SQLite databases, including creation, querying, and data manipulation.
*   **`MEMORY`**: Offers tools for direct in-memory data block manipulation, supporting structured data, symbol management, and custom opcode execution.
*   **`VARTOOLSET`**: A collection of utilities for variable inspection, type conversion, string and list manipulation, and mathematical operations.
*   **`HUFFMANENCODING`**: Implements Huffman encoding and decoding for lossless data compression.
*   **`PASSWDBRUTER`**: (Details inferred) Likely provides tools and strategies for password brute-forcing operations.

### Interaction & Automation
*   **`ATLAS`**: The AI engine of Alien, leveraging local LLMs (via Ollama) to provide intelligent assistance, command generation, script creation, and contextual chat capabilities.
*   **`TUI`**: A rich Text User Interface for interactive use of the Alien framework within a terminal.
*   **`CLI`**: A Command Line Interface for scripting and direct execution of Alien functionalities.
*   **`PIPE`**: The central communication bus and execution handler for Alien's internal operations, ensuring consistent command processing.
*   **`LOGIC`**: Enables conditional execution of commands and logic blocks within the TUI and potentially scripts.

### System & Web Interaction
*   **`NETWORKPROXY`**: Manages network proxy configurations and provides tools for making HTTP/S requests, including proxy validation.
*   **`BROWSER`**: Foundational module for browser-related operations, intended for future expansion with Selenium.
*   **`TRANSMISSION`**: Implements socket-level communication for TCP, UDP, and IPC (Linux-only) protocols.
*   **`WSL`**: (Windows-Specific) Provides basic interaction capabilities with the Windows Subsystem for Linux.
*   **`DOCKER`**: Foundational module for interacting with Docker containers.

### Core Utilities
*   **Configuration Management**: A centralized `self.configure` dictionary allows for runtime customization of module behaviors. Values can be accessed and modified using `getConfigureValue` and `setConfigureValue`.
*   **Logging (`logPipe`)**: A flexible logging system that can output to the console, TUI, and/or files in JSON or plain text format, with configurable verbosity and unique file naming.
*   **Error Handling (`self.error`)**: Standardized mechanism for raising exceptions with consistent formatting.
*   **Encoding/Decoding**: Includes utilities for Base64, Hex, URL-safe tokens, and steganographic encoding/decoding using invisible ASCII characters.
*   **Cryptography**: Basic ciphers (Caesar, Vigenere, XOR) and secure random token generation.

## Prerequisites

*   **Python:** Version 3.x (developed with 3.10+ in mind).
*   **External Libraries:** Install the required Python packages using pip:
    ```bash
    pip install -U blessed googlesearch-python requests beautifulsoup4 shodan huffman wikipedia selenium
    ```
    *   **`blessed`**: Required for the Text User Interface (TUI).
    *   **`googlesearch-python`**: Used by the `DORKER` module.
    *   **`requests`**: Used by various modules for HTTP/S communication (e.g., `NETWORKPROXY`, `DORKER`, `ATLAS`).
    *   **`beautifulsoup4`**: Used for HTML parsing (e.g., `DORKER`).
    *   **`shodan`**: Required for the `SHODAN` module.
    *   **`huffman`**: Used by the `HUFFMANENCODING` module.
    *   **`wikipedia`**: Used by the `WIKISEARCH` module.
    *   **`selenium`**: Imported by `BROWSER` for future web automation capabilities. Requires WebDriver installation (e.g., ChromeDriver) if used.
*   **External Tools & Services (for specific modules):**
    *   **Ollama:** For `ATLAS` module functionality. An Ollama instance must be running with desired models (e.g., `llama3:8b`, `codellama`) pulled. See Ollama's official documentation.
    *   **Nmap:** For the `NMAP` module. Nmap must be installed and accessible in your system's PATH.
    *   **Wordlists:** For `DIRBUSTER` and `PASSWDBRUTER` modules, appropriate wordlists are needed (e.g., from SecLists, Kali-Wordlists).
        *   Example: `git clone https://github.com/00xBAD/kali-wordlists.git`
    *   **FFUF (Optional):** If you plan to extend `DIRBUSTER` to use FFUF.
        *   Example: `git clone https://github.com/ffuf/ffuf.git`
    *   **WSL (Windows Only):** For `WSL` module functionality, WSL must be installed and configured (e.g., `wsl --install kali-linux`). 

## Installation

1.  **Clone the Repository (if applicable) or Save the Script:**
    Save the main script as `ALNv2017.py`.
2.  **Install Prerequisites:**
    Ensure Python 3.x is installed. Then, install the required libraries:
    ```bash
    pip install -U blessed googlesearch-python requests beautifulsoup4 shodan huffman wikipedia selenium
    ```
3.  **Set up External Tools:**
    Install Nmap, Ollama (and pull models), and acquire necessary wordlists as described in the Prerequisites section.

## Getting Started

The Alien Framework can be run in several modes:

1.  **Text User Interface (TUI - Default Mode):**
    Execute the script without any command-line arguments:
    ```bash
    python ALNv2017.py
    ```
    This launches an interactive terminal interface. Type `help` within the TUI for a list of commands.

2.  **Command Line Interface (CLI):**
    Execute specific Alien methods directly from your terminal:
    ```bash
    python ALNv2017.py <METHOD_PATH> --args '[arg1, arg2]' --kwargs '{"key1":"value1"}'
    ```
    *   `<METHOD_PATH>`: Dot-separated path to the method (e.g., `NMAP.scan`, `getConfigureValue`).
    *   `--args`: JSON string of a list for positional arguments.
    *   `--kwargs`: JSON string of a dictionary for keyword arguments.

    Example:
    ```bash
    python ALNv2017.py NMAP.scan --args '["127.0.0.1"]' --kwargs '{"ports":[80,443]}'
    ```

3.  **As a Python Library:**
    Import and use the `Alien` class in your own Python scripts.

## Usage Examples

### Python Scripting

```python
# example_script.py
from ALNv2017 import Alien

# Initialize Alien.
# By default, this also initializes system info and logging.
alien = Alien()

# Example: Configure logging for verbosity
alien.setConfigureValue("logPipe-configure.verbose", 1)
alien.setConfigureValue("logPipe-configure.filePipe", 0) # Disable file logging for this example

alien.logPipe("MyScript", "Alien instance created and configured.")

# Example: Using the NMAP module
alien.logPipe("MyScript", "Attempting NMAP scan on localhost...")
# Ensure Nmap is installed and in PATH. Some scans might need elevated privileges.
nmap_results = alien.NMAP.scan(targets="127.0.0.1", ports=[22, 80, 443], arguments="-sV -T4")
if nmap_results and nmap_results.get("hosts"):
    for host_ip, host_data in nmap_results["hosts"].items():
        alien.logPipe("MyScript", f"Host: {host_ip}, Status: {host_data.get('status')}")
        for proto, ports_info in host_data.get("ports", {}).items():
            for port_id, port_details in ports_info.items():
                if port_details.get('state') == 'open':
                    alien.logPipe("MyScript", f"  {proto.upper()}/{port_id} Open - Service: {port_details.get('service')}, Version: {port_details.get('product')} {port_details.get('version')}")
else:
    alien.logPipe("MyScript", "Nmap scan failed or returned no host information.")

# Example: Using the ATLAS module (ensure Ollama is running with a model like 'llama3:8b')
alien.logPipe("MyScript", "Initializing ATLAS module...")
alien.ATLAS.initImports() # Ensure requests and json are loaded for ATLAS

if alien.ATLAS.isOllamaRunning() == 1:
    alien.logPipe("MyScript", "Ollama is running. Asking ATLAS to suggest a command...")
    # Use a more specific goal for better suggestions
    goal = "Scan all TCP ports on 192.168.1.10 and identify service versions."
    suggested_alien_command, explanation = alien.ATLAS.suggestAlienCommand(user_goal=goal)
    if suggested_alien_command:
        alien.logPipe("MyScript", f"ATLAS suggested Alien command: {suggested_alien_command}")
        # You could potentially execute this command via alien.PIPE.execute()
    else:
        alien.logPipe("MyScript", f"ATLAS explanation (no direct command): {explanation}")

    # Example: Generate a shell command
    shell_command_request = "Find all files modified in the last 24 hours in /tmp"
    suggested_shell_cmd = alien.ATLAS.generateCommand(request=shell_command_request, platform="linux")
    alien.logPipe("MyScript", f"ATLAS suggested shell command for '{shell_command_request}': {suggested_shell_cmd}")
else:
    alien.logPipe("MyScript", "Ollama is not running. ATLAS features requiring Ollama will not work.")

alien.logPipe("MyScript", "Script execution finished.")
```

### Text User Interface (TUI)

Launch the TUI by running `python ALNv2017.py` without arguments.

*   **Interactive Commands:** Type commands directly (e.g., `NMAP.scan "127.0.0.1" ports=[80,22]`).
*   **Help:** Use `help` for general commands or `help <MODULE.METHOD>` for specific help.
*   **Suggestions & History:** Use Tab for autocompletion and Up/Down arrows for command history.
*   **Session Variables:** Use `set var_name value` and `env` to manage session variables.
*   **Conditional Logic:** Use `if $var == "val" { COMMAND } else { OTHER_COMMAND }`.
*   **ATLAS Chat:** Prefix your input with `atlas:` (or your configured prefix) to chat with the ATLAS AI.

### Command Line Interface (CLI)

Execute Alien methods non-interactively.

**Syntax:**
`python ALNv2017.py <METHOD_PATH> [--args JSON_LIST] [--kwargs JSON_DICT]`

**Example: Get Alien configuration value**
```bash
python ALNv2017.py getConfigureValue --args '["logPipe-configure.verbose"]'
```

**Example: Perform a Shodan host lookup (requires Shodan API key configured in ALNv2017.py)**
```bash
python ALNv2017.py SHODAN.host --args '["1.1.1.1"]' --kwargs '{"history":false}'
```
Output will be in JSON format.

## Configuration

The Alien Framework uses an internal dictionary `self.configure` for managing settings for its various modules.

*   **Accessing Configuration:** Use `alien.getConfigureValue("path.to.key")`.
*   **Modifying Configuration:** Use `alien.setConfigureValue("path.to.key", new_value)`.

Key configuration sections include:
*   `logPipe-configure`: Controls logging behavior (verbosity, file output, formatting).
*   `ollama-configure`: Paths to the Ollama executable.
*   `atlas-configure`: Ollama API URL, default models for ATLAS tasks.
*   `shodan-configure`: Shodan API key.
*   `nmapPortScanner-configure`: Default Nmap arguments and ports.
*   And many more specific to each module.

Review the `__init__` method of the `Alien` class in `ALNv2017.py` for a comprehensive list of default configurations.

## Logging

Alien features a robust logging system via the `logPipe` method.

*   **Verbosity:** Controlled by `logPipe-configure.verbose`.
*   **File Logging:** Controlled by `logPipe-configure.filePipe`. Logs can be saved to a specified directory and file, with options for unique naming.
*   **Format:** Logs are structured (typically JSON by default for file output) and include timestamps, source method, instance IDs, and thread/process IDs.

## Future Development

The Alien Framework is an evolving project. Potential future enhancements include:
*   More sophisticated web automation (`WebAutomator` using Selenium).
*   Advanced network protocol clients (SNMP, SSH, FTP).
*   Deeper integration with vulnerability databases and scanning tools.
*   Expanded NLP and Machine Learning capabilities within `ATLAS`.
*   Enhanced system monitoring and file management utilities.
*(Refer to `NextAdditions.md` for more brainstormed ideas).*

## Contributing

Currently, the Alien Framework is primarily a solo project. However, feedback, bug reports, and well-structured feature requests are welcome. Please open an issue on the GitHub repository for discussions.

## License

Copyright © 2025 JackalSyn Ind.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---

This README provides a comprehensive guide to the Alien Framework. For specific module or method details, refer to the docstrings within `ALNv2017.py` or use the TUI's `help` command.
