# Alien Framework (ALNv2018.py)

[![Python Version](https://img.shields.io/badge/python-3.x-blue.svg)](https://www.python.org/)

![HEAD](https://github.com/J4ck3LSyN-Gen2/Alien/blob/main/src/imgs/alien.jpg)

[![Python Version](https://img.shields.io/badge/python-3.x-blue.svg)](https://www.python.org/)
---

## Overview

The Alien Framework (ALNv2018) is a comprehensive and versatile Python-based toolkit engineered for a wide array of software engineering and cybersecurity-related tasks. It encapsulates a rich suite of functionalities, accessible through distinct modules, designed for network analysis, data manipulation, AI-assisted operations, user interaction (TUI/CLI), web automation, and more.

A cornerstone of Alien's design is **lazy initialization**. Modules are loaded and resources are consumed only upon their first access (e.g., `alien_instance.NMAP`). This approach ensures efficient performance and judicious resource management, making the framework lightweight and responsive.

---

## Key Features

* **Modular Architecture:** Functionality is organized into distinct, lazily-loaded modules.
* **Network Operations:** Robust tools for network scanning (`NMAP`), device discovery (`SHODAN`), and web reconnaissance (`WIKISEARCH`).
* **Data Management:** In-memory data manipulation (`MEMORY`), SQLite database interaction (`SQL`), variable inspection and conversion (`VARTOOLSET`), and data compression (`HUFFMANENCODING`).
* **AI-Powered Assistance (`ATLAS`):** Integration with local Large Language Models (LLMs) via Ollama for tasks like command/script generation, contextual chat, and pentesting assistance.
* **User Interfaces:**
    * **TUI (Text User Interface):** An interactive terminal interface for easy access to Alien's capabilities, featuring command history, suggestions, and session variable management.
    * **CLI (Command Line Interface):** Enables direct execution of Alien methods from the system shell.
* **System & Web Interaction:** Proxy management (`NETWORKPROXY`), full-fledged browser automation (`BROWSER`), socket-level communication (`TRANSMISSION`), and interfaces for `WSL`.
* **Core Utilities:** Centralized configuration, flexible logging (`logPipe`), standardized error handling, and various encoding/decoding utilities (Base64, Hex, invisible ASCII steganography, basic ciphers).
* **Process Management:** Tools for managing background threads and subprocesses.
* **Remote Control:** A secure, threaded HTTP/S server (`API`) to expose Alien's functionalities for remote control and integration.

---

## Core Modules

The Alien Framework is composed of several specialized modules:

### Networking & Reconnaissance
* **`NMAP`**: An interface for the Nmap network scanner, allowing for port scanning, service detection, and OS fingerprinting.
* **`SHODAN`**: Integrates with the Shodan API to discover internet-connected devices and services.
* **`WIKISEARCH`**: Fetches and processes data from Wikipedia, enabling programmatic access to its vast information.

### Data Handling & Manipulation
* **`SQL`**: Provides an interface for managing SQLite databases, including creation, querying, and data manipulation.
* **`MEMORY`**: Offers tools for direct in-memory data block manipulation, supporting structured data, symbol management, and custom opcode execution.
* **`VARTOOLSET`**: A collection of utilities for variable inspection, type conversion, string and list manipulation, and mathematical operations.
* **`HUFFMANENCODING`**: Implements Huffman encoding and decoding for lossless data compression.

### Interaction & Automation
* **`ATLAS`**: The AI engine of Alien, leveraging local LLMs (via Ollama) to provide intelligent assistance, command generation, script creation, and contextual chat capabilities.
* **`TUI`**: A rich Text User Interface for interactive use of the Alien framework within a terminal.
* **`CLI`**: A Command Line Interface for scripting and direct execution of Alien functionalities.
* **`PIPE`**: The central communication bus and execution handler for Alien's internal operations, ensuring consistent command processing.
* **`LOGIC`**: Enables conditional execution of commands and logic blocks within the TUI and potentially scripts.
* **`API`**: Provides a secure, threaded HTTP/S server to expose Alien's functionalities for remote control and integration. This allows other applications or scripts to programmatically interact with and control Alien's modules.

### System & Web Interaction
* **`NETWORKPROXY`**: Manages network proxy configurations and provides tools for making HTTP/S requests, including proxy validation.
* **`BROWSER`**: Provides robust browser automation capabilities using **Selenium**. It can launch and control a web browser (e.g., Chrome, Firefox) to navigate pages, execute JavaScript, interact with elements (clicking buttons, filling forms), manage cookies, and scrape content from dynamic, JavaScript-rendered websites.
* **`TRANSMISSION`**: Implements socket-level communication for TCP, UDP, and IPC (Linux-only) protocols.
* **`WSL`**: (Windows-Specific) Provides basic interaction capabilities with the Windows Subsystem for Linux.

### Core Utilities
* **Configuration Management**: A centralized `self.configure` dictionary allows for runtime customization of module behaviors. Values can be accessed and modified using `getConfigureValue` and `setConfigureValue`.
* **Logging (`logPipe`)**: A flexible logging system that can output to the console, TUI, and/or files in JSON or plain text format, with configurable verbosity and unique file naming.
* **Error Handling (`self.error`)**: Standardized mechanism for raising exceptions with consistent formatting.
* **Encoding/Decoding**: Includes utilities for Base64, Hex, URL-safe tokens, and steganographic encoding/decoding using invisible ASCII characters.
* **Cryptography**: Basic ciphers (Caesar, Vigenere, XOR) and secure random token generation.

---

## Prerequisites

* **Python:** Version 3.x (developed with 3.10+ in mind).
* **External Libraries:** Install the required Python packages using pip:
    ```bash
    pip install -U blessed requests shodan huffman wikipedia selenium
    ```
    * **`blessed`**: Required for the Text User Interface (TUI).
    * **`requests`**: Used by various modules for HTTP/S communication (e.g., `NETWORKPROXY`, `ATLAS`, `API`).
    * **`shodan`**: Required for the `SHODAN` module.
    * **`huffman`**: Used by the `HUFFMANENCODING` module.
    * **`wikipedia`**: Used by the `WIKISEARCH` module.
    * **`selenium`**: Required by the `BROWSER` module for web automation.
* **External Tools & Services (for specific modules):**
    * **Ollama:** For `ATLAS` module functionality. An Ollama instance must be running with desired models (e.g., `codellama:13b-instruct`) pulled. See Ollama's official documentation.
    * **Nmap:** For the `NMAP` module. Nmap must be installed and accessible in your system's PATH.
    * **WebDriver (for `BROWSER` module):** To use the `BROWSER` module, you need a WebDriver that matches your browser (e.g., Chrome, Firefox). Selenium's built-in "Selenium Manager" will attempt to download the correct driver automatically if it's not found in your system's PATH.
    * **WSL (Windows Only):** For `WSL` module functionality, WSL must be installed and configured (e.g., `wsl --install kali-linux`).

---

## Installation

1.  **Clone the Repository (if applicable) or Save the Script:**
    Save the main script as `ALNv2018.py`.
2.  **Install Prerequisites:**
    Ensure Python 3.x is installed. Then, install the required libraries:
    ```bash
    pip install -U blessed requests shodan huffman wikipedia selenium
    ```
3.  **Set up External Tools:**
    Install Nmap and Ollama (and pull models) as described in the Prerequisites section.

---

## Getting Started

The Alien Framework can be run in several modes:

1.  **Text User Interface (TUI - Default Mode):**
    Execute the script without any command-line arguments:
    ```bash
    python ALNv2018.py
    ```
    This launches an interactive terminal interface. Type `help` within the TUI for a list of commands.

2.  **Command Line Interface (CLI):**
    Execute specific Alien methods directly from your terminal using a structured command-line parser. This provides a more robust and explicit way to interact with modules and their methods.
    ```bash
    python ALNv2018.py <MODULE> <METHOD> [options...]
    ```
    * `<MODULE>`: The name of the module (e.g., `NMAP`, `SHODAN`). Use `CORE` for direct Alien methods like `getConfigureValue` or `logPipe`.
    * `<METHOD>`: The name of the method to execute within the specified module.
    * `[options...]`: Method-specific arguments, passed as named parameters.
    
    To understand the arguments a specific method accepts, use the `--help` flag:
    ```bash
    python ALNv2018.py NMAP scan --help
    ```

    Example: Perform an Nmap scan
    ```bash
    python ALNv2018.py NMAP scan --targets "127.0.0.1" --ports 80 443 --arguments "-sV -T4"
    ```

    Example: Get an Alien configuration value
    ```bash
    python ALNv2018.py CORE getConfigureValue --path-string "logPipe-configure.verbose"
    ```

    Example: Perform a Shodan host lookup (requires Shodan API key configured in `ALNv2018.py`)
    ```bash
    python ALNv2018.py SHODAN host --target-ip "1.1.1.1" --history false
    ```
    Output from CLI commands will typically be in JSON format where applicable.

3.  **As a Python Library:**
    Import and use the `Alien` class in your own Python scripts for programmatic control and integration.

---

## Usage Examples

### Python Scripting

```python
# example_script.py
from ALNv2018 import Alien

# Initialize Alien.
# By default, this also initializes system info and logging.
alien = Alien()

# Example: Configure logging for verbosity
alien.setConfigureValue("logPipe-configure.verbose", 1)
alien.setConfigureValue("logPipe-configure.filePipe", 0) # Disable file logging for this example

alien.logPipe("MyScript", "Alien instance created and configured.")

# Example: Using the NMAP module for port scanning
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

# Example: Using the BROWSER module to scrape a JavaScript-rendered page
alien.logPipe("MyScript", "Attempting to scrape a dynamic page with BROWSER.scrapeURL...")
# The scrapeURL method starts a headless browser, navigates, scrapes, and closes it.
# Note: The first run might be slow if Selenium Manager needs to download a driver.
dynamic_page_source = alien.BROWSER.scrapeURL(url="[https://www.google.com](https://www.google.com)") # Replace with a JS-heavy site for a real test
if dynamic_page_source:
    alien.logPipe("MyScript", f"Successfully scraped page source (first 200 chars): {dynamic_page_source[:200]}...")
    # You could now parse this source with BeautifulSoup or other tools for further analysis.
else:
    alien.logPipe("MyScript", "Failed to scrape the page using the BROWSER module.")

# Example: Starting the Alien API server
alien.logPipe("MyScript", "Attempting to start the Alien API server...")
# This will start a new thread for the API server.
# By default, it runs on port 5000 and is accessible at [http://127.0.0.1:5000/api](http://127.0.0.1:5000/api)
# You can configure port, host, and SSL via alien.setConfigureValue.
api_server_status = alien.API.startServer()
if api_server_status:
    alien.logPipe("MyScript", "Alien API server started successfully. Access it via HTTP/S requests.")
    # In a real application, you'd keep your script running or handle threads.
    # For this example, we'll just log success.
else:
    alien.logPipe("MyScript", "Failed to start Alien API server.")


alien.logPipe("MyScript", "Script execution finished.")
```
Text User Interface (TUI)

### Launch the TUI by running python ALNv2018.py without arguments.
* Interactive Commands: Type commands directly (e.g., `NMAP.scan "127.0.0.1" ports=[80,22]`).
* Help: Use `help` for general commands or `help <MODULE.METHOD>` for specific help on how to use a module's method.
* Suggestions & History: Use `Tab` for autocompletion and `Up/Down arrows` for command history, streamlining your workflow.
* Session Variables: Use `set var_name value` and `env` to manage session variables, useful for storing and reusing data across commands.
* Conditional Logic: Employ `if $var == "val" { COMMAND } else { OTHER_COMMAND }` for dynamic command execution based on session variables.
* ATLAS Chat: Prefix your input with atlas: (or your configured prefix) to engage in a contextual chat with the ATLAS AI.

### Command Line Interface (CLI)
#### Execute Alien methods non-interactively with a powerful argument parser, ideal for scripting and automation.
Syntax:`python ALNv2018.py <MODULE> <METHOD> [options...]`

Example: Get Alien configuration value
```Bash
python ALNv2018.py CORE getConfigureValue --path-string "logPipe-configure.verbose"
```
Example: Perform a Shodan host lookup (requires Shodan API key configured in ALNv2018.py)
```Bash
python ALNv2018.py SHODAN host --target-ip "1.1.1.1" --history false
```
Output will be in JSON format, making it easy to parse with other tools.
### Configuration

The Alien Framework uses an internal dictionary self.configure for managing settings for its various modules. This centralized approach allows for flexible runtime customization.
* Accessing Configuration: Use `alien.getConfigureValue("path.to.key")`.
* Modifying Configuration: Use `alien.setConfigureValue("path.to.key", new_value)`.

Key configuration sections include:
* logPipe-configure: Controls logging behavior (verbosity, file output, formatting).
* ollama-configure: Paths to the Ollama executable.
* atlas-configure: Ollama API URL, default models for ATLAS tasks.
* shodan-configure: Shodan API key.
* nmapPortScanner-configure: Default Nmap arguments and ports.
* browser-configure: Settings for the Selenium-based BROWSER module, including the path to the WebDriver executable, browser type (chrome/firefox), and headless mode.
* api-configure: Settings for the API module, such as the listening host, port, and SSL certificate paths.

And many more specific to each module, allowing granular control over Alien's operations.
Review the __init__ method of the Alien class in ALNv2018.py for a comprehensive list of default configurations.

### Logging
Alien features a robust logging system via the logPipe method, providing detailed insights into its operations.
* Verbosity: Controlled by `logPipe-configure.verbose`, allowing you to adjust the level of detail from minimal to verbose.
* File Logging: Controlled by `logPipe-configure.filePipe`. Logs can be saved to a specified directory and file, with options for unique naming based on timestamp or other criteria.
* Format: Logs are structured (typically `JSON` by default for file output) and include essential metadata such as timestamps, the source method, instance IDs, and thread/process IDs, making them easy to parse and analyze for debugging or auditing.

### Future Development
The Alien Framework is an evolving project, continuously being enhanced with new capabilities. Potential future enhancements include:
* Enhanced BROWSER module for even more complex web automation, including advanced element interaction (e.g., complex form submissions, drag-and-drop), managing browser profiles and local storage, and handling multiple tabs/windows more efficiently.
* Advanced network protocol clients (SNMP, SSH, FTP) for broader network interaction and analysis.
* Deeper integration with vulnerability databases and scanning tools to provide more context-aware and automated security assessments.
* Expanded NLP and Machine Learning capabilities within ATLAS for more sophisticated data analysis, anomaly detection, and predictive capabilities in cybersecurity contexts.
* Enhanced system monitoring and file management utilities to provide comprehensive oversight and control over the operating environment.
* Implement a way for `ATLAS` to execute commands and get the results, fully automating tests (In Development ALNv2019.py)

### Contributing

Currently, the Alien Framework is primarily a solo project. However, feedback, bug reports, and well-structured feature requests are genuinely welcome as contributions to its development. Please open an issue on the GitHub repository for discussions or to propose enhancements.

### License

Copyright © 2025 JackalSyn Ind.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

This README provides a comprehensive guide to the Alien Framework. For specific module or method details, refer to the docstrings within ALNv2018.py or use the TUI's help command.
