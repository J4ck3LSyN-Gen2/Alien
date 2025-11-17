# Alien Interpreter (Generation 2)

This document provides an overview of the Alien Interpreter's execution structure and its standard library.

## Execution Structure

The following diagram illustrates the flow of execution within the interpreter, from the main `run` command down to individual statement and expression handling.

```mermaid
graph TD
    subgraph Main Execution
        A[run()] --> B{Has Inline?};
        B -- Yes --> C[Execute Inline Statements];
        B -- No --> D{Find Entry Point (e.g., 'main')};
        C --> D;
        D -- Found --> E[Call _handleStatements(main body)];
        D -- Not Found --> F[End];
        E --> F;
    end

    subgraph Statement Handling
        G[_handleStatements(statements, scope)] --> H{Push Scope};
        H --> I{Loop through statements};
        I -- Next Statement --> J{Switch on statement 'type'};
        I -- No More Statements --> K{Pop Scope};
        K --> L[Return Value or None];

        J -- assign --> JA[_handleExpression(value)] --> JB[_varAssign(name, value)];
        J -- if --> JC{_handleExpression(condition)};
        JC -- True --> JD[_handleStatements(then_block)];
        JC -- False --> JE{Check 'elseif'};
        JE -- True --> JF[_handleStatements(elseif_then)];
        JE -- False --> JG{Check 'else'};
        JG -- True --> JH[_handleStatements(else_block)];
        J -- for --> JI[_handleExpression(iterable)] --> JJ{Loop};
        JJ -- Each item --> JK[Create loop scope & _handleStatements(body)];
        J -- while --> JL{_handleExpression(condition)};
        JL -- True --> JM[_handleStatements(body)] --> JL;
        J -- return --> JN[_handleExpression(value)] --> K;
        J -- call/methodCall --> JO[_handleExpression(statement)];
        J -- import --> JP[_handleImport(statement)];
        J -- try --> JQ[_handleTryCatch(statement)];
        
        JB --> I;
        JD --> I;
        JF --> I;
        JH --> I;
        JK --> JJ;
        JM --> JL;
        JO --> I;
        JP --> I;
        JQ --> I;
    end

    subgraph Expression Evaluation
        S[_handleExpression(expression)] --> T{Switch on expression 'type'};
        T -- literal --> U[Return value];
        T -- varRef --> V[_varResolve(name)];
        T -- binaryOp --> W[_handleExpression(left)] & X[_handleExpression(right)] --> Y[_handleBinaryOp(op, left, right)];
        T -- call --> Z[_handleFunctionCall(name, args, kwargs)];
        T -- methodCall --> AA[_handleFunctionCall(method, args, kwargs)];
        T -- new --> AB[Create instance & _handleFunctionCall(constructor)];
    end

    subgraph Function/Library Calls
        FC[_handleFunctionCall()] --> FD{Is Python Callable?};
        FD -- Yes --> FE[Execute Python function];
        FD -- No --> FF{Is Alien Function?};
        FF -- Yes --> FG[Bind args, create new scope] --> G;
        FE --> R[Return Value];
        L --> R;
    end

    E --> G;
    JO --> S;
    JA --> S;
    JC --> S;
    JI --> S;
    JL --> S;
    JN --> S;
    JQ --> G;
    Z --> FC;
    AA --> FC;
    AB --> FC;

    classDef internal fill:#f9f,stroke:#333,stroke-width:2px;
    class A,B,C,D,E,F,G,H,I,J,K,L,S,FC,R internal;
```

## Standard Library

The interpreter comes with a built-in standard library providing essential functionalities.

### `alien`
Core interpreter functionalities.
- **`getLoggerObject()`**: Returns the internal logger object.
- **`logPipe(...)`**: Pipes a message to the logger (if enabled).
- **`getSelf()`**: Returns the `interpreterHandle` instance itself, useful for Pythonic libraries.

### `io`
Input and output operations.
- **`print(*args, **kwargs)`**: Prints values to the console.
  - *Example*: `{"type":"call", "functionName":"io.print", "arguments":[{"type":"literal", "value":"Hello, World!"}]}`
- **`input(prompt)`**: Reads a line from console input.
  - *Example*: `{"type":"assign", "target":{"name":"userInput"}, "value":{"type":"call", "functionName":"io.input", "arguments":[{"type":"literal", "value":"Enter name: "}]}}`

### `json`
JSON manipulation.
- **`loads(string)`**: Parses a JSON string into an object (dict/list).
- **`dumps(data, indent)`**: Converts a dictionary or list into a JSON formatted string.
- **`load(filePath)`**: Reads a JSON file and parses it.
- **`dump(data, filePath)`**: Writes a dictionary or list to a JSON file.

### `time`
Time-related functions.
- **`time()`**: Returns the current time as a Unix timestamp (float).
- **`sleep(seconds)`**: Pauses execution for a given number of seconds.
- **`getTimeDifference(startTime)`**: Calculates the difference between the current time and a start time.
- **`asciiTime()`**: Returns a human-readable string of the current time.

### `systemInfo`
Gathers information about the host system.
- **`sysInfo()`**: Returns a dictionary containing comprehensive system information (OS, CPU, memory, etc.).

### `path`
File and directory manipulation.
- **`isDir(path)`**: Checks if a path is a directory.
- **`isFile(path)`**: Checks if a path is a file.
- **`exist(path)`**: Checks if a path exists.
- **`mkDir(dirName, path)`**: Creates a new directory.
- **`rmDir(path)`**: Removes a directory.
- **`rmFile(path)`**: Removes a file.
- **`file.read(filePath)`**: Reads the content of a file as a string.
- **`file.writeStr(filePath, data)`**: Writes a string to a file, overwriting it.
- **`file.writeBytes(filePath, data)`**: Writes bytes to a file, overwriting it.
- **`file.append(filePath, data)`**: Appends a string to a file.

### `cypher.passwd`
Password and token generation.
- **`tokenHex(length)`**: Generates a random token in hexadecimal format.
- **`tokenBytes(length)`**: Generates a random token as bytes.
- **`randomBytes(length)`**: Generates a set of random bytes.

### `memory`
Low-level memory block emulation.
- **`init.struct()`**: Initializes the struct module for packing/unpacking data.
- **`init.block()`**: Initializes the main memory block (bytearray).
- **`bytes.read(offset, length)`**: Reads a number of bytes from a specific offset in the block.
- **`bytes.write(offset, data)`**: Writes bytes to a specific offset in the block.

### `variables`
A rich library for manipulating primitive data types.
- **`string.join(list, separator)`**: Joins a list of strings.
- **`string.split(string, separator)`**: Splits a string into a list.
- **`string.replace(string, target, replacer)`**: Replaces parts of a string.
- **`string.reverse(string)`**: Reverses a string.
- **`list.append(item, list)`**: Appends an item to a list.
- **`list.pop(list)`**: Removes and returns the last item from a list.
- **`list.index(index, list)`**: Gets an item from a list by its index.
- **`dict.keyExists(key, dict)`**: Checks if a key exists in a dictionary.
- **`dict.get(key, dict, elseOption)`**: Gets a value from a dictionary by its key.
- **`dict.append(key, value, dict)`**: Adds a key-value pair to a dictionary.
- **`dict.removeKey(key, dict)`**: Removes a key from a dictionary.
- **`bool.flip(boolean)`**: Inverts a boolean value (`True` -> `False`).
- **`bytes.encode(string, encoding)`**: Encodes a string into bytes.
- **`bytes.decode(bytes, encoding)`**: Decodes bytes into a string.

### `huffman`
Huffman compression.
- **`encode(data)`**: Compresses data using the Huffman algorithm.
- **`decode(data)`**: Decompresses data that was compressed with Huffman.

### `zip`
ZIP archive manipulation.
- **`compress.targetFiles(outputZipName, fileList)`**: Compresses a list of specified files into a zip archive.
- **`compress.directory(targetPath, outputPath)`**: Compresses an entire directory.
- **`decompress.directory(targetPath, outputPath)`**: Decompresses a zip archive.
- **`getContents(targetPath)`**: Lists the contents of a zip archive.

### `sock`
Low-level socket operations.
- **`getSocketObject(sockType)`**: Creates and returns a socket object of a given type (e.g., 'tcp').
- **`connectEX(socketObject, host, port)`**: Tests a connection to a host and port.

### `curl`
Web request functionality.
- **`basicGet(url)`**: Performs a simple HTTP GET request.

### `proc`
Process and command execution.
- **`shell(command)`**: Executes a shell command and returns its output.
  - *Example*: `{"type":"call", "functionName":"proc.shell", "arguments":[{"type":"literal", "value":"ls -l"}]}`