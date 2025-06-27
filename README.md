# Minimalistic Packer (Python-Only)

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)

This project is a proof-of-concept executable packer written entirely in Python. It demonstrates how a simple packer can compress and encrypt a Windows executable, and then bundle it with a Python-based loader into a new, single executable file. The resulting file, when run, will unpack the original executable in memory and execute it.

This project is intended for educational purposes to understand the basic principles of executable packing.

## Features

*   **LZW Compression:** Reduces the size of the payload.
*   **AES-256 Encryption:** Encrypts the compressed payload to obscure it.
*   **Python-based Loader:** The packed executable uses an embedded Python runtime to load the original program.
*   **Standalone Executable:** The final packed file is a single, standalone executable.

## Project Structure

```
.Minimalistic-Packer/
├── Packer.py           # The main script to pack the executable.
├── README.md           # This file.
├── Source.txt          # A brief description of the files.
├── build.sh            # A script to build the sample C program.
├── calc.c              # A sample C program to be packed.
├── calc.exe            # The compiled sample executable.
└── loader.py           # The Python script that acts as the runtime loader.
```

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

*   Python 3
*   `pip` for Python 3
*   A C compiler, such as `gcc`, to build the sample executable.

### Installation

1.  **Clone the repository:**
    ```sh
    git clone https://github.com/your-username/Minimalistic-Packer.git
    cd Minimalistic-Packer
    ```

2.  **Install the required Python dependencies:**
    ```sh
    pip3 install pyinstaller pycryptodome
    ```

3.  **Build the sample executable:**

    The project comes with a sample `calc.c` file. You can compile it using the provided build script.
    ```sh
    chmod +x build.sh
    ./build.sh
    ```
    This will create a `calc.exe` file in the project directory.

### Running the Packer

To pack the `calc.exe` executable, run the `Packer.py` script:

```sh
python3 Packer.py
```

The script will perform the following steps:

1.  Read the `calc.exe` file.
2.  Compress and encrypt its contents.
3.  Use `pyinstaller` to build a new executable from `loader.py`.
4.  Append the encrypted data, AES key, and IV to the new executable.

The final packed executable will be located in the `dist/` directory, named `packed_calc.exe`.

## How It Works

### The Packing Process

1.  **Payload Preparation:** The `Packer.py` script first reads the target executable (`calc.exe`). It then compresses the data using a simple LZW algorithm and encrypts the result with AES-256.

2.  **Loader Creation:** The script uses `pyinstaller` to compile the `loader.py` script into a standalone Windows executable. This executable contains the Python interpreter and all the necessary libraries to run the loader script.

3.  **Data Injection:** The encrypted payload, along with the AES key and IV needed for decryption, are appended to the end of the `pyinstaller`-generated executable. This creates the final, packed executable.

### The Loading Process

When the packed executable is run, the `loader.py` script is executed.

1.  **Data Extraction:** The loader script opens its own executable file in binary mode. It seeks to the end of the file to find and read the appended payload, key, and IV.

2.  **Decryption and Decompression:** The loader uses the extracted key and IV to decrypt the payload, and then decompresses the data to retrieve the original executable's content.

3.  **Execution:** The decompressed executable data is written to a temporary file on disk. The loader then uses the `subprocess` module to execute this temporary file.

4.  **Cleanup:** After the executed process terminates, the temporary file is deleted.

## Limitations and Disclaimer

This is a proof-of-concept and has several limitations:

*   **Antivirus Detection:** This type of packer is easily detected by most modern antivirus software.
*   **Performance:** The loading process involves writing to disk and starting a new process, which is not as efficient as more advanced in-memory loading techniques.
*   **Reliance on PyInstaller:** The project's core functionality depends on `pyinstaller` to create the loader executable.

This tool should be used for educational purposes only.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.
