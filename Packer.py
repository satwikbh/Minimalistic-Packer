import os
import subprocess
import sys
from Crypto.Cipher import AES
from Crypto import Random
import struct


class Packer:
    def __init__(self, exe_path, output_name):
        self.exe_path = exe_path
        self.output_name = output_name
        self.aes_key = Random.new().read(32)
        self.aes_iv = Random.new().read(AES.block_size)

    def compress(self, uncompressed):
        """Compress a string to a list of output symbols."""
        dict_size = 256
        dictionary = {chr(i): chr(i) for i in range(dict_size)}
        w = ""
        result = []
        for c in uncompressed:
            wc = w + c
            if wc in dictionary:
                w = wc
            else:
                result.append(dictionary[w])
                dictionary[wc] = dict_size
                dict_size += 1
                w = c
        if w:
            result.append(dictionary[w])
        return result

    def encrypt_data(self, data):
        """Encrypts data using AES (CBC mode)."""
        encryptor = AES.new(self.aes_key, AES.MODE_CBC, self.aes_iv)
        # Pad the data to be a multiple of 16
        padding_length = 16 - (len(data) % 16)
        data += bytes([padding_length]) * padding_length
        return encryptor.encrypt(data)

    def pack(self):
        # Read the executable to be packed
        with open(self.exe_path, "rb") as f:
            exe_data = f.read()

        # Compress and encrypt the executable data
        compressed_data = self.compress(exe_data.decode("latin-1"))
        encrypted_data = self.encrypt_data("".join(compressed_data).encode("latin-1"))

        # Create the PyInstaller command
        pyinstaller_command = [
            "pyinstaller",
            "--onefile",
            "--noconsole",
            f"--name={self.output_name}",
            "loader.py",
        ]

        # Run PyInstaller
        print("Running PyInstaller...")
        subprocess.run(pyinstaller_command, check=True)
        print("PyInstaller finished.")

        # Append the encrypted data, key, and IV to the created executable
        with open(os.path.join("dist", self.output_name), "ab") as f:
            f.write(encrypted_data)
            f.write(struct.pack("<I", len(encrypted_data)))
            f.write(self.aes_iv)
            f.write(struct.pack("<I", len(self.aes_iv)))
            f.write(self.aes_key)
            f.write(struct.pack("<I", len(self.aes_key)))

        print(
            f"Successfully packed {self.exe_path} into {os.path.join('dist', self.output_name)}"
        )


if __name__ == "__main__":
    # You need to have a file named 'calc.exe' in the same directory
    # or provide a path to another executable.
    if not os.path.exists("calc.exe"):
        print("Error: calc.exe not found. Please provide a valid executable.")
        sys.exit(1)

    packer = Packer("calc.exe", "packed_calc.exe")
    packer.pack()
