import os
import subprocess
import sys
import tempfile
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
import struct

# This is a placeholder for the compressed and encrypted data
# The packer will replace this with the actual data.
packed_data = b""

# These will be patched by the packer
AES_KEY = b""
AES_IV = b""


def decompress(compressed):
    """Decompress a list of output ks to a string."""
    dict_size = 256
    dictionary = {chr(i): chr(i) for i in range(dict_size)}

    result = []
    w = compressed.pop(0)
    result.append(w)
    for k in compressed:
        if k in dictionary:
            entry = dictionary[k]
        elif k == dict_size:
            entry = w + w[0]
        else:
            raise ValueError("Bad compressed k: %s" % k)
        result.append(entry)

        dictionary[dict_size] = w + entry[0]
        dict_size += 1

        w = entry
    return "".join(result)


def decrypt_data(data, key, iv):
    """Decrypts data using AES (CBC mode)."""
    decryptor = AES.new(key, AES.MODE_CBC, iv)
    # The last block might be padded, so we need to unpad it.
    decrypted_data = decryptor.decrypt(data)
    padding_length = decrypted_data[-1]
    return decrypted_data[:-padding_length]


def main():
    # The actual packed data is appended to this script by the packer.
    # We need to find where the script ends and the data begins.
    # This is a simple way to do it, but it's not very robust.
    with open(sys.executable, "rb") as f:
        # The packer will write a magic number to indicate the start of the data
        f.seek(-36, os.SEEK_END)  # 32 byte key + 4 byte size
        key_size = struct.unpack("<I", f.read(4))[0]
        f.seek(-(36 + key_size), os.SEEK_END)

        aes_key = f.read(key_size)

        f.seek(-16, os.SEEK_END)
        iv_size = struct.unpack("<I", f.read(4))[0]
        f.seek(-(16 + iv_size), os.SEEK_END)
        aes_iv = f.read(iv_size)

        f.seek(-(16 + iv_size + 4), os.SEEK_END)
        data_size = struct.unpack("<I", f.read(4))[0]
        f.seek(-(16 + iv_size + 4 + data_size), os.SEEK_END)
        packed_data = f.read(data_size)

    # Decrypt and decompress
    decrypted_data = decrypt_data(packed_data, aes_key, aes_iv)
    decompressed_data = decompress(list(decrypted_data))

    # Write to a temporary file and execute
    fd, temp_path = tempfile.mkstemp(suffix=".exe")
    os.write(fd, decompressed_data.encode("latin-1"))
    os.close(fd)

    # Make the file executable
    os.chmod(temp_path, 0o755)

    # Run the executable
    subprocess.run([temp_path], check=True)

    # Clean up the temporary file
    os.remove(temp_path)


if __name__ == "__main__":
    main()
