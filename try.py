from Crypto.PublicKey import RSA
from collections import defaultdict
from Crypto.Cipher import AES
from cStringIO import StringIO
from Crypto import Random
import pefile
import struct
import random
import os

class Cryption:


    def __init__(self):
        self.aeskey = Random.new().read(32)
        self.iv = Random.new().read(AES.block_size)
        random_generator = Random.new().read
        self.key = RSA.generate(1024, random_generator)
        '''
        #include the below lines incase others fail and download the respective package
        (pub_key, priv_key) = rsa.newkeys(1024)
        self.pub_key = pub_key
        self.priv_key = priv_key
        '''
 
    
    def encrypt_file(self, key, in_filename, out_filename=None, chunksize=64 * 1024):
        """ Encrypts a file using AES (CBC mode) with the
            given key.
    
            key:
                The encryption key - a string that must be
                either 16, 24 or 32 bytes long. Longer keys
                are more secure.
    
            in_filename:
                Name of the input file
    
            out_filename:
                If None, '<in_filename>.enc' will be used.
    
            chunksize:
                Sets the size of the chunk which the function
                uses to read and encrypt the file. Larger chunk
                sizes can be faster for some files and machines.
                chunksize must be divisible by 16.
        """
        if not out_filename:
            out_filename = in_filename + '.enc'
    
        iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
        encryptor = AES.new(key, AES.MODE_CBC, iv)
        filesize = os.path.getsize(in_filename)
    
        with open(in_filename, 'rb') as infile:
            with open(out_filename, 'wb') as outfile:
                outfile.write(struct.pack('<Q', filesize))
                outfile.write(iv)
    
                while True:
                    chunk = infile.read(chunksize)
                    if len(chunk) == 0:
                        break
                    elif len(chunk) % 16 != 0:
                        chunk += ' ' * (16 - len(chunk) % 16)
    
                    outfile.write(encryptor.encrypt(chunk))
 
    
    def decrypt_file(self, key, in_filename, out_filename=None, chunksize=24 * 1024):
        """ Decrypts a file using AES (CBC mode) with the
            given key. Parameters are similar to encrypt_file,
            with one difference: out_filename, if not supplied
            will be in_filename without its last extension
            (i.e. if in_filename is 'aaa.zip.enc' then
            out_filename will be 'aaa.zip')
        """
        if not out_filename:
            out_filename = os.path.splitext(in_filename)[0]
    
        with open(in_filename, 'rb') as infile:
            origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
            iv = infile.read(16)
            decryptor = AES.new(key, AES.MODE_CBC, iv)
    
            with open(out_filename, 'wb') as outfile:
                while True:
                    chunk = infile.read(chunksize)
                    if len(chunk) == 0:
                        break
                    outfile.write(decryptor.decrypt(chunk))
    
                outfile.truncate(origsize)
 
        
    def encrypt_string(self,msg):
        encryption_suite = AES.new(self.aeskey, AES.MODE_CFB, self.iv)
        enc_text = encryption_suite.encrypt(msg)
        return enc_text
 
    
    def decrypt_string(self,pinch):
        decryption_suite = AES.new(self.aeskey, AES.MODE_CFB, self.iv)
        dec_text = decryption_suite.decrypt(pinch)
        return dec_text
 
    
    def encrypt_key(self,aes_key):
        public_key = self.key.publickey()
        return public_key.encrypt(aes_key,32)


    def decrypt_key(self,aes_key_cipher):
        return self.key.decrypt(aes_key_cipher)
  
    
    def compress(self,uncompressed):
        """Compress a string to a list of output symbols."""
     
        # Build the dictionary.
        dict_size = 256
        dictionary = dict((chr(i), chr(i)) for i in xrange(dict_size))
        # in Python 3: dictionary = {chr(i): chr(i) for i in range(dict_size)}
     
        w = ""
        result = []
        for c in uncompressed:
            wc = w + c
            if wc in dictionary:
                w = wc
            else:
                result.append(dictionary[w])
                # Add wc to the dictionary.
                dictionary[wc] = dict_size
                dict_size += 1
                w = c
     
        # Output the code for w.
        if w:
            result.append(dictionary[w])
        return result
 
 
    def decompress(self,compressed):
        """Decompress a list of output ks to a string."""
     
        # Build the dictionary.
        dict_size = 256
        dictionary = dict((chr(i), chr(i)) for i in xrange(dict_size))
        # in Python 3: dictionary = {chr(i): chr(i) for i in range(dict_size)}
     
        # use StringIO, otherwise this becomes O(N^2)
        # due to string concatenation in a loop
        result = StringIO()
        w = compressed.pop(0)
        result.write(w)
        for k in compressed:
            if k in dictionary:
                entry = dictionary[k]
            elif k == dict_size:
                entry = w + w[0]
            else:
                raise ValueError('Bad compressed k: %s' % k)
            result.write(entry)
     
            # Add w+entry[0] to the dictionary.
            dictionary[dict_size] = w + entry[0]
            dict_size += 1
     
            w = entry
        return result.getvalue()
    
        
    def main(self):
        pe = pefile.PE('try.exe','w')
        #print self.encrypt_string('x')
        #print self.decrypt_string(self.encrypt_string('x'))
        #print self.encrypt_key(self.aeskey)
        #print self.decrypt_key(self.encrypt_key(self.aeskey))
        
        compressed_list = []
        encrypted_list = defaultdict(list)
        
        for each in pe.sections:
            if each.Name[:5] == '.rsrc':
                #Just rename the section name so that it will be the first section
                each.Name.replace('.rsrc','.mpx1')
            else:
                compressed_list.append(self.compress(str(each)))
            data = str(pe.get_data(each.PointerToRawData))
            f = open('temp','w')
            print >> f, data
            self.encrypt_file(self.aeskey,f.name)
            new_f_name = f.name + '.enc'
            f1 = open(new_f_name)
            s = ''
            for line in f1.readlines():
                s+=line
            #Used dictionary so that there will be a mapping from each file to content of file
            encrypted_list[each.Name[:5]].append(s)
            #Decryption shud be performed in such a way that there shud be no usage of files for it
            #Hence, use the dict again to store data before encryption
            self.decrypt_file(self.aeskey,new_f_name,'decomp.txt')


if __name__ == '__main__':
    cry = Cryption()
    cry.main()
