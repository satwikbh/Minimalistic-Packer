import pefile
import struct
from collections import defaultdict
import os
import random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random

class SectionDoublePError(Exception):
    pass

class Packer:
    
    def __init__(self):
        self.aeskey = Random.new().read(32)
        self.iv = Random.new().read(AES.block_size)
        random_generator = Random.new().read
        self.key = RSA.generate(1024, random_generator)
        
    def compress(self, uncompressed):
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
 
    def decompress(self, compressed):
        """Decompress a list of output ks to a string."""
        from cStringIO import StringIO
     
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
    
    def compress_main(self):
        '''
        This contains 
        1.) Compressor routine which will compress the data present in the sections and keep them in a list
        2.) Encryption routine which will encrypt  the sections and store it in a temp.enc file
        3.) Another encryption routine which will encrypt the key used in the encryption of the data
        
        '''
        self.compressed_list = []
        self.encrypted_list = defaultdict(list)
        
        self.data = ''
        self.sizeofdata = 0x00000000
        
        for each in self.pe.sections:
            if each.Name[:5] == '.rsrc':
                pass
            else:
                self.sizeofdata += len(self.pe.get_data(each.PointerToRawData, each.SizeOfRawData))
                self.data += str(self.pe.get_data(each.PointerToRawData, each.SizeOfRawData))
                self.sec = str(each)
                
                f = open('temp', 'w')
                print >> f, self.sec
                self.encrypt_file(self.aeskey, f.name)
                new_f_name = f.name + '.enc'
                f1 = open(new_f_name)
                s = ''
                for line in f1.readlines():
                    s += line
                self.encrypted_list[each.Name[:5]].append(s)
                self.encrypted_key = self.encrypt_key(self.aeskey)
                
        self.compressed_list.append(self.compress(self.data))
    
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
    
    def encrypt_key(self, aes_key):
        '''
        Encrypt the AES key used with RSA algorithm
        '''
        public_key = self.key.publickey()
        return public_key.encrypt(aes_key, 32)
    
    def decrypt_key(self, aes_key_cipher):
        '''
        Decrypt the AES key encrypted using the RSA Algorithm
        '''
        return self.decrypt_key(aes_key_cipher)
    
    def print_section_info(self, pe):
        for section in pe.sections:
            print section
    
    def Reserve_Header_space(self):
        """
        To make space for a new section header a buffer filled with nulls is added at the end of the headers. The buffer has the size of one file alignment.
        The data between the last section header and the end of the headers is copied to the new space (everything moved by the size of one file alignment).
        If any data directory entry points to the moved data the pointer is adjusted.
        """
        FileAlignment = self.pe.OPTIONAL_HEADER.FileAlignment
        SizeOfHeaders = self.pe.OPTIONAL_HEADER.SizeOfHeaders
        
        data = '\x00' * FileAlignment
        
        # Adding the null buffer.
        self.pe.__data__ = (self.pe.__data__[:SizeOfHeaders] + data + self.pe.__data__[SizeOfHeaders:])
        
        # computing the addr where all the sections end
        section_table_offset = (self.pe.DOS_HEADER.e_lfanew + 4 + self.pe.FILE_HEADER.sizeof() + self.pe.FILE_HEADER.SizeOfOptionalHeader)
        
        # copying the data between the end point of sections and the space reserved for sections
        new_section_offset = section_table_offset + self.pe.FILE_HEADER.NumberOfSections * 0x28
        size = SizeOfHeaders - new_section_offset
        data = self.pe.get_data(new_section_offset, size)
        self.pe.set_bytes_at_offset(new_section_offset + FileAlignment, data)
        
        # Fill the space with nulls
        self.pe.set_bytes_at_offset(new_section_offset, '\x00' * FileAlignment)
        data_directory_offset = section_table_offset - self.pe.OPTIONAL_HEADER.NumberOfRvaAndSizes * 0x8
        
        '''
        Checking data directories if anything points to the space between the last section header
        and the former SizeOfHeaders. If that's the case the pointer is increased by FileAlignment.
        '''
        for data_offset in xrange(data_directory_offset, section_table_offset, 0x8):
            data_rva = self.pe.get_dword_from_offset(data_offset)

            if new_section_offset <= data_rva and data_rva < SizeOfHeaders:
                self.pe.set_dword_at_offset(data_offset, data_rva + FileAlignment)
        
        SizeOfHeaders_offset = (self.pe.DOS_HEADER.e_lfanew + 4 + self.pe.FILE_HEADER.sizeof() + 0x3C)
        
        # Adjusting the size of headers value
        self.pe.set_dword_at_offset(SizeOfHeaders_offset, SizeOfHeaders + FileAlignment)
        section_raw_address_offset = section_table_offset + 0x14
        
        # The raw addresses of the sections are adjusted.
        for section in self.pe.sections:
            if section.PointerToRawData != 0:
                self.pe.set_dword_at_offset(section_raw_address_offset, section.PointerToRawData + FileAlignment)
                
            section_raw_address_offset += 0x28
            
        '''
        All changes in this method were made to the raw data (__data__). To make these changes
        accessbile in self.pe __data__ has to be parsed again. Since a new pefile is parsed during
        the init method, the easiest way is to replace self.pe with a new pefile based on __data__
        of the old self.pe.
        '''
        self.pe = pefile.PE(data=self.pe.__data__)
    
    def is_null_data(self, data):
        """
        Checks if the given data contains just null bytes.
        """
        for char in data:
            if char != '\x00':
                return False
        return True
    
    def push_back(self, Name=".NewSec", VirtualSize=0x00000000, VirtualAddress=0x00000000, RawSize=0x00000000, RawAddress=0x00000000, RelocAddress=0x00000000, Linenumbers=0x00000000, RelocationsNumber=0x0000, LinenumbersNumber=0x0000, Characteristics=0xE00000E0, Data=""):
        
        if self.pe.FILE_HEADER.NumberOfSections == len(self.pe.sections):
            
            FileAlignment = self.pe.OPTIONAL_HEADER.FileAlignment
            SectionAlignment = self.pe.OPTIONAL_HEADER.SectionAlignment
            
            if len(Name) > 8:
                raise SectionDoublePError("The Section Name cannot be >8 Bytes")
            else:
                if (VirtualAddress < (self.pe.sections[-1].Misc_VirtualSize + self.pe.sections[-1].VirtualAddress) or VirtualAddress % SectionAlignment != 0):
                    
                    if (self.pe.sections[-1].Misc_VirtualSize % SectionAlignment) != 0:
                        VirtualAddress = self.pe.sections[-1].Misc_VirtualSize + self.pe.sections[-1].VirtualAddress - (self.pe.sections[-1].Misc_VirtualSize % SectionAlignment) + SectionAlignment 
                    else:
                        VirtualAddress = self.pe.sections[-1].Misc_VirtualSize + self.pe.sections[-1].VirtualAddress
                    
                # TODO Check if length of data can be greater than V.Size
                if VirtualSize < len(Data) and VirtualSize == 0x00000000:
                    VirtualSize = len(Data)
                                
                # Since the page size is 4096 we need to perform padding 
                if (len(Data) % FileAlignment) != 0:
                    Data += '\x00' * (FileAlignment - (len(Data) % FileAlignment))
                    
                # s
                if RawSize != len(Data) :
                    # If Size is greater than entered data the pad bits 
                    if RawSize > len(Data):
                        if RawSize % FileAlignment == 0:
                            Data += '\x00' * (RawSize - (len(Data) % RawSize))
                    # else just change size to length
                    else:
                        RawSize = len(Data)
                
                '''
                The section offset is nothing but the size of all the headers such as NT header (e_lfanew), File Header, Optional Header
                '''
                section_table_offset = self.pe.DOS_HEADER.e_lfanew + 4 + self.pe.FILE_HEADER.sizeof() + self.pe.FILE_HEADER.SizeOfOptionalHeader
                
                '''
                We now need to allocate the new section size.
                The standard section size is 0x28 and incase if we give more than that then we need to pad it or use null
                '''
                
                if (self.pe.OPTIONAL_HEADER.SizeOfHeaders < section_table_offset + (self.pe.FILE_HEADER.NumberOfSections + 1) * 0x28 
                    or not self.is_null_data(self.pe.get_data(section_table_offset + (self.pe.FILE_HEADER.NumberOfSections) * 0x28, 0x28))):
                    
                    if self.pe.OPTIONAL_HEADER.SizeOfHeaders < self.pe.sections[0].VirtualAddress:
                        self.Reserve_Header_space()
                        print "Additional space to add a new section reserved"
                        print "Number of more sections that can be added space runs out is : " , (self.pe.OPTIONAL_HEADER.SizeOfHeaders - (section_table_offset + (self.pe.FILE_HEADER.NumberOfSections) * 0x28)) % 0x28
                    else:
                        raise SectionDoublePError("No more space can be added for the section header.")
                
                # If nothing is changed then the RawAddress would be the sum of Pointer to Raw Data and Size of Raw Data of the last Section
                if RawAddress != (self.pe.sections[-1].PointerToRawData + self.pe.sections[-1].SizeOfRawData):
                    RawAddress = (self.pe.sections[-1].PointerToRawData + self.pe.sections[-1].SizeOfRawData)
                
                '''
                Now we will append data of the new Section to the file
                '''
                if len(Data) > 0:
                    self.pe.__data__ = (self.pe.__data__[:RawAddress] + Data + self.pe.__data__[RawAddress:])
                
                section_offset = section_table_offset + self.pe.FILE_HEADER.NumberOfSections * 0x28
                
                '''
                Now we fill the section entries manually
                The values are constant and can be seen in the PE Section Header
                '''

                self.pe.set_bytes_at_offset(section_offset, Name)
                self.pe.set_dword_at_offset(section_offset + 0x08, VirtualSize)
                self.pe.set_dword_at_offset(section_offset + 0x0C, VirtualAddress)
                self.pe.set_dword_at_offset(section_offset + 0x10, RawSize)
                
                # Since we calculated Pointer + Size here this will become Pointer to Raw Data
                self.pe.set_dword_at_offset(section_offset + 0x14, RawAddress)
                self.pe.set_dword_at_offset(section_offset + 0x18, RelocAddress)
                self.pe.set_dword_at_offset(section_offset + 0x1C, Linenumbers)
                self.pe.set_word_at_offset(section_offset + 0x20, RelocationsNumber)
                self.pe.set_word_at_offset(section_offset + 0x22, LinenumbersNumber)
                self.pe.set_dword_at_offset(section_offset + 0x24, Characteristics)
                
                # Increase count of the sections
                self.pe.FILE_HEADER.NumberOfSections += 1
                
                # Parsing the section table of the file again to add the new section to the sections list of pefile.
                self.pe.parse_sections(section_table_offset)
                self.adjust_optional_header()
            
        else:
            raise SectionDoublePError("The Number of Sections in PE FileHeader and No of section is PE donot match")
        
        return self.pe
    
    def adjust_optional_header(self):
        '''
        Recalculate the SizeOfImage, SizeOfCode, SizeOfInitialized data & SizeOfUninitialized data in the optional header.
        '''
        self.pe.OPTIONAL_HEADER.SizeOfImage = (self.pe.sections[-1].VirtualAddress + self.pe.sections[-1].Misc_VirtualSize)
        self.pe.OPTIONAL_HEADER.SizeOfCode = 0
        self.pe.OPTIONAL_HEADER.SizeOfInitializedData = 0
        self.pe.OPTIONAL_HEADER.SizeOfUninitializedData = 0
        
        '''
        Recalculating the sizes by iterating through all the sections and checking if the characteristics are set
        '''
        for section in self.pe.sections:
            if section.Characteristics & 0x00000020:
                # Section contains code. this can be obtained by the flags and each flag represents the addr 
                # like 0x20 represents the Size of Code and 0x40 represents Initialized data
                self.pe.OPTIONAL_HEADER.SizeOfCode += section.SizeOfRawData
            if section.Characteristics & 0x00000040:
                self.pe.OPTIONAL_HEADER.SizeOfInitializedData += section.SizeOfRawData
            if section.Characteristics & 0x00000080:
                self.pe.OPTIONAL_HEADER.SizeOfUninitializedData += section.SizeOfRawData
    
    def remove_last(self):
        if (self.pe.FILE_HEADER.NumberOfSections > 0 and self.pe.FILE_HEADER.NumberOfSections == len(self.pe.sections)):
            if (self.pe.sections[-1] != 0):
                self.pe.__data__ = (self.pe.__data__[:self.pe.sections[-1].PointerToRawData] + self.pe.__data__[(self.pe.sections[-1].PointerToRawData + self.pe.sections[-1].SizeOfRawData):])
            
            self.pe.sections[-1].Name = '\x00' * 8
            self.pe.sections[-1].Misc_VirtualSize = 0x00000000
            self.pe.sections[-1].VirtualAddress = 0x00000000
            self.pe.sections[-1].SizeOfRawData = 0x00000000
            self.pe.sections[-1].PointerToRawData = 0x00000000
            self.pe.sections[-1].PointerToRelocations = 0x00000000
            self.pe.sections[-1].PointerToLinenumbers = 0x00000000
            self.pe.sections[-1].Characteristics = 0x00000000
            
            self.pe.sections.pop()
            
            self.pe.FILE_HEADER.NumberOfSections -= 1
            self.adjust_optional_header()
        else:
            raise SectionDoublePError('There is no Section to pop')
    
    def remove(self, number):
        
        counter = 0
        self.frag_size_of_code = 0x0
        self.frag_size_of_init_data = 0x0
        self.frag_size_of_uninit_data = 0x0
        
        while (len(self.pe.sections) - number - counter - 1) > 0:
            
            for x in xrange(number):
                if self.pe.sections[x].Characteristics & 0x00000020:
                    self.frag_size_of_code += self.pe.sections[x].SizeOfRawData
            
            '''
            First rename the target section with next section so that the last section can be easily removed.
            '''
                    
            if counter == 0 and number == 0:
                self.pe.sections[counter].VirtualAddress = self.pe.OPTIONAL_HEADER.BaseOfCode
            else:
                VA = self.pe.sections[counter - 1].VirtualAddress
                MVS = self.pe.sections[counter - 1].Misc_VirtualSize
                SA = self.pe.OPTIONAL_HEADER.SectionAlignment
                VSS = SA - ((VA + MVS) % SA) + (VA + MVS)
                self.pe.sections[number + counter].VirtualAddress = VSS
            
            self.pe.sections[number + counter].Name = self.pe.sections[number + counter + 1].Name 
            self.pe.sections[number + counter].Misc = self.pe.sections[number + counter + 1].Misc
            self.pe.sections[number + counter].Misc_PhysicalAddress = self.pe.sections[number + counter + 1].Misc_PhysicalAddress 
            self.pe.sections[number + counter].Misc_VirtualSize = self.pe.sections[number + counter + 1].Misc_VirtualSize
            self.pe.sections[number + counter].SizeOfRawData = self.pe.sections[number + counter + 1].SizeOfRawData

            if counter == 0 and number == 0:
                # Check
                # self.pe.sections[counter].PointerToRawData = self.pe.OPTIONAL_HEADER.SizeOfHeaders + self.pe.sections[number + counter].SizeOfRawData
                self.pe.sections[counter].PointerToRawData = self.pe.OPTIONAL_HEADER.SizeOfHeaders
            else:
                self.pe.sections[number + counter].PointerToRawData = self.pe.sections[number + counter - 1].PointerToRawData + self.pe.sections[number + counter - 1].SizeOfRawData
            self.pe.sections[number + counter].PointerToRelocations = self.pe.sections[number + counter + 1].PointerToRelocations 
            self.pe.sections[number + counter].PointerToLinenumbers = self.pe.sections[number + counter + 1].PointerToLinenumbers
            self.pe.sections[number + counter].NumberOfRelocations = self.pe.sections[number + counter + 1].NumberOfRelocations
            self.pe.sections[number + counter].NumberOfLinenumbers = self.pe.sections[number + counter + 1].NumberOfLinenumbers
            
            if self.pe.sections[number + counter].Characteristics & 0x00000020:
                
                self.frag_size_of_code += self.pe.sections[number + counter].SizeOfRawData
                self.pe.OPTIONAL_HEADER.BaseOfCode = self.pe.sections[number + counter].VirtualAddress
            
            if self.pe.sections[number + counter].Characteristics & 0x00000040:
                self.pe.OPTIONAL_HEADER.BaseOfData = self.pe.sections[number + counter].VirtualAddress
            
            if self.pe.sections[number + counter].Characteristics & 0x00000040:
                self.pe.OPTIONAL_HEADER.SizeOfUninitializedData = self.pe.sections[number + counter].Misc_VirtualSize
            
            self.pe.sections[number + counter].Characteristics = self.pe.sections[number + counter + 1].Characteristics
            
            '''
            Now set the DataDirectories part to the modified value
            '''
            for each in self.pe.OPTIONAL_HEADER.DATA_DIRECTORY:
                if each.VirtualAddress == 0x0:
                    pass
                else:
                    
                    if self.pe.sections[number + counter].Name == '.tls':
                        self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[9].VirtualAddress = self.pe.sections[number + counter].VirtualAddress
                    
                    if self.pe.sections[number + counter].Name[:6] == '.idata':
                        self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress = self.pe.sections[number + counter].VirtualAddress
                        self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[12].VirtualAddress = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress + self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].Size + self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[12].Size
                    
                    if self.pe.sections[number + counter].Name[:6] == '.reloc':
                        self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].VirtualAddress = self.pe.sections[number + counter].VirtualAddress
                    
                    if self.pe.sections[number + counter].Name[:6] == '.rdata':
                        self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].VirtualAddress = self.pe.sections[number + counter].VirtualAddress + self.pe.sections[number + counter].PointerToRawData
                    
                    if self.pe.sections[number + counter].Name[:5] == '.rsrc':
                        self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].VirtualAddress = self.pe.sections[number + counter].VirtualAddress
            
            counter += 1
        
        self.remove_last()    
        
        # TODO Set the SizeOfInitializedData and Uninitialized Data
        
        self.pe.OPTIONAL_HEADER.SizeOfCode = self.frag_size_of_code
        self.pe.OPTIONAL_HEADER.SizeOfImage = (self.pe.OPTIONAL_HEADER.SectionAlignment - (self.pe.sections[-1].VirtualAddress + self.pe.sections[-1].SizeOfRawData) % self.pe.OPTIONAL_HEADER.SectionAlignment) + (self.pe.sections[-1].VirtualAddress + self.pe.sections[-1].SizeOfRawData)
        self.pe.OPTIONAL_HEADER.SizeOfHeaders = (self.pe.OPTIONAL_HEADER.FileAlignment - (self.pe.DOS_HEADER.e_lfanew + 0x4 + self.pe.FILE_HEADER.sizeof() + self.pe.OPTIONAL_HEADER.sizeof() + (0x8 * self.pe.OPTIONAL_HEADER.NumberOfRvaAndSizes) + (self.pe.FILE_HEADER.NumberOfSections) * 0x28) % self.pe.OPTIONAL_HEADER.FileAlignment) + (self.pe.DOS_HEADER.e_lfanew + 0x4 + self.pe.FILE_HEADER.sizeof() + self.pe.OPTIONAL_HEADER.sizeof() + (0x8 * self.pe.OPTIONAL_HEADER.NumberOfRvaAndSizes) + (self.pe.FILE_HEADER.NumberOfSections) * 0x28)
        self.pe.OPTIONAL_HEADER.SizeOfInitializedData = 0x9c00
        
        # Just for now setting OEP to 1 section
        self.pe.OPTIONAL_HEADER.AddressOfEntryPoint = self.pe.sections[0].VirtualAddress    
        
    def main(self):
        self.pe = pefile.PE('calc.exe')
        
        # Initially raw_size is zero and we sumup the raw_sizes accordingly except that of Resource section
        RawSize_now = 0x0
        for each in self.pe.sections:
            if each.Name[:5] == '.rsrc':
                pass
            else:
                RawSize_now += each.SizeOfRawData
        
        # Step 1: Compress and encrypt all sections and section data except .rsrc
        self.compress_main()
        
        self.remove(1)

        self.pe.write('pe.exe')
        
        self.pe = pefile.PE('pe.exe')
        # Step 3: Changes the name of the .rsrc section to .mpx0 section
        for each in self.pe.sections:
            if each.Name[:5] == '.rsrc':
                each.Name = each.Name.replace('.rsrc', '.mpx0')
        
        va_now = self.pe.OPTIONAL_HEADER.SectionAlignment - (self.pe.sections[-1].VirtualAddress + self.pe.sections[-1].Misc_VirtualSize) % self.pe.OPTIONAL_HEADER.SectionAlignment + self.pe.sections[-1].VirtualAddress + self.pe.sections[-1].Misc_VirtualSize
        pointer_to_rawdata = self.pe.sections[-1].PointerToRawData + self.pe.sections[-1].SizeOfRawData
        # Check
        Encrypt_Size = 0x00000000
        
        print len(self.encrypted_list.values())
        for each in self.encrypted_list.values():
            Encrypt_Size += len(each[0])
        
        data = ''
        
        for each in self.compressed_list[0]:
            data += str(each)
        # Step 4:Create the required number of sections
        # Check Encrypt_Size is the size of the Encrypted sections which is nothing but the Virtual Size here
        
        # Empty Section
        self.push_back('.mpx1', self.sizeofdata + RawSize_now , va_now, 0x00000000 , pointer_to_rawdata, 0x00000000, 0x00000000, 0x0000, 0x0000, Characteristics=0xE0000080)
        
        # Compressed data sections
        self.push_back('.mpx2', 0x00000000, 0x00000000, 0x00000000, pointer_to_rawdata, 0x00000000, 0x00000000, 0x0000, 0x0000, Characteristics=0x60000020, Data=data)
        
        data = ''
        for each in self.encrypted_list.values():
            data += str(each[0])
        
        # Encrypted Sections
        self.push_back('.mpx3', 0x00000000, 0x00000000, 0x00000000, pointer_to_rawdata, 0x00000000, 0x00000000, 0x0000, 0x0000, Characteristics=0x60000020, Data=data)
        
        # Decompressed section data and Decrypted sections
        self.push_back('.mpx4')
         
        for each in self.pe.sections:
            print each.Name
            print 
            
        self.pe.write('pe.exe')
       
if __name__ == "__main__":
    pack = Packer()
    pack.main()
