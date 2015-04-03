import pefile
import os
from pefile import FileAlignment_Warning

class SectionDoublePError(Exception):
    pass

class Packer():
    
    def __init__(self, pe):
        self.pe = pe
        if (pe.is_dll() or pe.is_driver()) == True and pe.is_exe() == False:
            print "This packer works only for Executables not for dll or drivers"
            SystemExit(0)
            
    def is_null_data(self, char1):
        for x in char1:
            if x != '\x00':
                return False
            return True
        
    def adjust_Optional_Header(self):
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
        data = pe.get_data(new_section_offset, size)
        pe.set_bytes_at_offset(new_section_offset + FileAlignment, data)
        
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
        for sections in self.pe.sections:
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
    
    def print_section_info(self, pe):
        for section in pe.sections:
            print section
        
        # If you don't have pydasm installed comment the rest of the function out.
        '''
        print "The instructions at the beginning of the last section:"
        
        ep = pe.sections[-1].VirtualAddress
        ep_ava = ep+pe.OPTIONAL_HEADER.ImageBase
        data = pe.get_memory_mapped_image()[ep:ep+6]
        offset = 0
        while offset < len(data):
            i = pydasm.get_instruction(data[offset:], pydasm.MODE_32)
            print pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, ep_ava+offset)
            offset += i.length
        '''
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
                if VirtualSize < len(Data):
                    VirtualSize = len(Data)
                
                # Since the page size is 4096 we need to perform padding 
                if (len(Data) % FileAlignment) != 0:
                    Data += '\x00' * (FileAlignment - (len(Data) % FileAlignment))
                    
                # s
                if RawSize != len(Data):
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
                        print "Number of more sections that can be added space runs out is : " , (pe.OPTIONAL_HEADER.SizeOfHeaders - (section_table_offset + (pe.FILE_HEADER.NumberOfSections) * 0x28)) % 0x28
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
                self.adjust_Optional_Header()
            
        else:
            raise SectionDoublePError("The Number of Sections in PE FileHeader and No of section is PE donot match")
        
        return self.pe
    
    def remove(self):
        '''
        Remove the last section in the section table, Deletes the contents i.e, the data, section header 
        Then it adjusts the optional header. 
        '''
        if (self.pe.FILE_HEADER.NumberOfSections > 0) and (self.pe.FILE_HEADER.NumberOfSections == len(self.pe.sections)):
            
            # Remove the data of the particular section from the file.
            if self.pe.sections[-1].SizeOfRawData != 0:
                self.pe.__data__ = (self.pe.__data__[:self.pe.sections[-1].PointerToRawData] + self.pe.__data__[(self.pe.sections[-1].PointerToRawData + self.pe.sections[-1].SizeOfRawData):])
            
            # rewriting the section header with null
            self.pe.sections[-1].Name = '\x00' * 8
            self.pe.sections[-1].Misc_VirtualSize = 0x00000000
            self.pe.sections[-1].VirtualAddress = 0x00000000
            self.pe.sections[-1].SizeOfRawData = 0x00000000
            self.pe.sections[-1].PointerToRawData = 0x00000000
            self.pe.sections[-1].PointerToRelocations = 0x00000000
            self.pe.sections[-1].PointerToLinenumbers = 0x00000000
            self.pe.sections[-1].NumberOfRelocations = 0x0000
            self.pe.sections[-1].NumberOfLinenumbers = 0x0000
            self.pe.sections[-1].Characteristics = 0x00000000
            
            self.pe.sections.pop()
            
            self.pe.FILE_HEADER.NumberOfSections -= 1
            
            self.adjust_Optional_Header()
            
        else:
            raise SectionDoublePError("There's no section to pop.")            
            
def main():
    pe = pefile.PE('try.exe')
    packer = Packer(pe)
    packer.__init__(pe)

    print 'Enter 1 to add' , '\n' , '2 to remove section' , '\n'
    addFlag = int(raw_input())

    # why exactly this is it random or something else
    data = "\xE9\xDA\xF4\xFC\xFF\x89"
    
    try:
        '''
        you can add till max no. of sections limit is reached
        you can also change the characteristics based on how the section is to be ex: write or read Initialized data or UnInitialized data etc.,
        '''
        if addFlag == 1:
        	pe = packer.push_back(Name='.mp1', Characteristics=0x60000020, Data=data)
    	elif addFlag == 2:
	    	print "Just popped a section"
	    	packer.remove()
    	else:
	    	print "Enter 1 or 2 not other values"
	    	exit(0)
    except SectionDoublePError as e:
    	print e
    
    print "\nInformation on every section after one of the added sections has been added:"
    
    #packer.print_section_info(pe)
    
    # print the just added section
    print pe.sections[-1]
    
    # To check what is present in the data field
    # print int(pe.get_data(pe.sections[-1].PointerToRawData,10))
    
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = pe.sections[-1].VirtualAddress
    
    pe.write(filename='modified_write.exe')    

if __name__ == "__main__":
    main()

