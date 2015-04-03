import pefile
import Crypto
import rsa

(pub_key, priv_key) = rsa.newkeys(1024)

def compress(uncompressed):
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
 
 
def decompress(compressed):
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
 
''' 
How to use:
compressed = compress('TOBEORNOTTOBEORTOBEORNOT')
print (compressed)
decompressed = decompress(compressed)
print (decompressed)
'''

f = open('same.txt', 'w')

pe = pefile.PE('try.exe')

section_list = []

for section in pe.sections:
	if section.Name[:5] == '.rsrc':
		# Just rename it as new section and do nothing
		section.Name.replace('.rsrc', '.mx5')
	else:
		section_list.append(str(section))

compressed_list = []
comp_data = []

section_table_offset = pe.DOS_HEADER.e_lfanew + 4 + pe.FILE_HEADER.sizeof() + pe.FILE_HEADER.SizeOfOptionalHeader

section_counter = 0

for each in pe.sections:
	compressed_list.append(compress(str(each)))
	# comp_data.append(compress(str(pe.get_data(each.PointerToRawData))))
	section_counter += 1
	
	print each.Name
	data_len = len(str(pe.get_data(each.PointerToRawData)))
	
	if data_len % 16 == 0:
		# pass to function
		Crypto().encrypt_file(pub_key, , out_filename, chunksize)
	else:
		16 - (data_len % 16) + data_len
	
	

'''
Compress the entire sections into string
Create as many sections as there were earlier (to do this store the Number of sections before hand) while decompressing
Now we re-create each and every section using the information available in the decompressed string using the create section from push_back.

As for data we will do encryption of data not compression
'''

	
	