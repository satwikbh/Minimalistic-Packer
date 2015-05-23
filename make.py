import pefile

pe = pefile.PE('pe.exe')

f = open('pe.txt','w')

print >> f, pe.dump_info()

f.close()
