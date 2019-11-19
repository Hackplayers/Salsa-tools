import base64
import gzip
import array
import sys
import io

banner = """
  ______                             _            
 |  ____|                           | |           
 | |__   _ __   ___ _ __ _   _ _ __ | |_ ___ _ __ 
 |  __| | '_ \ / __| '__| | | | '_ \| __/ _ \ '__|
 | |____| | | | (__| |  | |_| | |_) | ||  __/ |   
 |______|_| |_|\___|_|   \__, | .__/ \__\___|_|   
     /\                   __/ | || |   | |        
    /  \   ___ ___  ___ _|___/|_|| |__ | |_   _   
   / /\ \ / __/ __|/ _ \ '_ ` _ \| '_ \| | | | |  
  / ____ \\__  \__ \  __/ | | | | | |_) | | |_| |  
 /_/    \_\___/___/\___|_| |_| |_|_.__/|_|\__, |  
                                           __/ |  
                                          |___/   
									
				by: CyberVaca@HackPlayers
"""

print(banner)

if len(sys.argv) != 4:
    print("Usage: {!s} <FILE> <PASSWORD> <OUTPUT_FILE>".format((sys.argv[0])))
    sys.exit(0)

FILE = sys.argv[1]
PASSWORD = sys.argv[2]
OUTPUT = sys.argv[3]


def crypt(key, data):
    S = list(range(256))
    j = 0

    for i in list(range(256)):
        j = (j + S[i] + ord(key[i % len(key)])) % 256
        S[i], S[j] = S[j], S[i]

    j = 0
    y = 0
    out = []

    for char in data:
       j = (j + 1) % 256
       y = (y + S[j]) % 256
       S[j], S[y] = S[y], S[j]
       out.append(char ^ S[(S[j] + S[y]) % 256])
       
    return out

def lee_archivo(path):

    f = open(path, "rb") # read binary data
    s = f.read() # read all bytes into a string
    return array.array("B", s) # "f" for float

def write_archivo(path, encriptado):
    out_file = open(path, "wb") 
    out_file.write(encriptado)
    out_file.close()


def ByteToHex (bytestring):
    s = ''.join('{:02x}'.format(x) for x in bytestring)
    return s

def gzipstream ( string ):
	out = io.BytesIO()
	with gzip.GzipFile(fileobj=out, mode='w') as fo:
		fo.write(string.encode())
	bytes_obj = out.getvalue()
	return base64.b64encode(bytes_obj)
#salida = [ord(char) for char in encriptado]

datos = lee_archivo(FILE)
key = [ord(char) for char in PASSWORD]
encriptado = crypt (PASSWORD, datos)
print("Password: ", PASSWORD)
print("RC4 Key: {!s}".format(key))
bytearray_encriptado = encriptado
hex_encriptado = ByteToHex(bytearray_encriptado)
payload_encriptado = gzipstream(hex_encriptado)
print("File Output: ", OUTPUT)
write_archivo(OUTPUT, payload_encriptado)


