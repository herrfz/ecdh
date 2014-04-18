# Echo server program
import socket
import time
from bitarray import bitarray
from ECDiffieHellman import ECDH

HOST = ''                 # Symbolic name meaning all available interfaces
PORT = 50008              # Arbitrary non-privileged port
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((HOST, PORT))

while True:
    data, addr = sock.recvfrom(1024)
    if not data: break

    ba = bitarray()
    ba.frombytes(data)

    other_key = tuple([int(x, 2) for x in [ba[:256].to01(), ba[256:].to01()]])

    dh = ECDH()

    if dh.check_public_key(other_key):
        dh.gen_private_key()
        dh.gen_public_key()
        ser_pub_key = bitarray(''.join(['{0:0256b}'.format(x) 
            for x in dh.public_key])).tobytes()    
        sock.sendto(ser_pub_key, addr)
        #time.sleep(3)  # simulate computation delay
        dh.gen_secret(other_key)
        print dh.shared_secret

    else:
        sock.sendto('key error', addr)
        print 'key error'

sock.close()