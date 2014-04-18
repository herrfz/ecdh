# Echo client program
import socket
from bitarray import bitarray
from ECDiffieHellman import ECDH

HOST = 'localhost'    # The remote host
PORT = 50008              # The same port as used by the server
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.connect((HOST, PORT))

dh = ECDH()
ser_pub_key = bitarray(''.join(['{0:0256b}'.format(x) 
    for x in dh.public_key])).tobytes()

sock.send(ser_pub_key)
data, server = sock.recvfrom(1024)

ba = bitarray()
ba.frombytes(data)

other_key = tuple([int(x, 2) for x in [ba[:256].to01(), ba[256:].to01()]])

if dh.check_public_key(other_key):
    dh.gen_secret(other_key)
    print dh.shared_secret
else:
    print 'key error'

sock.close()