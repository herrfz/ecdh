# requires Python >3.2 due to more intuitive bytes handling
import socket
from binascii import hexlify
from ECDiffieHellman import ECDH

HOST = 'localhost'          # The remote host
PORT = 50008                # The same port as used by the server
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.connect((HOST, PORT))

dh = ECDH()
ser_pub_key = b''.join([x.to_bytes(length=32, byteorder='big') 
    for x in dh.public_key])

sock.send(ser_pub_key)
data, server = sock.recvfrom(1024)

other_key = tuple([int.from_bytes(x, byteorder='big') 
    for x in [data[:32], data[32:]]])

if dh.check_public_key(other_key):
    dh.gen_secret(other_key)
    print(hexlify(dh.gen_key()))

else:
    print('key error')

sock.close()