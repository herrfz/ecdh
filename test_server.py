# requires Python >3.2 due to more intuitive bytes handling
import socket
from binascii import hexlify
from ECDiffieHellman import ECDH

HOST = ''                 # Symbolic name meaning all available interfaces
PORT = 50008              # Arbitrary non-privileged port
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((HOST, PORT))

while True:
    data, addr = sock.recvfrom(1024)
    if not data: break

    other_key = tuple([int.from_bytes(x, byteorder='big') 
        for x in [data[:32], data[32:]]])

    dh = ECDH()

    if dh.check_public_key(other_key):
        dh.gen_private_key()
        dh.gen_public_key()
        ser_pub_key = b''.join([x.to_bytes(length=32, byteorder='big') 
            for x in dh.public_key])

        sock.sendto(ser_pub_key, addr)

        dh.gen_secret(other_key)
        print(hexlify(dh.gen_key()))

    else:
        sock.sendto(bytes('key error', 'UTF-8'), addr)
        print('key error')

sock.close()