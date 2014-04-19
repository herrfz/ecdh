# requires Python >3.2 due to more intuitive bytes handling
import socket
import struct
from binascii import hexlify
from ECDiffieHellman import ECDH

HOST = 'localhost'          # The remote host
PORT = 50008                # The same port as used by the server
multicast_group = ('224.3.29.71', PORT)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(1)
ttl = struct.pack('b', 1)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
#sock.connect((HOST, PORT))

dh = ECDH()
ser_pub_key = b''.join([x.to_bytes(length=32, byteorder='big') 
    for x in dh.public_key])

try:
    sent = sock.sendto(ser_pub_key, multicast_group)

    data, server = sock.recvfrom(1024)

    other_key = tuple([int.from_bytes(x, byteorder='big') 
        for x in [data[:32], data[32:]]])

    if dh.check_public_key(other_key):
        dh.gen_secret(other_key)
        print(hexlify(dh.gen_key()))

    else:
        print('key error')

except socket.timeout:
    print('protocol timeout')

finally:
    sock.close()