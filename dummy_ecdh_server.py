# requires Python >3.2 due to more intuitive bytes handling
import socket
from binascii import hexlify
from ECDiffieHellman import ECDH

MCAST_GRP = '224.0.0.10'
MCAST_PORT = 4711

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.settimeout(5)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

dh = ECDH()

ser_pub_key = bytearray(66)
ser_pub_key[0] = 65
ser_pub_key[1] = 0x19
ser_pub_key[2:] = b''.join([x.to_bytes(length=32, byteorder='big') 
    for x in dh.public_key])

try:
    sent = sock.sendto(ser_pub_key, (MCAST_GRP, MCAST_PORT))

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