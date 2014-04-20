# requires Python >3.2 due to more intuitive bytes handling
import socket
import struct
import sys
from binascii import hexlify
from ECDiffieHellman import ECDH

MCAST_GRP = '224.1.1.1'
MCAST_PORT = 5007

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
sock.bind(('', MCAST_PORT))
mreq = struct.pack("4sl", socket.inet_aton(MCAST_GRP), socket.INADDR_ANY)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

while True:
    try:
        data, addr = sock.recvfrom(1024)

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

    except KeyboardInterrupt:
        sock.close()
        sys.exit()