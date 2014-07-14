# requires Python >3.2 due to more intuitive bytes handling
import socket
from binascii import hexlify
from ECDiffieHellman import ECDH

MCAST_GRP = '225.2.0.1'
MCAST_PORT = 4711

UDP_IP = '127.0.0.1'
UDP_PORT = 33201

m_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
m_sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

u_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u_sock.settimeout(5)
u_sock.bind((UDP_IP, UDP_PORT))

head = bytes([0x01,         # handle
              0x00,         # tx opts
              0x1c, 0xaa,   # sensor panid, little endian
              0x00, 0x00])  # sensor short addr, little endian

dh = ECDH()
# test private key (RFC 5114 test vector)
dh.private_key = int('814264145F2F56F2E96A8E337A1284993FAF432A5ABCE59E867B7291D507A3AF', 16)
dh.gen_public_key()

dap = b''.join([x.to_bytes(length=32, byteorder='big') 
    for x in dh.public_key])
# msdu = mID + pubkey
msdu = bytes([0x01]) + dap
mpdu = bytes([len(msdu)]) + msdu

REQ = bytes([0x17]) + head + mpdu
REQ = bytes([len(REQ)]) + REQ

try:
    m_sock.sendto(REQ, (MCAST_GRP, MCAST_PORT))
    print('sent data request: ', hexlify(REQ))

    CON, server = u_sock.recvfrom(1024)
    print(CON)

    IND, server = u_sock.recvfrom(1024)
    print(IND)

    #other_key = tuple([int.from_bytes(x, byteorder='big') 
    #    for x in [data[:32], data[32:]]])
    #
    #if dh.check_public_key(other_key):
    #    dh.gen_secret(other_key)
    #    print(hexlify(dh.gen_key()))
    #
    #else:
    #    print('key error')

except socket.timeout:
    print('protocol timeout')

finally:
    m_sock.close()
    u_sock.close()