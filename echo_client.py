# Echo client program
import socket

HOST = 'localhost'        # The remote host
PORT = 33400              # The same port as used by the server
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
msg = bytes([0x01, 0x03])
s.sendall(msg)
print('sent {} Bytes to {}'.format(len(msg), (HOST, PORT)))
data = s.recv(1024)
s.close()
print('Received', repr(data))