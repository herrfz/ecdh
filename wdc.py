import os
import socket
import struct
import logging
import argparse
import threading
from binascii import hexlify
from ECDiffieHellman import ECDH

TCP_PORT = 33400
TCP_RX_BUFFER_SIZE = 64
UDP_RX_BUFFER_SIZE = 256

BUSY_CONNECTED = 0x01
CONNECTING = 0x02
WRONG_CMD = 0x03

# messages
# WDC_GET_STATUS_RES
wdc_get_status_res = bytearray(64)
wdc_get_status_res[0] = 10  # ??? TODO
wdc_get_status_res[1] = 0x06
# WDC_DISCONNECTION_REQ
wdc_disconnection_req = bytearray(2)
wdc_disconnection_req[0] = 1  # ??? TODO
wdc_disconnection_req[1] = 0x03
# WDC_DISCONNECTION_REQ_ACK
wdc_disconnection_req_ack = bytearray(2)
wdc_disconnection_req_ack[0] = 1  # ??? TODO
wdc_disconnection_req_ack[1] = 0x04
# WDC_ERROR
wdc_error = bytearray(3)
wdc_error[0] = 2  # ?? TODO
wdc_error[1] = 0x00


class UDPMulticastHandler(threading.Thread):
    def __init__(self, sock):
        threading.Thread.__init__(self)
        self.stopped = False
        self.sock = sock

    def run(self):
        logging.info('UDP multicast is ready! [pid: {}]'.\
            format(os.getpid()))
        while not self.stopped:
            key_data, addr = self.sock.recvfrom(1024)

            other_key = tuple([int.from_bytes(x, byteorder='big')
                for x in [key_data[:32], key_data[32:]]])

            ecdh = ECDH()

            if ecdh.check_public_key(other_key):
                ecdh.gen_private_key()
                ecdh.gen_public_key()
                ser_pub_key = b''.join([x.to_bytes(length=32, byteorder='big')
                    for x in ecdh.public_key])

                self.sock.sendto(ser_pub_key, addr)

                ecdh.gen_secret(other_key)
                logging.info('key: {}'.format(hexlify(ecdh.gen_key())))

            else:
                self.sock.sendto(bytes('key error', 'UTF-8'), addr)
                logging.error('key error')

        logging.debug('UDP multicast thread is stopped')


def send_tcp_wdc_error(tcp_socket, error):
    msg = wdc_error
    msg[2] = error
    try:
        tcp_socket.sendall(msg)
        logging.debug('sent {} Bytes to TCP client socket'.\
            format(len(msg)))
    except:
        logging.error('error sending TCP WDC_ERROR')


def send_udp_wdc_error(udp_socket, address, error):
    '''call signature: send_udp_wdc_error(*srv_udp_sock, msg)
    '''
    msg = wdc_error
    msg[2] = error
    try:
        udp_socket.sendto(msg, address)
        logging.debug('sent {} Bytes to UDP client socket'.\
            format(len(msg)))
    except:
        logging.error('error sending UDP WDC_ERROR')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Kickass WDC v0.0')
    parser.add_argument('-v', '--verbose', action='store_true',
        dest='VERBOSE', default=False)
    parser.add_argument('-p', '--port', action='store', type=int,
        dest='TCP_PORT', default=TCP_PORT)
    args = parser.parse_args()
    LOGLEVEL = logging.DEBUG if args.VERBOSE else logging.INFO
    TCP_PORT = args.TCP_PORT

    logging.basicConfig(format='%(asctime)s : %(levelname)s : %(message)s',
        level=LOGLEVEL)

    connected = False

    # add multicast route here

    # start TCP socket
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.bind(('', TCP_PORT))
    tcp_sock.listen(5)

    logging.info('TCP receiving socket is ready! [pid: {}]'.\
            format(os.getpid()))

    while True:
        # thread management, check stopping flags and stop threads if req'd

        try:
            (client_sock, srv_address) = tcp_sock.accept()
            logging.debug('accepted {}'.format(srv_address))

            data = client_sock.recv(TCP_RX_BUFFER_SIZE)
            logging.debug('received {} Bytes from TCP client socket'.\
                    format(len(data)))

            # received length is not as stated in the data
            # (TODO, basically do input validation)
            if len(data) != data[0] + 1:
                send_tcp_wdc_error(client_sock, WRONG_CMD)
                client_sock.close()
                continue

            # WDC_CONNECTION_REQ
            if data[1] == 0x01:
                if connected:
                    send_tcp_wdc_error(client_sock, BUSY_CONNECTED)
                    client_sock.close()
                    continue

                # TODO
                wdc_get_status_res[0] = data[0] + 1
                wdc_get_status_res[3:] = data[2:]

                # serial port stuffs skipped

                # WDC_CONNECTION_RES TODO
                # seems to be taken from serialPortRxBuffer

                # open UDP multicast socket for receiving data
                try:
                    MCAST_PORT = 5007  # data[8]
                    MCAST_GRP = '224.1.1.1'  # data[10]
                    udp_mcast_sock = socket.socket(socket.AF_INET,
                        socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                    udp_mcast_sock.setsockopt(socket.SOL_SOCKET,
                        socket.SO_REUSEPORT, 1)  # TODO for Linux
                    udp_mcast_sock.bind(('', MCAST_PORT))
                    mreq = struct.pack("4sl", socket.inet_aton(MCAST_GRP),
                        socket.INADDR_ANY)
                    udp_mcast_sock.setsockopt(socket.IPPROTO_IP,
                        socket.IP_ADD_MEMBERSHIP, mreq)

                except:
                    logging.error('error binding/joining UDP multicast')
                    send_tcp_wdc_error(client_sock, CONNECTING)
                    client_sock.close()
                    continue

                # open UDP socket for sending data to server
                try:
                    SERVER_IP = srv_address
                    SERVER_UDP_PORT = 33401  # data[6]
                    udp_sock = socket.socket(socket.AF_INET,
                        socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                    srv_udp_sock = (udp_sock,
                        (SERVER_IP, SERVER_UDP_PORT))

                except:
                    logging.error('error opening UDP socket')
                    send_tcp_wdc_error(client_sock, CONNECTING)
                    client_sock.close()
                    continue

                # TODO reply to server

                # start a thread to listen UDP multicast
                udphdlr = UDPMulticastHandler(udp_mcast_sock)
                udphdlr.start()

                # serial thread skipped

                connected = True

            # WDC_DISCONNECTION_REQ
            elif data[1] == 0x03:
                if connected:
                    try:
                        # stop UDP multicast thread
                        udphdlr.stopped = True
                        udphdlr.join(1)  # thread blocks at recvfrom(),
                                         # join() had better be timed out

                        # serial port stuffs skipped

                        # close UDP socket to send data to server
                        srv_udp_sock[0].close()

                        # send disconnect ack
                        client_sock.sendall(wdc_disconnection_req_ack)
                        logging.debug('sent wdc disconnection TODO')

                    except:
                        logging.error('error sending disconnection ack')

                connected = False

            # WDC_GET_STATUS_REQ
            elif data[1] == 0x05:
                wdc_get_status_res[2] = connected

                # TODO send wdc_get_status_res

                logging.debug('sent wdc status res TODO')

            # WDC_SET_COOR_LONG_ADDR_REQ || WDC_RESET_REQ
            elif data[1] == 0x07 or data[1] == 0x09:
                if connected:
                    send_tcp_wdc_error(client_sock, BUSY_CONNECTED)
                    client_sock.close()
                    continue

                else:
                    # serial port stuffs skipped

                    if data[1] == 0x09:
                        try:
                            # stop UDP multicast thread
                            udphdlr.stopped = True
                            udphdlr.join(1)  # thread blocks at recvfrom(),
                                             # join() had better be timed out

                            # close UDP multicast socket
                            udp_mcast_sock.close()

                            # serial port stuffs skipped

                            # close UDP socket to send data to server
                            srv_udp_sock[0].close()

                            # close TCP socket
                            client_sock.close()

                            # (supposedly) reboot system
                            os._exit(0)

                        except:
                            logging.error('error resetting')

            else:
                send_tcp_wdc_error(client_sock, WRONG_CMD)
                client_sock.close()
                continue
                # serial port stuffs skipped

            client_sock.close()


        except KeyboardInterrupt:
            udphdlr.stopped = True
            udphdlr.join(1)  # thread blocks at recvfrom(),
                             # join() had better be timed out
            tcp_sock.close()
            udp_mcast_sock.close()
            srv_udp_sock[0].close()
            os._exit(0)
