import os
import socket
import struct
import logging
import argparse
import threading
from CmdHandlers import SerialCmdHandler
from CommAPIs import send_tcp

TCP_PORT = 33401
TCP_RX_BUFFER_SIZE = 64
UDP_RX_BUFFER_SIZE = 256

BUSY_CONNECTED = 0x01
CONNECTING = 0x02
WRONG_CMD = 0x03

# messages
# WDC_ERROR
wdc_error = bytearray(3)
wdc_error[0] = 2  # len w/o the len field itself
wdc_error[1] = 0x00

# WDC_CONNECTION_RES
wdc_connection_res = bytearray(10)
wdc_connection_res[0] = 9
wdc_connection_res[1] = 0x02

# WDC_DISCONNECTION_REQ_ACK
wdc_disconnection_req_ack = bytearray(2)
wdc_disconnection_req_ack[0] = 1
wdc_disconnection_req_ack[1] = 0x04

# WDC_GET_STATUS_RES
wdc_get_status_res = bytearray(64)
wdc_get_status_res[0] = 10
wdc_get_status_res[1] = 0x06

# WDC_SET_COOR_LONG_ADDR_REQ_ACK
wdc_set_coor_long_addr_req_ack = bytearray(2)
wdc_set_coor_long_addr_req_ack[0] = 1
wdc_set_coor_long_addr_req_ack[1] = 0x08

# WDC_RESET_REQ_ACK
wdc_reset_req_ack = bytearray(2)
wdc_reset_req_ack[0] = 1
wdc_reset_req_ack[1] = 0x0a


class UDPMulticastListener(threading.Thread):
    def __init__(self, sock, srv_udp_sock):
        threading.Thread.__init__(self, name='UDPMcast')
        self.stopped = False
        self.sock = sock
        self.srv_udp_sock = srv_udp_sock
        logging.info('UDP multicast is ready!')

    def run(self):
        while not self.stopped:
            try:
                data, addr = self.sock.recvfrom(1024)
                logging.debug('received {} bytes udp mcast'.\
                    format(len(data)))
                hdlr = SerialCmdHandler(data, self.srv_udp_sock)
                hdlr.start()
            except:
                break


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Kickass WDC v0.0')
    parser.add_argument('-v', '--verbose', action='store_true',
        dest='VERBOSE', default=False)
    parser.add_argument('-p', '--port', action='store', type=int,
        dest='TCP_PORT', default=TCP_PORT)
    args = parser.parse_args()
    LOGLEVEL = logging.DEBUG if args.VERBOSE else logging.INFO
    TCP_PORT = args.TCP_PORT

    logging.basicConfig(
        format='%(asctime)s : %(levelname)s : %(threadName)s : %(message)s',
        level=LOGLEVEL)
    logging.getLogger('wdclogger')

    connected = False

    # add multicast route TODO

    while True:
        try:
            # start TCP socket
            tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp_sock.bind(('', TCP_PORT))
            tcp_sock.listen(5)

            logging.info('TCP receiving socket is ready! [pid: {}]'.\
                    format(os.getpid()))

            (client_sock, srv_address) = tcp_sock.accept()
            logging.debug('accepted {}'.format(srv_address))

            while True:
                try:
                    data = client_sock.recv(TCP_RX_BUFFER_SIZE)
                    logging.debug('received {} Bytes from TCP client socket'.\
                            format(len(data)))

                    if len(data) == 0:
                        raise KeyboardInterrupt

                    # received length is not as stated in the data
                    # (TODO, basically do input validation)
                    if len(data) != data[0] + 1:
                        msg = wdc_error
                        msg[2] = WRONG_CMD
                        send_tcp(msg, client_sock,
                            errmsg='error sending wrong cmd')
                        continue

                    # WDC_CONNECTION_REQ
                    elif data[1] == 0x01:
                        if connected:
                            msg = wdc_error
                            msg[2] = BUSY_CONNECTED
                            send_tcp(msg, client_sock,
                                errmsg='error sending busy connected')
                            continue

                        wdc_get_status_res[0] = data[0] + 1
                        wdc_get_status_res[3:] = data[2:]

                        # serial port stuffs skipped

                        # open UDP multicast socket for receiving data
                        try:
                            MCAST_PORT = int.from_bytes(data[8:10], 
                                byteorder='little')
                            MCAST_GRP = data[10:-1].decode('ascii')
                            udp_mcast_sock = socket.socket(socket.AF_INET,
                                socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                            # on MAC OS X it's SO_REUSEPORT 
                            # in place of SO_REUSEADDR
                            udp_mcast_sock.setsockopt(socket.SOL_SOCKET,
                                socket.SO_REUSEADDR, 1)
                            udp_mcast_sock.bind(('', MCAST_PORT))
                            mreq = struct.pack("4sl",
                                socket.inet_aton(MCAST_GRP),
                                socket.INADDR_ANY)
                            udp_mcast_sock.setsockopt(socket.IPPROTO_IP,
                                socket.IP_ADD_MEMBERSHIP, mreq)

                        except:
                            logging.error(
                                'error binding/joining UDP multicast')
                            msg = wdc_error
                            msg[2] = CONNECTING
                            send_tcp(msg, client_sock, 
                                errmsg='error sending connecting error')
                            continue

                        # open UDP socket for sending data to server
                        try:
                            SERVER_IP = srv_address[0]
                            SERVER_UDP_PORT = int.from_bytes(data[6:8], 
                                byteorder='little')
                            udp_sock = socket.socket(socket.AF_INET,
                                socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                            srv_udp_sock = (udp_sock,
                                (SERVER_IP, SERVER_UDP_PORT))

                        except:
                            logging.error('error opening UDP socket')
                            msg = wdc_error
                            msg[2] = CONNECTING
                            send_tcp(msg, client_sock, 
                                errmsg='error sending connecting error')
                            continue

                        # fake response; 8 Byte coordnode long address
                        # should be taken from serial read, TODO
                        wdc_connection_res[2:] = [0xde, 0xad, 0xbe, 0xef, 
                                                  0xde, 0xad, 0xbe, 0xef]
                        
                        send_tcp(wdc_connection_res, client_sock,
                            errmsg='error sending wdc conn res')

                        # start a thread to listen UDP multicast
                        udphdlr = UDPMulticastListener(udp_mcast_sock, 
                            srv_udp_sock)
                        udphdlr.start()

                        # serial thread skipped

                        connected = True

                    # WDC_DISCONNECTION_REQ
                    elif data[1] == 0x03:
                        if connected:
                            try:
                                # stop UDP multicast thread
                                udphdlr.stopped = True
                                udphdlr.join(1)  
                                # thread blocks at recvfrom(),
                                # join() had better be timed out

                                # stop serial port thread TODO

                                # close UDP socket to send data to server
                                srv_udp_sock[0].close()

                                # send disconnect on serial port TODO

                                # send disconnect ack
                                send_tcp(wdc_disconnection_req_ack,
                                    client_sock,
                                    errmsg='error sending disconnect ack')

                            except:
                                logging.error('error disconnecting')

                        connected = False

                    # WDC_GET_STATUS_REQ
                    elif data[1] == 0x05:
                        wdc_get_status_res[2] = connected

                        # send wdc_get_status_res
                        send_tcp(wdc_get_status_res, client_sock,
                            errmsg='error sending status res')

                    # WDC_SET_COOR_LONG_ADDR_REQ || WDC_RESET_REQ
                    elif data[1] == 0x07 or data[1] == 0x09:
                        if connected:
                            msg = wdc_error
                            msg[2] = BUSY_CONNECTED
                            send_tcp(msg, client_sock,
                                errmsg='error sending busy connected')

                        else:
                            # send command to serial TODO
                            # wait and read serial response TODO

                            ack = wdc_set_coor_long_addr_req_ack\
                            if data[1] == 0x07 else wdc_reset_req_ack

                            send_tcp(ack, client_sock,
                                errmsg='error sending set longaddr/reset ack')

                            if data[1] == 0x09:
                                try:
                                    # stop UDP multicast thread
                                    udphdlr.stopped = True
                                    udphdlr.join(1)  
                                    # thread blocks at recvfrom(),
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
                        msg = wdc_error
                        msg[2] = WRONG_CMD
                        send_tcp(msg, client_sock, 
                            errmsg='error sending wrong cmd')
                        # serial port stuffs skipped


                except KeyboardInterrupt:
                    if 'udphdlr' in globals():
                        udphdlr.stopped = True
                        udphdlr.join(1)  
                        # thread blocks at recvfrom(),
                        # join() had better be timed out

                    if 'client_sock' in globals():
                        client_sock.close()

                    if 'tcp_sock' in globals():
                        tcp_sock.close()

                    if 'udp_mcast_sock' in globals():
                        udp_mcast_sock.close()

                    if 'srv_udp_sock' in globals():
                        srv_udp_sock[0].close()

        except:
            continue
