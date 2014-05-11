import pickle
import logging

logging.getLogger('wdclogger')


def send_tcp(msg, tcp_socket, errmsg=''):
    try:
        tcp_socket.sendall(msg)
        logging.debug('sent {} Bytes to TCP client socket: {}'.\
            format(len(msg)))
    except:
        logging.error(errmsg)


def send_udp(msg, udp_socket, address):
    '''call signature: send_udp(msg, *srv_udp_sock)
       address is a tuple (IPADDR, PORTNBR)
    '''
    try:
        udp_socket.sendto(msg, address)
        logging.debug('sent {} Bytes to UDP client socket'.\
            format(len(msg)))
    except:
        logging.error('error sending UDP')


def dummy_write_serial(msg, filename):
    # store status in dummy pickle file
    with open(filename, 'wb+') as f:
        pickle.dump(msg, f, pickle.HIGHEST_PROTOCOL)


def dummy_read_serial(filename):
    # get status from dummy pickle file
    with open(filename, 'rb') as f:
        return pickle.load(f)