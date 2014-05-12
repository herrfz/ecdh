import pickle
import logging

logging.getLogger('wdclogger')

# dummifying wrappers
def dummy_write(func):
    def func_wrapper(msg, fd):
        with open(fd, 'wb+') as f:
            pickle.dump(msg, f)
    return func_wrapper

def dummy_read(func):
    def func_wrapper(fd):
        with open(fd, 'rb') as f:
            return pickle.load(f)
    return func_wrapper


def send_tcp(msg, tcp_socket, errmsg=''):
    try:
        tcp_socket.sendall(msg)
        logging.debug('sent {} Bytes to TCP client socket'.\
            format(len(msg)))
    except:
        logging.error(errmsg)

def send_udp(msg, udp_socket, address):
    '''call signature: send_udp(msg, *srv_udp_sock);
       address is a tuple (IPADDR, PORTNBR)
    '''
    try:
        udp_socket.sendto(msg, address)
        logging.debug('sent {} Bytes to UDP client socket'.\
            format(len(msg)))
    except:
        logging.error('error sending UDP')

@dummy_write
def write_serial(msg, fd):
    pass

@dummy_read
def read_serial(fd):
    pass