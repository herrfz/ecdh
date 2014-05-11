import logging
import threading
from binascii import hexlify
from ECDiffieHellman import ECDH

# for storing dummy status
import pickle
status_file = './status.pickle'

# error codes
BUSY_CONNECTED = 0x01
CONNECTING = 0x02
WRONG_CMD = 0x03

# messages
# WDC_ERROR
wdc_error = bytearray(3)
wdc_error[0] = 2
wdc_error[1] = 0x00

# WDC_GET_TDMA_RES
wdc_get_tdma_res = bytearray(24)
wdc_get_tdma_res[0] = 23
wdc_get_tdma_res[1] = 0x16

# ACK
ack = bytearray(2)
ack[0] = 1

LOGLEVEL = logging.DEBUG
logging.basicConfig(format='%(asctime)s : %(levelname)s : %(message)s',
    level=LOGLEVEL)


def send_udp(msg, udp_socket, address):
    '''call signature: send_udp_wdc_error(msg, *srv_udp_sock)
    '''
    try:
        udp_socket.sendto(msg, address)
        logging.debug('sent {} Bytes to UDP client socket'.\
            format(len(msg)))
    except:
        logging.error('error sending UDP')


class SerialCmdHandler(threading.Thread):
    def __init__(self, data, srv_udp_sock):
        threading.Thread.__init__(self)
        self.data = data
        self.srv_udp_sock = srv_udp_sock
        self.running = False

    def run(self):
        data = self.data

        # this if hasn't been tested
        if len(data) == 0 or len(data) != data[0] + 1:
            msg = wdc_error
            msg[2] = WRONG_CMD
            send_udp(msg, *(self.srv_udp_sock))

        if data[1] == 0x10:  # syn TDMA
            logging.debug('sync-ing WDC')

        elif data[1] == 0x11:  # start TDMA
            logging.debug('starting TDMA')

            wdc_get_tdma_res = bytearray(24)
            wdc_get_tdma_res[0] = data[0] + 1
            wdc_get_tdma_res[1] = 0x16
            wdc_get_tdma_res[2] = 0x01  # running
            wdc_get_tdma_res[3:] = data[2:]

            # store status in dummy pickle file
            with open(status_file, 'wb+') as f:
                pickle.dump(wdc_get_tdma_res, f,
                    pickle.HIGHEST_PROTOCOL)

            msg = ack
            msg[1] = 0x12  # START_TDMA_REQ_ACK
            send_udp(msg, *self.srv_udp_sock)

        elif data[1] == 0x13:  # stop TDMA
            logging.debug('stopping TDMA')

            msg = ack
            msg[1] = 0x14  # STOP_TDMA_REQ_ACK
            send_udp(msg, *self.srv_udp_sock)

        elif data[1] == 0x15:  # TDMA status
            logging.debug('sending TDMA status response')

            # get status from dummy pickle file
            with open(status_file, 'rb') as f:
                wdc_get_tdma_res = pickle.load(f)

            msg = wdc_get_tdma_res
            send_udp(msg, *self.srv_udp_sock)

        elif data[1] == 0x17:  # data request
            logging.debug('data request')

        else:
            msg = wdc_error
            msg[2] = WRONG_CMD
            #send_udp(msg, *(self.srv_udp_sock))
            #logging.error('wrong command')

            ## incomplete
            key_data = data[2:]
            other_key = tuple([int.from_bytes(x, byteorder='big')
                for x in [key_data[:32], key_data[32:]]])

            ecdh = ECDH()

            if ecdh.check_public_key(other_key):
                ecdh.gen_private_key()
                ecdh.gen_public_key()
                ser_pub_key = b''.join([x.to_bytes(length=32, byteorder='big')
                    for x in ecdh.public_key])

                #self.sock.sendto(ser_pub_key, addr)

                ecdh.gen_secret(other_key)
                logging.info('key: {}'.format(hexlify(ecdh.gen_key())))
            