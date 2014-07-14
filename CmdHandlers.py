import logging
import threading
from binascii import hexlify
from ECDiffieHellman import ECDH
from CommAPIs import send_udp, write_serial, read_serial

# for storing dummy status
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
# wdc_error[2] depends on the error type

# WDC_GET_TDMA_RES
wdc_get_tdma_res = bytearray(24)
wdc_get_tdma_res[0] = 23
wdc_get_tdma_res[1] = 0x16

# ACK
ack = bytearray(2)
ack[0] = 1
# ack[1] depends on the ack type

logging.getLogger('wdclogger')


class SerialCmdHandler(threading.Thread):
    '''Dummy handler for serial commands
    '''
    def __init__(self, data, srv_udp_sock):
        threading.Thread.__init__(self, name='Serial')
        self.data = data
        self.srv_udp_sock = srv_udp_sock
        self.running = False

    def run(self):
        data = self.data

        # TODO: this "if" hasn't been tested
        if len(data) == 0 or len(data) != data[0] + 1:
            msg = wdc_error
            msg[2] = WRONG_CMD
            send_udp(msg, *(self.srv_udp_sock))
            logging.error('bad command')
            return

        if data[1] == 0x10:  # syn TDMA
            logging.debug('sync-ing WDC')

        elif data[1] == 0x11:  # start TDMA
            logging.debug('starting TDMA')

            wdc_get_tdma_res = bytearray(24)
            wdc_get_tdma_res[0] = data[0] + 1
            wdc_get_tdma_res[1] = 0x16
            wdc_get_tdma_res[2] = 0x01  # running
            wdc_get_tdma_res[3:] = data[2:]

            write_serial(wdc_get_tdma_res, status_file)

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

            wdc_get_tdma_res = read_serial(status_file)

            msg = wdc_get_tdma_res
            send_udp(msg, *self.srv_udp_sock)

        elif data[1] == 0x17:  # data request
            logging.debug('data request {}'.format(data))

            if data[2] in range(1, 9):  # key management messages
                ## TEST TEST TEST TEST TODO
                #params = data[3:196]
                dap = data[3:]

                if len(dap) != 64:
                    logging.error('wrong public key length')
                    return

                other_key = tuple([int.from_bytes(x, byteorder='big')
                    for x in [dap[:32], dap[32:]]])

                ecdh = ECDH()

                if ecdh.check_public_key(other_key):
                    ecdh.gen_private_key()
                    ecdh.gen_public_key()
                    ser_pub_key = b''.join([x.to_bytes(length=32,
                        byteorder='big') for x in ecdh.public_key])
                    ecdh.gen_secret(other_key)

                    send_udp(ser_pub_key, *(self.srv_udp_sock))

                    logging.info('key: {}'.format(hexlify(ecdh.gen_key())))

            elif data[2] in [0x09, 0x0A]:  # application unicast, broadcast
                pass

            else:
                msg = wdc_error
                msg[2] = WRONG_CMD
                send_udp(msg, *(self.srv_udp_sock))
                logging.error('wrong MAC_DATA_REQUEST mID')

        else:
            msg = wdc_error
            msg[2] = WRONG_CMD
            #send_udp(msg, *(self.srv_udp_sock))
            #logging.error('wrong command')
