# requires Python >3.2
import json
import hashlib
import elliptic as ec
from random import randint
from binascii import hexlify

class ECDH(object):
    """
    An implementation of ECDH protocol.
    This class uses parameters stored in the curve_params file.
    """
    def __init__(self, curve_params='ecp_256.txt', flip_sign=True):
        """
        Initialise, and generate the public and private keys.
        """
        with open(curve_params) as f:
            self.params = json.load(f)
    
        for k in self.params:
            if k != 'eq':
                self.params[k] = int(self.params[k], 16)

        if flip_sign:
            self.params['a'] = (-1 * self.params['a']) % self.params['p']
            self.params['b'] = (-1 * self.params['b']) % self.params['p']

        self.basepoint = (self.params['gx'], self.params['gy'])

        self.gen_private_key()
        self.gen_public_key()


    def gen_private_key(self):
        """
        Generate a private key.
        """
        self.private_key = randint(1, self.params['n'] - 1)


    def gen_public_key(self):
        """
        Generate a public key.
        """
        self.public_key = ec.mulp(self.params['a'], self.params['b'], 
            self.params['p'], self.basepoint, self.private_key)


    def check_public_key(self, other_key):
        """
        Check the other party's public key to make sure it's valid.
        """
        if (other_key is not None
            and other_key[0] >= 0 and other_key[0] <= self.params['p'] - 1
            and other_key[1] >= 0 and other_key[1] <= self.params['p'] - 1
            and ec.element(other_key, self.params['a'], self.params['b'], 
                self.params['p'])):
            return True
        return False


    def gen_secret(self, other_key):
        """
        Check to make sure the public key is valid, then combine it with the
        private key to generate a shared secret.
        """
        if self.check_public_key(other_key):
            self.shared_secret = ec.mulp(self.params['a'], self.params['b'], 
                self.params['p'], other_key, self.private_key)
        else:
            raise Exception("Invalid public key.")


    def gen_key(self):
        """
        Obtain key from shared secret. 
        This is intended to be a pluggable module, 
        e.g. to use other algorithm like HKDF
        """
        s = hashlib.sha256()
        secret_bytes = b''.join([x.to_bytes(length=32, byteorder='big') 
            for x in self.shared_secret])
        s.update(secret_bytes)
        return s.digest()


if __name__=="__main__":
    """
    Run an example elliptic curve Diffie-Hellman exchange 
    """
 
    a = ECDH()
    b = ECDH()

    a.gen_secret(b.public_key)
    b.gen_secret(a.public_key)
 
    key_a = a.gen_key()
    key_b = b.gen_key()
 
    if(key_a == key_b):
        print("Shared keys match.")
        print("Key:", hexlify(key_a))
    else:
        print("Shared secrets didn't match!")
        print("Shared secret: ", a.shared_secret)
        print("Shared secret: ", b.shared_secret)