import json
import hashlib
import elliptic as ec
from random import randint
from binascii import hexlify

class ECDH(object):
    """
    An implementation of ECDH protocol.
    This class uses parameters stored in the prime_file.
    """
    def __init__(self, prime_file='ecp_256.txt', flip_sign=True):
        """
        Generate the public and private keys.
        """
        with open(prime_file) as f:
            self.params = json.load(f)
    
        for k in self.params:
            if k != 'eq':
                self.params[k] = int(self.params[k], 16)

        if flip_sign:
            self.params['a'] = (-1 * self.params['a']) % self.params['p']
            self.params['b'] = (-1 * self.params['b']) % self.params['p']

        self.basepoint = (self.params['gx'], self.params['gy'])

        # just for testing in __main__ below, not to be used in a protocol!
        self.__private_key__ = self.gen_private_key()
        self.__public_key__ = self.gen_public_key(self.__private_key__)


    def gen_private_key(self):
        """
        Generate a private key.
        """
        return randint(1, self.params['n'] - 1)


    def gen_public_key(self, private_key):
        """
        Generate a public key.
        """
        return ec.mulp(self.params['a'], self.params['b'], self.params['p'], 
            self.basepoint, private_key)


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


    def gen_secret(self, private_key, other_key):
        """
        Check to make sure the public key is valid, then combine it with the
        private key to generate a shared secret.
        """
        if self.check_public_key(other_key):
            shared_secret = ec.mulp(self.params['a'], self.params['b'], 
                self.params['p'], other_key, private_key)
            return shared_secret
        else:
            raise Exception("Invalid public key.")


    def gen_key(self, private_key, other_key):
        """
        Derive the shared secret, then hash it to obtain the shared key.
        """
        shared_secret = self.gen_secret(private_key, other_key)
        s = hashlib.sha256()
        s.update(str(shared_secret))
        return s.digest()


if __name__=="__main__":
    """
    Run an example elliptic curve Diffie-Hellman exchange 
    """
 
    a = ECDH()
    b = ECDH()
 
    key_a = a.gen_key(a.__private_key__, b.__public_key__)
    key_b = b.gen_key(b.__private_key__, a.__public_key__)
 
    if(key_a == key_b):
        print "Shared keys match."
        print "Key:", hexlify(key_a)
    else:
        print "Shared secrets didn't match!"
        print "Shared secret: ", a.gen_secret(a.__private_key__, 
            b.__public_key__)
        print "Shared secret: ", b.gen_secret(b.__private_key__, 
            a.__public_key__)