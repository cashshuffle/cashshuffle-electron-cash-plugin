from ecdsa.util import number_to_string, string_to_number
import ecdsa
from electroncash.bitcoin import (generator_secp256k1, point_to_ser, EC_KEY)
import hashlib
# For now it is ECIES encryption/decryption methods from bitcoin lib. It should be updated for something else i suppose.

class Crypto(object):

    def __init__(self):
        self.G = generator_secp256k1
        self._r  = self.G.order()

    def generate_key_pair(self):
        self.private_key = ecdsa.util.randrange( pow(2,256) ) %self._r
        self.eck = EC_KEY(number_to_string(self.private_key, self._r))
        self.public_key = point_to_ser(self.private_key*self.G,True)

    def export_private_key(self):
        if self.private_key:
            return bytes.hex(number_to_string(self.private_key, self._r))
        else:
            return None

    def restore_from_privkey(self, secret_string):
        self.private_key = string_to_number(bytes.fromhex(secret_string))
        self.eck = EC_KEY(bytes.fromhex(secret_string))
        self.public_key = point_to_ser(self.private_key*self.G,True)

    def export_public_key(self):
        """
        serialization of public key
        """
        return bytes.hex(self.public_key)

    def encrypt(self, message, pubkey):
        res = self.eck.encrypt_message(message.encode('utf-8'), bytes.fromhex(pubkey))
        return res.decode('utf-8')

    def decrypt(self, message):
        return self.eck.decrypt_message(message)

    def hash(self, text, algorithm = 'sha224'):
        h = hashlib.new(algorithm)
        h.update(text.encode('utf-8'))
        return h.digest()
