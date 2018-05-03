from electroncash.bitcoin import (
    bfh,  bh2u, MySigningKey, MyVerifyingKey ,SECP256k1,
    generator_secp256k1, point_to_ser, public_key_to_p2pkh, Hash,
    pubkey_from_signature, msg_magic, TYPE_ADDRESS)
from electroncash.transaction import Transaction, int_to_hex
from electroncash.address import Address
import ecdsa
import hashlib

class Coin(object):
    """
    it is a class for interaction with blockchain interaction
    will be fake functions for now
    """

    def __init__(self, network):
        self.network = network

    def sufficient_funds(self, address, amount):
        """
        System should check for sufficient funds here.
        amount here is satoshis
        """
        unspent_list = self.network.synchronous_get(('blockchain.address.listunspent', [address]))
        values = [uxto['value'] for uxto in unspent_list]
        return len([i for i in values if i > amount]) > 0

    def address(self, vk):
        return public_key_to_p2pkh(bytes.fromhex(vk))

    def get_first_sufficient_utxo(self, address, amount):
        # it takes a list of coins from address,
        # filter coins for sufficietn ammount
        # takes first coin.
        # protocol doesn't specify which coin form address is used for transaction.
        # It is supposed to have single output for address to be shuffled
        coins = self.network.synchronous_get(('blockchain.address.listunspent', [address]))
        coins = [coin for coin in coins if coin['value'] >= amount ]
        if coins:
            return coins[0]
        else:
            return None

    def make_unsigned_transaction(self, amount, fee, inputs, outputs, changes):
        coins = {vk : self.get_first_sufficient_utxo(inputs[vk], amount) for vk in inputs}
        for vk in coins:
            coins[vk]['type'] = 'p2pkh'
            coins[vk]['address'] = Address.from_string(self.address(vk))
            coins[vk]['pubkeys'] = [vk]
            coins[vk]['x_pubkeys'] = [vk]
            coins[vk]['prevout_hash'] = coins[vk]['tx_hash']
            coins[vk]['prevout_n'] = coins[vk]['tx_pos']
            coins[vk]['signatures'] = [None]
            coins[vk]['num_sig'] = 1
        tx_inputs = [coins[vk] for vk in sorted(coins)]
        tx_outputs = [(TYPE_ADDRESS, Address.from_string(output), int(amount)) for output in outputs ]
        tx = Transaction.from_io(tx_inputs, tx_outputs)
        tx_changes = [(TYPE_ADDRESS, Address.from_string(changes[vk]), int(coins[vk]['value'] - amount - fee))  for vk in changes if Address.is_valid(changes[vk])]
        tx.add_outputs(tx_changes)
        return tx

    def get_transaction_signature(self, tx, sk, vk):
        txin = list(filter(lambda x: vk in x['pubkeys'], tx.inputs()))
        if txin:
            tx_num = tx.inputs().index(txin[0])
            pre_hash = Hash(bfh(tx.serialize_preimage(tx_num)))
            private_key = MySigningKey.from_secret_exponent(sk.secret, curve = SECP256k1)
            public_key = private_key.get_verifying_key()
            sig = private_key.sign_digest_deterministic(pre_hash, hashfunc=hashlib.sha256, sigencode = ecdsa.util.sigencode_der)
            assert public_key.verify_digest(sig, pre_hash, sigdecode = ecdsa.util.sigdecode_der)
            result = bh2u(sig) + int_to_hex(tx.nHashType() & 255, 1)
            return result.encode('utf-8')
        return b''

    def add_transaction_signatures(self, tx, signatures):
        for i, txin in enumerate(tx._inputs):
            tx._inputs[i]['signatures'] = [signatures.get(tx._inputs[i]['pubkeys'][0]).decode()]
            tx.raw = tx.serialize()
        return tx

    def check_double_spend(t):
        """
        Double Spend Check should go here
        NOT IMPLEMENTED
        """
        return true

    def verify_tx_signature(self, sig, tx, vk):
        txin = list(filter(lambda x: vk in x['pubkeys'], tx.inputs()))
        if txin:
            tx_num = tx.inputs().index(txin[0])
            pre_hash = Hash(bfh(tx.serialize_preimage(tx_num)))
            order = generator_secp256k1.order()
            r, s = ecdsa.util.sigdecode_der(bfh(sig.decode()[:-2]), order)
            sig_string = ecdsa.util.sigencode_string(r, s, order)
            compressed = len(vk) <= 66
            for recid in range(0,4):
                try:
                    pubk = MyVerifyingKey.from_signature(sig_string, recid, pre_hash, curve = SECP256k1)
                    pubkey = bh2u(point_to_ser(pubk.pubkey.point, compressed))
                    if vk == pubkey:
                        return True
                except:
                    continue
        else:
            return False


    def verify_signature(self, sig, message, vk):
        pk, compressed = pubkey_from_signature(sig,Hash(msg_magic(message)))
        address_from_signature = public_key_to_p2pkh(point_to_ser(pk.pubkey.point,compressed))
        address_from_vk = self.address(vk)
        return address_from_signature == address_from_vk
