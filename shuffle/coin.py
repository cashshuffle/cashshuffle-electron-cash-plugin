import hashlib
from electroncash.bitcoin import (
    bfh, bh2u, MySigningKey, MyVerifyingKey, SECP256k1,
    generator_secp256k1, point_to_ser, public_key_to_p2pkh, Hash,
    pubkey_from_signature, msg_magic, TYPE_ADDRESS)
from electroncash.transaction import Transaction, int_to_hex
from electroncash.address import Address
import ecdsa

def address_from_public_key(public_key):
    "get address from public key"
    return public_key_to_p2pkh(bytes.fromhex(public_key))


class Coin(object):
    """
    it is a class for interaction with blockchain interaction
    will be fake functions for now
    """

    def __init__(self, network):
        self.network = network

    def check_inputs_for_sufficient_funds(self, inputs, amount):
        """
        This function check on blockchain for sufficient funds.

        inputs is a dict with bitcoin pubkeys as a keys
        and list of utxo hashes as values.

        the sum of all utxo values should be greater then amount

        it does as follows:
        1. check utxo list for every pubkey in the dict
        2. check if utxo from inputs are in the utxo list on blockchain for this pubkeys
            2.a return None if there is a utxo from list not on utxo set from blockchain
        3. return True if summary values of utxos are greater then amount and False otherwise
        """
        total = 0
        try:
            for public_key in inputs:
                address = address_from_public_key(public_key)
                unspent_list = self.network.synchronous_get(('blockchain.address.listunspent', [address]))
                utxos = {utxo['tx_hash']:utxo['value'] for utxo in unspent_list}
                for utxo in inputs[public_key]:
                    if utxo in utxos:
                        total += utxos[utxo]
                    else:
                        return None
            return total > amount
        except Exception as e:
            return None

    def get_coins(self, inputs):
        coins = {}
        for public_key in inputs:
            address = address_from_public_key(public_key)
            coins[public_key] = []
            unspent_list = self.network.synchronous_get(('blockchain.address.listunspent', [address]))
            utxo_hashes = {utxo["tx_hash"]:utxo for utxo in unspent_list}
            for utxo in inputs[public_key]:
                if utxo in utxo_hashes:
                    coins[public_key].append(utxo_hashes[utxo])
                else:
                    return None
        return coins

    # def sufficient_funds(self, address, amount):
    #     """
    #     System should check for sufficient funds here.
    #     amount here is satoshis
    #
    #     if network object raise exception then this function returns None
    #     """
    #     try:
    #         unspent_list = self.network.synchronous_get(('blockchain.address.listunspent', [address]))
    #         values = [uxto['value'] for uxto in unspent_list]
    #         return len([i for i in values if i > amount]) > 0
    #     except:
    #         return None

    # def address(self, verification_key):
    #     "get address from public key"
    #     return public_key_to_p2pkh(bytes.fromhex(verification_key))

    # def get_first_sufficient_utxo(self, address, amount):
    #     """
    #     it takes a list of coins from address,
    #     filter coins for sufficietn ammount
    #     takes first coin.
    #     protocol doesn't specify which coin form address is used for transaction.
    #     It is supposed to have single output for address to be shuffled
    #     """
    #
    #     coins = self.network.synchronous_get(('blockchain.address.listunspent', [address]))
    #     coins = [coin for coin in coins if coin['value'] >= amount]
    #     if coins:
    #         return coins[0]
    #     else:
    #         return None

    # def make_unsigned_transaction(self, amount, fee, inputs, outputs, changes):
    #     "make unsigned transaction"
    #     coins = {}
    #     try:
    #         coins = {verification_key : self.get_first_sufficient_utxo(inputs[verification_key], amount + fee)
    #                  for verification_key in inputs}
    #     except:
    #         return None
    #     for verification_key in coins:
    #         coins[verification_key]['type'] = 'p2pkh'
    #         coins[verification_key]['address'] = Address.from_string(self.address(verification_key))
    #         coins[verification_key]['pubkeys'] = [verification_key]
    #         coins[verification_key]['x_pubkeys'] = [verification_key]
    #         coins[verification_key]['prevout_hash'] = coins[verification_key]['tx_hash']
    #         coins[verification_key]['prevout_n'] = coins[verification_key]['tx_pos']
    #         coins[verification_key]['signatures'] = [None]
    #         coins[verification_key]['num_sig'] = 1
    #     tx_inputs = [coins[verification_key] for verification_key in sorted(coins)]
    #     tx_outputs = [(TYPE_ADDRESS, Address.from_string(output), int(amount))
    #                   for output in outputs]
    #     transaction = Transaction.from_io(tx_inputs, tx_outputs)
    #     tx_changes = [(TYPE_ADDRESS,
    #                    Address.from_string(changes[verification_key]),
    #                    int(coins[verification_key]['value'] - amount - fee))
    #                   for verification_key in sorted(changes)
    #                   if Address.is_valid(changes[verification_key])]
    #     transaction.add_outputs(tx_changes)
    #     return transaction

    def make_unsigned_transaction(self, amount, fee, all_inputs, outputs, changes):
        "make unsigned transaction"
        coins = {}
        tx_inputs = []
        amounts = {}
        try:
            for player in all_inputs:
                coins[player] = self.get_coins(all_inputs[player])
        except:
            return None
        for player in coins:
            amounts[player] = 0
            for pubkey in coins[player]:
                for utxo in coins[player][pubkey]:
                    utxo['type'] = 'p2pkh'
                    utxo['address'] = Address.from_string(address_from_public_key(pubkey))
                    utxo['pubkeys'] = [pubkey]
                    utxo['x_pubkeys'] = [pubkey]
                    utxo['prevout_hash'] = utxo['tx_hash']
                    utxo['prevout_n'] = utxo['tx_pos']
                    utxo['signatures'] = [None]
                    utxo['num_sig'] = 1
                    tx_inputs.append(utxo)
                    amounts[player] += utxo['value']
        tx_outputs = [(TYPE_ADDRESS, Address.from_string(output), int(amount))
                      for output in outputs]
        transaction = Transaction.from_io(tx_inputs, tx_outputs)
        tx_changes = [(TYPE_ADDRESS, Address.from_string(changes[player]), int(amounts[player] - amount -fee))
                      for player in sorted(changes)
                      if Address.is_valid(changes[player])]
        transaction.add_outputs(tx_changes)
        return transaction

    # def get_transaction_signature(self, transaction, secret_key, verification_key):
    #     "get transaction signature"
    #     txin = list(filter(lambda x: verification_key in x['pubkeys'], transaction.inputs()))
    #     if txin:
    #         tx_num = transaction.inputs().index(txin[0])
    #         pre_hash = Hash(bfh(transaction.serialize_preimage(tx_num)))
    #         private_key = MySigningKey.from_secret_exponent(secret_key.secret, curve=SECP256k1)
    #         public_key = private_key.get_verifying_key()
    #         sig = private_key.sign_digest_deterministic(pre_hash,
    #                                                     hashfunc=hashlib.sha256,
    #                                                     sigencode=ecdsa.util.sigencode_der)
    #         assert public_key.verify_digest(sig, pre_hash, sigdecode=ecdsa.util.sigdecode_der)
    #         result = bh2u(sig) + int_to_hex(transaction.nHashType() & 255, 1)
    #         return result.encode('utf-8')
    #     return b''

    def get_transaction_signature(self, transaction, inputs, secret_keys):
        "get transaction signature"
        signatures = {}
        for txin in transaction.inputs():
            pubkey = txin['pubkeys'][0]
            if pubkey in inputs:
                tx_num = transaction.inputs().index(txin)
                pre_hash = Hash(bfh(transaction.serialize_preimage(tx_num)))
                private_key = MySigningKey.from_secret_exponent(secret_keys[pubkey].secret, curve=SECP256k1)
                public_key = private_key.get_verifying_key()
                sig = private_key.sign_digest_deterministic(pre_hash,
                                                            hashfunc=hashlib.sha256,
                                                            sigencode=ecdsa.util.sigencode_der)
                assert public_key.verify_digest(sig, pre_hash, sigdecode=ecdsa.util.sigdecode_der)
                signatures[txin['tx_hash']] = (bh2u(sig) + int_to_hex(transaction.nHashType() & 255, 1)).encode('utf-8')
        return signatures

    # def add_transaction_signatures(self, transaction, signatures):
    #     "Add players signatures from transaction"
    #     inputs = transaction.inputs()
    #     # transaction._inputs
    #     for i, txin in enumerate(inputs):
    #         inputs[i]['signatures'] = [signatures.get(inputs[i]['pubkeys'][0]).decode()]
    #         transaction.raw = transaction.serialize()
    #     return transaction

    def add_transaction_signatures(self, transaction, signatures):
        "Add players signatures from transaction"
        inputs = transaction.inputs()
        for i, txin in enumerate(inputs):
            if signatures.get(txin['tx_hash'], None):
                inputs[i]['signatures'] = [signatures[txin['tx_hash']].decode()]
        transaction.raw = transaction.serialize()


    def verify_tx_signature(self, signature, transaction, verification_key, tx_hash):
        "It verifies the transaction signatures"
        txin = list(filter(lambda x: verification_key in x['pubkeys'] and x['tx_hash'] == tx_hash, transaction.inputs()))
        if txin:
            tx_num = transaction.inputs().index(txin[0])
            pre_hash = Hash(bfh(transaction.serialize_preimage(tx_num)))
            order = generator_secp256k1.order()
            r, s = ecdsa.util.sigdecode_der(bfh(signature.decode()[:-2]), order)
            sig_string = ecdsa.util.sigencode_string(r, s, order)
            compressed = len(verification_key) <= 66
            for recid in range(0, 4):
                try:
                    pubk = MyVerifyingKey.from_signature(sig_string, recid,
                                                         pre_hash, curve=SECP256k1)
                    pubkey = bh2u(point_to_ser(pubk.pubkey.point, compressed))
                    if verification_key == pubkey:
                        return True
                except:
                    continue
        else:
            return False

    def broadcast_transaction(self, transaction):
        try:
            return self.network.broadcast(transaction)
        except:
            return None, None

    def verify_signature(self, signature, message, verification_key):
        "This method verifies signature of message"
        pk, compressed = pubkey_from_signature(signature, Hash(msg_magic(message)))
        pubkey = point_to_ser(pk.pubkey.point, compressed).hex()
        return pubkey == verification_key
        # address_from_signature = public_key_to_p2pkh(point_to_ser(pk.pubkey.point, compressed))
        # address_from_vk = self.address(verification_key)
        # return address_from_signature == address_from_vk
