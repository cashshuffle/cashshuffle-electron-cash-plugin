class BlameException(Exception):
    pass

class Round(object):
    """
    A single round of the protocol. It is possible that the players may go through
    several failed rounds until they have eliminated malicious players.
    """

    def __init__(self, coin, crypto, messages, inchan, outchan, logchan , session , phase, amount, fee, sk, pubkey, players, addr_new, change):

        self.__coin = coin
        self.__crypto = crypto
        self.__inchan = inchan
        self.__outchan = outchan
        self.__logchan = logchan
        self.__session = session
        self.__messages = messages
        self.__phase = phase
        #The amount to be shuffled.
        if amount >= 0:
            self.__amount = amount
        else:
            raise ValueError('wrong amount value')
        # The miner fee to be paid per player.
        if fee >= 0:
            self.__fee = fee
        else:
            raise ValueError('wrong fee value')
        # My signing private key
        self.__sk = sk
        # Which player am I?
        self.__me = None
        # The number of players.
        self.__N = None
        # The players' public keys
        if type(players) is dict:
            self.__players = players
            # The number of players.
            self.__N = len(players) # Do we realy need it?
        else:
            raise TypeError('Players should be stored in dict object')
        # My verification public key, which is also my identity.
        self.__vk = pubkey
        # decryption key
        if self.__N == len(set(players.values())):
            if self.__vk in players.values():
                self.__me = { players[player] : player for player in players}[self.__vk]

            else:
                raise ValueError('My public key is not in players list')
        else:
            raise ValueError('Same public keys appears!')
        # decryption key
        self.__encryption_keys = dict()
        # The set of new addresses into which the coins will be deposited.
        self.__new_addresses = set()
        self.__addr_new = addr_new
        # My change address. (may be null).
        self.__change = change
        self.__change_addresses = {}
        self.__signatures = dict()
        self.__inbox = {self.__messages.phases[phase]:{} for phase in self.__messages.phases}
        self.__debug = False
        self.tx = None
        self.done = None

    def inchan_to_inbox(self):
        """
        This method do the follows:
            1. reads from incoming channels
            2. parse the incoming message
            3. store the packets from message to inbox[phase][from_key]
        Then methods reads from inbox not from inchan. I need it to cathc the message from "future"
        """
        try:
            val = self.__inchan.recv()
            if val is None:
                return None
            else:
                self.__messages.packets.ParseFromString(val)
        except Exception:
            self.__logchan.send('Decoding Error!')
        phase = self.__messages.get_phase()
        from_key = self.__messages.get_from_key()
        self.__inbox[phase][from_key] = val
        for sig, msg, player in self.__messages.get_signatures_and_packets():
            if not self.__coin.verify_signature(sig, msg, player):
                self.__messages.clear_packets()
                self.__messages.blame_invalid_signature(self.__players[player])
                self.send_message()
                self.__logchan.send('Blame: player ' + player + ' message with wrong signature!')
                raise BlameException('Player ' + player + ' message with wrong signature!')
        # blames = self.__messages.get_blame()
        if phase == 7: # Normal alias should go here
            self.__logchan.send('Blame: got Blame message from another player')
            raise BlameException('Exit by Blame')
        # if blames:
        #     print('I recieve the blame actually')
        #     self.__logchan.send("Blame on you!")
        if self.__debug:
            self.__logchan.send("Player " + str(self.__me)+"\n"+str(self.__inbox))
        return True

    def send_message(self, destination = None):
        self.__messages.form_all_packets(self.__sk, self.__session, self.__me, self.__vk, destination, self.__phase)
        self.__outchan.send(self.__messages.packets.SerializeToString())

    def blame_insufficient_funds(self):
        offenders = list()
        for player in self.__players:
            # address = public_key_to_p2pkh(players[player])
            address = self.__coin.address(self.__players[player])
            if not self.__coin.sufficient_funds(address,self.__amount + self.__fee):
                offenders.append(self.__players[player])
        if len(offenders) == 0:
            return
        else:
            self.__phase = "Blame"
            for offender in offenders:
                self.__messages.blame_insufficient_funds(offender)
                self.send_message()
                #log the Exception
                self.__logchan.send('Blame: insufficient funds of player ' + str(list(self.__players.keys())[list(self.__players.values()).index(offender)]))
            raise BlameException('Insufficient funds')

    def broadcast_new_key(self):
        # Generate encryption/decryption pair
        self.__crypto.generate_key_pair()
        # Broadcast the public key and store it in the set with everyone else's.
        self.__messages.clear_packets()
        self.__messages.add_encryption_key(self.__crypto.export_public_key(), self.__change)
        self.send_message()

    # In phase 1, everybody announces their new encryption keys to one another. They also
    # optionally send change addresses to one another. This function reads that information
    # from a message and puts it in some nice data structures.

    def encrypt_new_address(self):
        # Add our own address to the mix. Note that if me == N, ie, the last player, then no
        # encryption is done. That is because we have reached the last layer of encryption.
        encrypted = self.__addr_new
        for i in range(self.__N , self.__me, -1):
            # Successively encrypt with the keys of the players who haven't had their turn yet.
            encrypted = self.__crypto.encrypt(encrypted, self.__encryption_keys[self.__players[i]])
        return encrypted

    def process_inbox(self):
        phase = self.__messages.phases[self.__phase]
        # Announcement
        if self.__phase is 'Announcement':
            if len(self.__inbox[phase]) == self.__N:
                messages = self.__inbox[phase]
                for message in messages:
                    self.__messages.packets.ParseFromString(messages[message])
                    from_key = self.__messages.get_from_key()
                    self.__encryption_keys[from_key] = self.__messages.get_encryption_key()
                    self.__change_addresses[from_key] = self.__messages.get_address()
                if (len(self.__encryption_keys) == self.__N):
                    self.__logchan.send('Player '+ str(self.__me) + ' recieved all keys for test.')
                    self.__phase = 'Shuffling'
                    self.__logchan.send("Player " + str( self.__me) + " reaches phase 2.")
                    self.__messages.clear_packets()
                    if self.__me == 1:
                        self.__messages.add_str(self.encrypt_new_address())
                        self.send_message(destination = self.__players[self.__me + 1])
                        self.__logchan.send("Player " + str(self.__me) + " encrypt new address")
                        self.__phase = 'BroadcastOutput'
        # Shuffling
        elif self.__phase is 'Shuffling':
            if self.__me == self.__N:
                sender = self.__players[self.__N - 1]
                if self.__inbox[phase].get(sender):
                    self.__messages.packets.ParseFromString(self.__inbox[phase][sender])
                    for packet in self.__messages.packets.packet:
                        packet.packet.message.str = self.__crypto.decrypt(packet.packet.message.str)
                    # add the last address
                    self.__messages.add_str(self.__addr_new)
                    # shuffle the packets
                    self.__messages.shuffle_packets()
                    # form packet ...
                    self.__phase = 'BroadcastOutput'
                    self.send_message()
                    self.__logchan.send("Player " + str(self.__me) + " encrypt new address")
            else:
                sender = self.__players[self.__me - 1]
                if self.__inbox[phase].get(sender):
                    self.__messages.packets.ParseFromString(self.__inbox[phase][sender])
                    for packet in self.__messages.packets.packet:
                        packet.packet.message.str = self.__crypto.decrypt(packet.packet.message.str)
                    # add encrypted new addres of players
                    self.__messages.add_str(self.encrypt_new_address())
                    # shuffle the packets
                    self.__messages.shuffle_packets()
                    self.send_message(destination = self.__players[self.__me + 1])
                    self.__logchan.send("Player " + str(self.__me) + " encrypt new address")
                    self.__phase = 'BroadcastOutput'
        # BroadcastOutput
        elif self.__phase is 'BroadcastOutput':
            sender = self.__players[self.__N]
            if self.__inbox[phase].get(sender):
                # extract addresses from packets
                self.__messages.packets.ParseFromString(self.__inbox[phase][sender])
                # self.__logchan.send("Player #" + str(self.__me) +"\n"+ str(self.__messages.packets))
                self.__new_addresses = self.__messages.get_new_addresses()
                #check if player address is in
                # self.__logchan.send('new addresses\n' + str(self.__new_addresses))
                if self.__addr_new in self.__new_addresses:
                    self.__logchan.send("Player "+ str(self.__me) + " receive addresses and found itsefs")
                else:
                    self.__messages.clear_packets()
                    self.__messages.blame_missing_output(self.__vk)
                    self.send_message()
                    self.__logchan.send("Blame: player " + str(self.__me) + "  not found itsefs new address")
                    raise BlameException("Blame: player " + str(self.__me) + "  not found itsefs new address")
                self.__phase = 'EquivocationCheck'
                self.__logchan.send("Player "+ str(self.__me) + " reaches phase 4: ")
                # compute hash
                # computed_hash =str(self.__crypto.hash( str(self.__new_addresses) + str([self.__encryption_keys[self.__players[i]] for i in range(1, self.__N + 1) ])))
                computed_hash =self.__crypto.hash( str(self.__new_addresses) + str([self.__encryption_keys[self.__players[i]] for i in range(1, self.__N + 1) ]))
                # create a new message
                self.__messages.clear_packets()
                # add new hash
                self.__messages.add_hash(computed_hash)
                self.send_message()
        elif self.__phase is 'EquivocationCheck':
            computed_hash =self.__crypto.hash( str(self.__new_addresses) + str([self.__encryption_keys[self.__players[i]] for i in range(1, self.__N + 1) ]))
            if len(self.__inbox[phase]) == self.__N:
                messages = self.__inbox[phase]
                for player in messages:
                    self.__messages.packets.ParseFromString(messages[player])
                    hash_value = self.__messages.get_hash()
                    if hash_value != computed_hash:
                        self.__messages.clear_packets()
                        self.__messages.blame_equivocation_failure(self.__players[player])
                        self.send_message()
                        self.__logchan.send('Blame: wrong hash computed by player' + str(player))
                        raise BlameException('Wrong hash computed by player ' + str(player))
                self.__logchan.send('Player ' + str(self.__me) + ' is checked the hashed.')
                self.__phase = 'VerificationAndSubmission'
                self.__logchan.send("Player "+ str(self.__me) + " reaches phase 5: ")
                inputs = {self.__players[player]:self.__coin.address(self.__players[player])  for player in self.__players}
                self.transaction = self.__coin.make_unsigned_transaction(self.__amount, self.__fee, inputs, self.__new_addresses, self.__change_addresses)
                signature = self.__coin.get_transaction_signature(self.transaction, self.__sk, self.__vk)
                self.__messages.clear_packets()
                self.__messages.add_signature(signature)
                self.send_message()
                self.__logchan.send("Player " + str(self.__me) + " send transction signature")
        elif self.__phase is 'VerificationAndSubmission':
                if len(self.__inbox[phase]) == self.__N:
                    self.signatures = {}
                    self.__logchan.send("Player " + str(self.__me) + " got transction signatures")
                    for player in self.__players:
                        self.__messages.packets.ParseFromString(self.__inbox[phase][self.__players[player]])
                        player_signature = self.__messages.get_signature()
                        self.signatures[self.__players[player]] = player_signature
                        check = self.__coin.verify_tx_signature(player_signature, self.transaction, self.__players[player])
                        if not check:
                            self.__messages.clear_packets()
                            self.__messages.blame_wrong_transaction_signature(self.__players[player])
                            self.send_message()
                            self.__logchan.send('Blame: wrong transaction signature from player ' + str(player))
                            raise BlameException('Wrong tx signature from player ' + str(player))

                    # add signing
                    self.__coin.add_transaction_signatures(self.transaction, self.signatures)
                    self.tx = self.transaction
                    self.__logchan.send("Player " + str(self.__me) + " complete protocol")
                    self.done = True


    def protocol_loop(self):
        if self.__amount <= 0:
            raise ValueError('wrong amount for transaction')
        # Phase 1: Announcement
        # In the announcement phase, participants distribute temporary encryption keys.
        self.__phase = 'Announcement'
        self.__logchan.send("Player " + str(self.__me) + " begins CoinShuffle protocol " + " with " + str(self.__N) + " players.")
        # Check for sufficient funds.
        # There was a problem with the wording of the original paper which would have meant
        # that player 1's funds never would have been checked, but it's necessary to check
        # everybody.
        self.blame_insufficient_funds()
        self.__logchan.send("Player " + str(self.__me) + " finds sufficient funds.")
        self.broadcast_new_key()
        self.__logchan.send("Player " + str(self.__me) + " has broadcasted the new encryption key.")
        # Now we wait to receive similar key from everyone else.
        #TO Reciver form multiple
        self.__logchan.send("Player " + str( self.__me) + " is about to read announcements.")

        while not self.done:
            if self.inchan_to_inbox():
                self.process_inbox()
