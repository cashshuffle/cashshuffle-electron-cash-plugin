class BlameException(Exception):
    pass

class Round(object):
    """
    A single round of the protocol. It is possible that the players may go through
    several failed rounds until they have eliminated malicious players.
    """

    def __init__(self, coin, crypto, messages, inchan, outchan, logchan , session , phase, amount, fee, sk, pubkey, players, addr_new, change):

        self.coin = coin
        self.crypto = crypto
        self.inchan = inchan
        self.outchan = outchan
        self.logchan = logchan
        self.session = session
        self.messages = messages
        self.phase = phase
        assert (amount > 0), 'Wrong amount value'
        self.amount = amount
        assert (fee > 0), 'Wrong fee value'
        self.fee = fee
        self.sk = sk
        self.me = None
        self.N = None
        assert(type(players) is dict), "Players should be stored in dict"
        self.players = players
        self.N = len(players)
        self.vk = pubkey
        if self.N == len(set(players.values())):
            if self.vk in players.values():
                self.me = { players[player] : player for player in players}[self.vk]
            else:
                self.logchan('Error: publick key is not in the players list')
                raise ValueError('My public key is not in players list')
        else:
            self.logchan.send('Error: same publick keys appears in the pool!')
            raise ValueError('Same public keys appears!')
        self.encryption_keys = dict()
        self.new_addresses = set()
        self.addr_new = addr_new
        self.change = change
        self.change_addresses = {}
        self.signatures = dict()
        self.inbox = {self.messages.phases[phase]:{} for phase in self.messages.phases}
        self.debug = False
        self.tx = None
        self.done = None

    def first_player(self):
        return min(sorted(self.players))

    def last_player(self):
        return max(sorted(self.players))

    def next_player(self, player = None):
        player = self.me if player is None else player
        if player is not self.last_player():
            # with sorted(self.players) as players:
            #     return players[players.index(player) + 1]
            return sorted(self.players)[sorted(self.players).index(player) + 1]
        else:
            return None

    def previous_player(self, player = None):
        player = self.me if player is None else player
        if player is not self.first_player():
            return sorted(self.players)[sorted(self.players).index(player) - 1]
        else:
            return None

    def from_last_to_previous(self):
        index = sorted(self.players).index(self.next_player())
        return reversed(sorted(self.players)[index:])

    def check_for_signatures(self):
        for sig, msg, player in self.messages.get_signatures_and_packets():
            if not self.coin.verify_signature(sig, msg, player):
                self.messages.clear_packets()
                self.messages.blame_invalid_signature(self.players[player])
                self.send_message()
                self.logchan.send('Blame: player ' + player + ' message with wrong signature!')
                raise BlameException('Player ' + player + ' message with wrong signature!')

    def ban_the_liar(self, accused):
        self.messages.clear_packets()
        self.messages.blame_the_liar(accused)
        self.send_message(destination = self.vk)

    def inchan_to_inbox(self):
        """
        This method do the follows:
            1. reads from incoming channels
            2. parse the incoming message
            3. store the packets from message to inbox[phase][from_key]
        Then methods reads from inbox not from inchan. I need it to cathc the message from "future"
        """
        try:
            val = self.inchan.recv()
            if val is None:
                return None
            else:
                self.messages.packets.ParseFromString(val)
        except Exception:
            self.logchan.send('Decoding Error!')
        phase = self.messages.get_phase()
        from_key = self.messages.get_from_key()
        self.check_for_signatures()
        if from_key in self.players.values():
            self.inbox[phase][from_key] = val
        if self.debug:
            self.logchan.send("Player " + str(self.me)+"\n"+str(self.inbox))
        return True

    def send_message(self, destination = None):
        self.messages.form_all_packets(self.sk, self.session, self.me, self.vk, destination, self.phase)
        self.outchan.send(self.messages.packets.SerializeToString())

    def blame_insufficient_funds(self):
        offenders = list()
        for player in self.players:
            address = self.coin.address(self.players[player])
            if not self.coin.sufficient_funds(address,self.amount + self.fee):
                offenders.append(self.players[player])
        if len(offenders) == 0:
            self.logchan.send("Player " + str(self.me) + " finds sufficient funds.")
            return True
        else:
            self.phase = "Blame"
            old_players  = self.players.copy()
            self.players = {player:self.players[player] for player in self.players if self.players[player] not in offenders}
            for offender in offenders:
                self.messages.clear_packets()
                self.messages.blame_insufficient_funds(offender)
                self.send_message()
                self.logchan.send('Blame: insufficient funds of player ' + str(list(old_players.keys())[list(old_players.values()).index(offender)]))
            if len(self.players) > 1:
                self.N = len(self.players)
            else:
                self.logchan.send('Error: not enough players with sufficent funds')
                raise Exception('Error: not enough players with sufficent funds')
            if self.vk in offenders:
                self.logchan.send('Error: players funds is not enough')
                raise Exception('Error: players funds is not enough')
            return False

    def broadcast_new_key(self):
        self.phase = 'Announcement'
        self.crypto.generate_key_pair()
        self.messages.clear_packets()
        self.messages.add_encryption_key(self.crypto.export_public_key(), self.change)
        self.send_message()
        self.logchan.send("Player " + str(self.me) + " has broadcasted the new encryption key.")
        self.logchan.send("Player " + str( self.me) + " is about to read announcements.")

    def encrypt_new_address(self):
        encrypted = self.addr_new
        for i in self.from_last_to_previous():
            encrypted = self.crypto.encrypt(encrypted, self.encryption_keys[self.players[i]])
        return encrypted

    def different_ciphertexts(self):
        ciphertexts = self.messages.get_new_addresses()
        return len(ciphertexts) == len(set(ciphertexts))

    def is_inbox_complete(self, phase):
        return len(self.inbox[phase]) == self.N

    def skipped_equivocation_check(self, accused):
        string_to_hash = str([self.encryption_keys[self.players[i]] for i in sorted(self.players)])
        computed_hash = self.crypto.hash(string_to_hash)
        self.messages.clear_packets()
        self.messages.blame_shuffle_failure(accused, computed_hash)
        self.phase  = 'Blame'
        self.send_message()

    def check_for_blame(self):
        if self.inbox[7]:
            return True
        else:
            return False

    def check_reasons_and_accused(self, reason):
        if not self.messages.get_blame_reason() == reason:
            self.logchan.send("Blame: different blame reasons from players")
            raise BlameException("Blame: different blame reasons from players")
        elif self.messages.get_accused_key in self.players.values():
            self.logchan.send("Blame: different blame players from players")
            raise BlameException("Blame: different blame players from players")

    def check_for_shuffling(self):
        shufflings = {}
        cheater = None
        phase_blame = self.messages.phases["Blame"]
        for player in self.inbox[phase_blame]:
            self.messages.packets.ParseFromString(self.inbox[phase_blame][player])
            shufflings[player] = {}
            shufflings[player]['encryption_key'] = self.messages.get_public_key()
            shufflings[player]['decryption_key'] = self.messages.get_decryption_key()
            invalid_packets = self.messages.get_invalid_packets()
            self.messages.packets.ParseFromString(invalid_packets)
            shufflings[player]['strs'] = [packet.packet.message.str for packet in self.messages.packets.packet]
        for player in sorted(self.players)[1:]:
            for i in sorted(self.players):
                if i >= player:
                    self.crypto.restore_from_privkey(shufflings[self.players[i]]['decryption_key'])
                    shufflings[self.players[player]]['strs'] = [self.crypto.decrypt(enc_str) for enc_str in shufflings[self.players[player]]['strs']]
        for pl_out, pl_in in zip(sorted(self.players)[1:-1], sorted(self.players)[2:]):
            marker = len(set(shufflings[self.players[pl_out]]['strs']) ^ set(shufflings[self.players[pl_in]]['strs'])) == 1
            if not marker:
                 cheater =  self.players[pl_out]
                 self.logchan.send('cheater is ' + str(pl_out))
                 break
        return cheater

    def process_announcement(self):
        phase = self.messages.phases[self.phase]
        if self.is_inbox_complete(phase):
            messages = self.inbox[phase]
            self.encryption_keys = dict()
            self.change_addresses = {}
            for message in messages:
                self.messages.packets.ParseFromString(messages[message])
                from_key = self.messages.get_from_key()
                self.encryption_keys[from_key] = self.messages.get_encryption_key()
                self.change_addresses[from_key] = self.messages.get_address()
            if len(self.encryption_keys) == self.N:
                self.logchan.send('Player '+ str(self.me) + ' recieved all keys for test.')
                self.phase = 'Shuffling'
                self.logchan.send("Player " + str( self.me) + " reaches phase 2.")
                self.messages.clear_packets()
                if self.me == self.first_player():
                    self.messages.add_str(self.encrypt_new_address())
                    self.send_message(destination = self.players[self.next_player()])
                    self.logchan.send("Player " + str(self.me) + " encrypt new address")
                    self.phase = 'BroadcastOutput'

    def process_shuffling(self):
        phase = self.messages.phases[self.phase]
        if self.me == self.last_player():
            sender = self.players[self.previous_player(player = self.last_player())]
            if self.inbox[phase].get(sender):
                self.messages.packets.ParseFromString(self.inbox[phase][sender])
                for packet in self.messages.packets.packet:
                    packet.packet.message.str = self.crypto.decrypt(packet.packet.message.str)
                self.messages.add_str(self.addr_new)
                self.messages.shuffle_packets()
                self.phase = 'BroadcastOutput'
                self.send_message()
                self.logchan.send("Player " + str(self.me) + " encrypt new address")
        else:
            sender = self.players[self.previous_player()]
            if self.inbox[phase].get(sender):
                self.messages.packets.ParseFromString(self.inbox[phase][sender])
                for packet in self.messages.packets.packet:
                    packet.packet.message.str = self.crypto.decrypt(packet.packet.message.str)
                if self.different_ciphertexts():
                    self.messages.add_str(self.encrypt_new_address())
                    self.messages.shuffle_packets()
                    self.send_message(destination = self.players[self.next_player()])
                    self.logchan.send("Player " + str(self.me) + " encrypt new address")
                    self.phase = 'BroadcastOutput'
                else:
                    self.skipped_equivocation_check(sender)
                    self.logchan.send("Player "+ str(self.me) + " wrong from " + str(sender))

    def process_broadcast_output(self):
        phase = self.messages.phases[self.phase]
        sender = self.players[self.last_player()]
        if self.inbox[phase].get(sender):
            self.messages.packets.ParseFromString(self.inbox[phase][sender])
            self.new_addresses = self.messages.get_new_addresses()
            if self.addr_new in self.new_addresses:
                self.logchan.send("Player "+ str(self.me) + " receive addresses and found itsefs")
            else:
                self.logchan.send("Blame: player " + str(self.me) + "  not found itsefs new address")
                self.skipped_equivocation_check(sender)
                return
            self.phase = 'EquivocationCheck'
            self.logchan.send("Player "+ str(self.me) + " reaches phase 4: ")
            computed_hash =self.crypto.hash(str(self.new_addresses) + str([self.encryption_keys[self.players[i]] for i in sorted(self.players) ]))
            self.messages.clear_packets()
            self.messages.add_hash(computed_hash)
            self.send_message()

    def process_equivocation_check(self):
        phase = self.messages.phases[self.phase]
        computed_hash = self.crypto.hash( str(self.new_addresses) + str([self.encryption_keys[self.players[i]] for i in sorted(self.players) ]))
        if len(self.inbox[phase]) == self.N:
            messages = self.inbox[phase]
            for player in messages:
                self.messages.packets.ParseFromString(messages[player])
                hash_value = self.messages.get_hash()
                if hash_value != computed_hash:
                    phase1_packets = b"".join(list(self.inbox[self.messages.phases["Announcement"]].values()))
                    phase3_packets = b"".join(list(self.inbox[self.messages.phases["BroadcastOutput"]].values()))
                    packets_for_send = phase1_packets + phase3_packets
                    self.messages.clear_packets()
                    self.messages.blame_equivocation_failure(player, invalid_packets = packets_for_send)
                    self.phase = "Blame"
                    self.send_message()
                    cheater = [p for p in self.players if self.players[p] == player][0]
                    self.logchan.send("Player " + str(self.me) +" find bad hash from " +str(cheater))
                    self.logchan.send('Blame: wrong hash computed by player ' + str(cheater))
                    return
            self.phase = 'VerificationAndSubmission'
            self.logchan.send("Player "+ str(self.me) + " reaches phase 5: ")
            inputs = {self.players[player]:self.coin.address(self.players[player]) for player in self.players}
            self.transaction = self.coin.make_unsigned_transaction(self.amount, self.fee, inputs, self.new_addresses, self.change_addresses)
            signature = self.coin.get_transaction_signature(self.transaction, self.sk, self.vk)
            self.messages.clear_packets()
            self.messages.add_signature(signature)
            self.send_message()
            self.logchan.send("Player " + str(self.me) + " send transction signature")

    def process_verification_and_submission(self):
        phase = self.messages.phases[self.phase]
        if len(self.inbox[phase]) == self.N:
            self.signatures = {}
            self.logchan.send("Player " + str(self.me) + " got transction signatures")
            for player in self.players:
                self.messages.packets.ParseFromString(self.inbox[phase][self.players[player]])
                player_signature = self.messages.get_signature()
                self.signatures[self.players[player]] = player_signature
                check = self.coin.verify_tx_signature(player_signature, self.transaction, self.players[player])
                if not check:
                    self.messages.clear_packets()
                    self.messages.blame_wrong_transaction_signature(self.players[player])
                    self.send_message()
                    self.logchan.send('Blame: wrong transaction signature from player ' + str(player))
                    raise BlameException('Wrong tx signature from player ' + str(player))
            self.coin.add_transaction_signatures(self.transaction, self.signatures)
            self.tx = self.transaction
            self.logchan.send("Player " + str(self.me) + " complete protocol")
            self.done = True

    def process_blame_insufficient_funds(self, phase, reason):
        messages = self.inbox[phase]
        if len(messages) == self.N:
            for sender in messages:
                self.messages.packets.ParseFromString(messages[sender])
                self.check_reasons_and_accused(reason)
            self.ban_the_liar(self.messages.get_accused_key())
            self.inbox[self.messages.phases["Blame"]] = {}
            self.broadcast_new_key()

    def process_blame_equivocation_failure(self, phase, reason):
        messages = self.inbox[phase]
        keys_matrix = {key:set() for key in self.players.values()}
        changes_matrix = {key:set() for key in self.players.values()}
        new_addresses_matrix = {key:set() for key in self.players.values()}
        if len(messages) == self.N:
            for sender in messages:
                self.messages.packets.ParseFromString(messages[sender])
                self.check_reasons_and_accused(reason)
                invalid_packets = self.messages.get_invalid_packets()
                self.messages.packets.ParseFromString(invalid_packets)
                self.check_for_signatures()
                for packet in self.messages.packets.packet:
                    if packet.packet.phase == 1:
                        keys_matrix[packet.packet.from_key.key].add(packet.packet.message.key.key)
                        changes_matrix[packet.packet.from_key.key].add(packet.packet.message.address.address)
                    if packet.packet.phase == 3:
                        new_addresses_matrix[sender].add(packet.packet.message.str)
            new_addresses_matrix.update((k,frozenset(v)) for k,v in new_addresses_matrix.items())
            key_cheaters = list(filter(lambda key: len(keys_matrix[key])>1, keys_matrix))
            change_cheaters = list(filter(lambda key: len(changes_matrix[key])>1, changes_matrix))
            all_cheaters = list(set(key_cheaters + change_cheaters))
            if len(set(new_addresses_matrix.values()))>1:
                all_cheaters.append(self.players[self.last_player()])
            if len(all_cheaters)>0:
                self.players = {player:self.players[player] for player in self.players if self.players[player] not in all_cheaters}
                self.N = len(self.players)
                for phase in self.messages.phases:
                    if not phase == "Announcement":
                        self.inbox[self.messages.phases[phase]] = {}
                phase_1 = self.messages.phases["Announcement"]
                self.inbox[phase_1] = {key:self.inbox[phase_1][key] for key in self.inbox[phase_1] if key not in all_cheaters}
                phase1_packets = self.inbox[phase_1].copy()
                encryption_keys = list(self.encryption_keys.values())
                for message in phase1_packets:
                    self.messages.packets.ParseFromString(phase1_packets[message])
                    ec = self.messages.get_encryption_key()
                    if ec in encryption_keys:
                        del self.inbox[phase_1][message]
                for player in all_cheaters:
                    self.ban_the_liar(player)
                if not self.vk in all_cheaters:
                    self.inbox[self.messages.phases["Blame"]] = {}
                    self.broadcast_new_key()

    def process_blame_shuffle_failure(self, phase, reason):
        phase_blame = self.messages.phases["Blame"]
        if len(self.inbox[phase_blame]) == 1:
            if not self.messages.get_from_key() == self.vk:
                self.skipped_equivocation_check(self.messages.get_accused_key())
        elif len(self.inbox[phase_blame]) == self.N:
            hashes = set()
            for player in self.inbox[phase_blame]:
                self.messages.packets.ParseFromString(self.inbox[phase_blame][player])
                hashes.add(self.messages.get_hash())
            if len(hashes) == 1:
                accused = self.messages.get_accused_key()
                ec = self.crypto.export_public_key()
                dc = self.crypto.export_private_key()
                phase2_packets = b"".join(list(self.inbox[self.messages.phases["Shuffling"]].values()))
                self.messages.clear_packets()
                self.messages.blame_shuffle_and_equivocation_failure(accused, ec, dc, phase2_packets)
                self.send_message()
                self.inbox[phase_blame] = {}
            else:
                raise('Blame!')

    def process_blame_shuffle_and_equivocation_failure(self, phase, reason):
        phase_blame = self.messages.phases["Blame"]
        if len(self.inbox[phase_blame]) == self.N:
            cheater = self.check_for_shuffling()
            if cheater:
                if not cheater == self.vk:
                    self.ban_the_liar(cheater)
                    self.players = {player:self.players[player] for player in self.players if not self.players[player] == cheater}
                    self.N = len(self.players)
                    self.inbox = {self.messages.phases[phase]:{} for phase in self.messages.phases}
                    self.broadcast_new_key()

    def process_blame(self):
        phase = self.messages.phases[self.phase]
        reason  = self.messages.get_blame_reason()
        {
            self.messages.blame_reason('Insufficient Funds') : self.process_blame_insufficient_funds,
            self.messages.blame_reason('Equivocation failure') : self.process_blame_equivocation_failure,
            self.messages.blame_reason('Shuffle Failure') : self.process_blame_shuffle_failure,
            self.messages.blame_reason('Shuffle and Equivocation Failure') : self.process_blame_shuffle_and_equivocation_failure
        }[reason](phase, reason)

    def process_inbox(self):
        if self.check_for_blame():
            self.process_blame()
        else:
            {'Announcement' : self.process_announcement,
             'Shuffling' : self.process_shuffling,
             'BroadcastOutput' : self.process_broadcast_output,
             'EquivocationCheck' : self.process_equivocation_check,
             'VerificationAndSubmission' : self.process_verification_and_submission,
             'Blame' : self.process_blame
            }[self.phase]()

    def protocol_loop(self):
        assert (self.amount > 0), "Wrong amount for transction"
        self.logchan.send("Player " + str(self.me) + " begins CoinShuffle protocol " + " with " + str(self.N) + " players.")
        if self.blame_insufficient_funds():
            self.broadcast_new_key()
        while not self.done:
            if self.inchan_to_inbox():
                self.process_inbox()
