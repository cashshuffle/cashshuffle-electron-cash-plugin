from test import TestProtocolCase
from electroncash.bitcoin import public_key_to_p2pkh

class TestProtocol(TestProtocolCase):

    def test_002_insufficient_funds(self):
        protocolThreads = self.make_clients_threads(with_print = True)
        # make insufficient funds for first player
        bad_addr = public_key_to_p2pkh(bytes.fromhex(protocolThreads[0].vk))
        # print(self.network.coins[bad_addr][0]['value'])
        self.network.coins[bad_addr][0]['value'] = self.amount - 1
        self.start_protocols(protocolThreads)
        done = False
        while not done:
            alives = [self.is_round_live(p) for p in protocolThreads[1:]]
            done = False if None in alives else not all(alives)
        self.stop_protocols(protocolThreads)
        tx = protocolThreads[1].protocol.tx.raw
        for pThread in protocolThreads[2:]:
            self.assertEqual(tx, pThread.protocol.tx.raw)
