import unittest
from test import TestProtocolCase
from electroncash.bitcoin import public_key_to_p2pkh

class TestProtocol(TestProtocolCase):

    def test_001_same_keys_appears(self):
        protocolThreads = self.make_clients_threads()
        protocolThreads[0].vk = protocolThreads[1].vk
        self.start_protocols(protocolThreads)
        done = False
        while not done:
            for p in protocolThreads:
                if p.done.is_set():
                    done = True
                    break
        self.stop_protocols(protocolThreads)
        last_messages = [self.get_last_logger_message(pThread) for pThread in protocolThreads]
        self.assertIn('Error: The same keys appears!', last_messages)

    def test_002_insufficient_funds(self):
        protocolThreads = self.make_clients_threads(with_print = True)
        bad_addr = public_key_to_p2pkh(bytes.fromhex(protocolThreads[0].vk))
        self.network.coins[bad_addr][0]['value'] = self.amount - 1
        self.start_protocols(protocolThreads)
        done = False
        while not done:
            completes = [self.is_protocol_complete(p) for p in protocolThreads[1:]]
            done = all(completes)
        self.stop_protocols(protocolThreads)
        tx = protocolThreads[1].protocol.tx.raw
        for pThread in protocolThreads[2:]:
            self.assertEqual(tx, pThread.protocol.tx.raw)
