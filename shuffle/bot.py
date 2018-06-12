from time import sleep
import argparse
from electroncash.network import Network, SimpleConfig
from electroncash.bitcoin import deserialize_privkey, regenerate_key
from electroncash.networks import NetworkConstants
from electroncash_plugins.shuffle.client import ProtocolThread

def keys_from_priv(priv_key):
    address, secret, compressed = deserialize_privkey(priv_key)
    sk = regenerate_key(secret)
    pubk = sk.get_public_key(compressed)
    return sk, pubk

def is_protocol_done(pThread):
    if pThread.protocol:
        return pThread.protocol.done
    else:
        return pThread.done.is_set()

class SimpleLogger(object):

    def __init__(self):
        self.pThread = None

    def send(self, message):
        print(message)
        if message.startswith("Error"):
            self.pThread.done.set()

#parser
parser = argparse.ArgumentParser(description="CashShuffle bot")
parser.add_argument("--testnet", action="store_true", dest="testnet", default=False, help="Use Testnet")
parser.add_argument("-P", "--port", help="cashshuffle server port", type=int, required=True)
parser.add_argument("-S", "--server", help="cashshuffle server port", type=str, required=True)
parser.add_argument("-A", "--amount", help="amount to shuffle", type=int, choices=[1e6, 1e5, 1e3], default=1e3)
parser.add_argument("-F", "--fee", help="fee value", type=int, default=1000)
parser.add_argument("-K", "--key", help="private key of input address", type=str, required=True)
parser.add_argument("-N", "--new-address", help="output address", type=str, required=True)
parser.add_argument("-C", "--change", help="change address", type=str, required=True)


args = parser.parse_args()
# Get network
config = SimpleConfig({})
if args.testnet:
    NetworkConstants.set_testnet()
    config = SimpleConfig({'server':"bch0.kister.net:51002:s"})
network = Network(config)
network.start()
# setup server
port = args.port
host = args.server
# setup amounts (in satoshis)
amount = args.amount
fee = args.fee
# privkey
priv_key = args.key
sk, pubk = keys_from_priv(priv_key)
# new address and change
new_addr = args.new_address
change = args.change
#Start protocol thread
logger = SimpleLogger()
pThread = ProtocolThread(host, port, network, amount, fee, sk, pubk, new_addr, change, logger=logger)
logger.pThread = pThread
pThread.start()
# sleep()
while not is_protocol_done(pThread):
    sleep(1)
