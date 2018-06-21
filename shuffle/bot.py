from time import sleep
import argparse
import requests
import schedule
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

def job():
    logger = SimpleLogger()
    res = requests.get(stat_endpoint)
    pools = res.json().get("pools", [])
    if len(pools) > 0:
        members = [pool.get("members", 0) for pool in pools
                   if not pool.get("fool", False)
                   and pool.get("amount") == amount][0]
        if members >= args.limit:
            # network.start()
            sleep(5)
            pThread = ProtocolThread(host, port, network, amount, fee, sk, pubk, new_addr, change, logger=logger)
            logger.pThread = pThread
            pThread.start()
            while not is_protocol_done(pThread):
                sleep(1)
            # network.stop()
            pThread.join()
            pThread = None
        else:
            logger.send("Not enough members")
    else:
        logger.send("Noone in the pools")

#parser
parser = argparse.ArgumentParser(description="CashShuffle bot")
parser.add_argument("--testnet", action="store_true", dest="testnet", default=False, help="Use Testnet")
parser.add_argument("-P", "--port", help="cashshuffle server port", type=int, required=True)
parser.add_argument("-I", "--stat-port", help="cashshuffle statistics server port", type=int, required=True)
parser.add_argument("-S", "--server", help="cashshuffle server port", type=str, required=True)
parser.add_argument("-A", "--amount", help="amount to shuffle", type=int, choices=[1e6, 1e5, 1e3], default=1e3)
parser.add_argument("-F", "--fee", help="fee value", type=int, default=1000)
parser.add_argument("-L", "--limit", help="minimal number of players to enter the pool", type=int, default=1)
parser.add_argument("-K", "--key", help="private key of input address", type=str, required=True)
parser.add_argument("-N", "--new-address", help="output address", type=str, required=True)
parser.add_argument("-C", "--change", help="change address", type=str, required=True)
parser.add_argument("-T", "--period", help="period for checking the server in minutes", type=int, default=10)



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
stat_port = args.stat_port
# setup amounts (in satoshis)
amount = args.amount
fee = args.fee
# privkey
priv_key = args.key
sk, pubk = keys_from_priv(priv_key)
print(pubk)
# new address and change
new_addr = args.new_address
change = args.change
from electroncash.address import Address
#Start protocol thread
stat_endpoint = "http://{}:{}/stats".format(host, stat_port)

schedule.every(args.period).minutes.do(job)

while True:
    schedule.run_pending()
    sleep(60)
