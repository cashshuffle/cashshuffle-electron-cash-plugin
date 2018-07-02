import sys
from time import sleep, time
import argparse
import requests
import schedule
from electroncash.network import Network, SimpleConfig
from electroncash.address import Address
from electroncash.bitcoin import deserialize_privkey, regenerate_key
from electroncash.networks import NetworkConstants
from electroncash_plugins.shuffle.client import ProtocolThread
from electroncash_plugins.shuffle.coin import Coin
from electroncash.storage import WalletStorage
from electroncash.wallet import Wallet


def parse_args():
    parser = argparse.ArgumentParser(description="CashShuffle bot")
    parser.add_argument("--testnet", action="store_true", dest="testnet", default=False, help="Use Testnet")
    parser.add_argument("--ssl", action="store_true", dest="ssl", default=False, help="enable ssl")
    parser.add_argument("-P", "--port", help="cashshuffle server port", type=int, required=True)
    parser.add_argument("-I", "--stat-port", help="cashshuffle statistics server port", type=int, required=True)
    parser.add_argument("-S", "--server", help="cashshuffle server port", type=str, required=True)
    parser.add_argument("-F", "--fee", help="fee value", type=int, default=1000)
    parser.add_argument("-L", "--limit", help="minimal number of players to enter the pool", type=int, default=1)
    parser.add_argument("-M", "--maximum-per-pool", help="maximal number of players to support the pool", type=int, default=1)
    parser.add_argument("-W", "--wallet", help="wallet", type=str, required=True)
    parser.add_argument("--password", help="wallet password", type=str, default ="")
    parser.add_argument("-T", "--period", help="period for checking the server in minutes", type=int, default=10)
    # test_params = "--testnet -P 33333 -S localhost -I 5000 -W plugins/shuffle/wallet/test_wallet --password testwallet -L 2".split()
    return parser.parse_args()

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
        print("[CashShuffle Bot] {}".format(message))
        if message.startswith("Error"):
            self.pThread.done.set()
        elif message.startswith("Blame"):
            if "insufficient" in message:
                pass
            elif "wrong hash" in message:
                pass
            else:
                self.pThread.done.set()

def job():
    job_start_time = time()
    pools = []
    pool_size = None
    try:
        res = requests.get(stat_endpoint, verify=False)
        pools = res.json().get("pools", [])
        pool_size = res.json().get("PoolSize", None)
    except:
        basic_logger.send("[CashShuffle Bot] Stat server not respond")
        return
    if len(pools) > 0:
        # Select not full pools with members more then limit
        members = [pool for pool in pools
                   if not pool.get("full", False) and
                   pool.get("members", 0) >= args.limit]
        # Select unspent outputs in the wallet
        utxos = wallet.get_utxos(exclude_frozen=True, confirmed_only=True)
        # Select fresh inputs
        fresh_outputs = wallet.get_unused_addresses()
        if len(members) == 0:
            basic_logger.send("[CashShuffle] No pools sutisfiying the requirments")
        else:
            basic_logger.send("[CashShuffle] Trying to support {} pools".format(len(members)))
        for member in members:
            number_of_players = member['members']
            threshold = min(number_of_players + args.maximum_per_pool, pool_size)
            member.update({"addresses" : []})
            amount = member['amount'] + fee
            good_utxos = [utxo for utxo in utxos if utxo['value'] > amount]
            for good_utxo in good_utxos:
                addr = Address.to_string(good_utxo['address'], Address.FMT_LEGACY)
                try:
                    first_utxo = coin.get_first_sufficient_utxo(addr, amount)
                    if first_utxo:
                        address = {}
                        address.update({"input_address": good_utxo['address']})
                        address.update({"change_address": addr})
                        address.update({"shuffle_address": Address.to_string(fresh_outputs[0], Address.FMT_LEGACY)})
                        member['addresses'].append(address)
                        del fresh_outputs[0]
                        utxos.remove(good_utxo)
                        number_of_players += 1
                        if number_of_players == threshold:
                            break
                except Exception as e:
                    basic_logger.send("[CashShuffle Bot] {}".format(e))
                    basic_logger.send("[CashShuffle Bot] Network problems")
        print(members)
        # Define Protocol threads
        pThreads = []
        for member in members:
            amount = member["amount"]
            if member.get("addresses", None):
                for address in member.get("addresses"):
                    priv_key = wallet.export_private_key(address["input_address"], password)
                    sk, pubk = keys_from_priv(priv_key)
                    new_addr = address["shuffle_address"]
                    change = address["change_address"]
                    logger = SimpleLogger()
                    pThread = (ProtocolThread(host, port, network, amount, fee, sk, pubk, new_addr, change, logger=logger, ssl=ssl))
                    logger.pThread = pThread
                    pThreads.append(pThread)
        # start Threads
        for pThread in pThreads:
            pThread.start()
        done = False
        while not done:
            sleep(1)
            done = all([is_protocol_done(pThread) for pThread in pThreads])
            if (time() - job_start_time) > 1000:
                "Protocol execution Time Out"
                done = True
        for pThread in pThreads:
            pThread.join()
    else:
        basic_logger.send("[CashShuffle Bot] Nobody in the pools")

basic_logger = SimpleLogger()
args = parse_args()
# Get network
config = SimpleConfig({})
password = args.password
wallet_path = args.wallet
storage = WalletStorage(wallet_path)
if not storage.file_exists():
    basic_logger.send("Error: Wallet file not found.")
    sys.exit(0)
if storage.is_encrypted():
    storage.decrypt(password)
if args.testnet:
    NetworkConstants.set_testnet()
    config = SimpleConfig({'server':"bch0.kister.net:51002:s"})
network = Network(config)
network.start()
wallet = Wallet(storage)
wallet.start_threads(network)
coin = Coin(network)
# # setup server
port = args.port
host = args.server
stat_port = args.stat_port
ssl = args.ssl
fee = args.fee
secured = ("s" if ssl else "")
stat_endpoint = "http{}://{}:{}/stats".format(secured, host, stat_port)

schedule.every(args.period).minutes.do(job)

while True:
    schedule.run_pending()
    sleep(30)
## Delete later
network.stop()
wallet.stop_threads()
