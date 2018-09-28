# Shuffle

CashShuffle is a plugin for the [Electron Cash](https://electroncash.org/) BCH wallet. The version of [Electron Cash](https://electroncash.org/) should be not less then `3.1.2` .It allows users to make shuffled transactions using [CoinJoin](https://en.wikipedia.org/wiki/CoinJoin).

WARNING: THIS IS PRE-RELEASE SOFTWARE. This has been made available to provide feedback and review!

## Installation

For installation of plugin do the follows:

1. Download the latest release of the plugin (it should be a zip file) from [here](/releases).

2. Open Electron Cash.

3. Go to "Tools" | "Installed Plugins"

4. Click the "Add Plugin" button.

5. Select the plugin release you just downloaded.

6. Confirm that you understand the risks and dangers (do read the dialog, don't just blindly click through)

7. Click "Install".

8. Restart Electron Cash and you now should see the "Shuffle" tab in the main window.


## Making a shuffle

1. Choose server from servers list

3. Use `Shuffle input addresses` to choose coins which you want to shuffle. This list of coins is formed from  the UTXO's of your wallet.

4. From `Shuffle change address` choose the address for your change. You can leave this as the default setting if you want to use input address as change address. If you wish to use change addresses which not been used before check the `use only fresh change aderesses` checkbox.

5. From `Shuffle output address` choose the address for the shuffled output.

6. In the amount block, choose the amount of coins for shuffling.

7. Fee is fixed and unchanged.

8. If the amount of coins in input is greater than the sum of the shuffling amount fee, then the `Shuffle` button will become enabled

9. Pressing `Shuffle` will start the shuffling process. After 5 participants registered on the server, the shuffling process will begin.

10. Press `Cancel` if you wish to cancel the protocol evaluation. It can take a few seconds to proceed.

11. If all goes well, you will see the outputs and a transaction dialog window. If something goes wrong you will see the errors in the output.

12. In this version of protocol, one of the participants should press `broadcast` on the transaction dialog window.

## Configuring servers servers list

List of servers placed in file `shuffle/servers.json`

If you want to add your server to the list follow the next structure:

```json
{
   "your.server.here":
   {
     "port" : 31415,
     "ssl": true
   }
}
```

`port` value should be integer value of your server port and `ssl` should be boolean value of ssl support.

## Running a shuffling bot

You can run a shuffling bot for supporting of shuffling process. Bot is a simple python script which is looking at the selected cashshuffle server to see if it is a some players in the pool. If it finds a players it also run cahsshuffle protocol clients for mixing.

If you want to run the bot you need to install `schedule` module first:

```
pip install schedule
```

Then you should run the bot itself. Do it from electron-cash root directory:

```
python3 plugins/shuffle/bot.py -S cashshuffle_server_name -P cashshuffle_port_number -I cashshuffle_info_port -W path_to_wallet
```

Here `cashshuffle_server_name` is a cashshuffle server address. It should not contain protocol prefix like `http://` or `https://`. It also should not contain port srecifications like `:3000` or so. Specify the port numbers with `cashshuffle_port_number` and `cashshuffle_info_port` parameters. `path_to_wallet` is a path in the system where the wallet is. Here is how it can look like

```
python3 plugins/shuffle/bot.py -S cashshuffle.server.name -P 8080 -I 8081 -W my_wallet
```

It means we run a bot to support shuffling on the `http://cashshuffle.server.name:8080` server, which use port number 8081 for information and wallet with name `my_wallet` is placed in the electron-cash root

### Specifying the server parameters

Cashshuffle server can be run with `ssl` suport. You should use `--ssl` key to specify it:

```
python3 plugins/shuffle/bot.py --ssl -S cashshuffle_server_name -P cashshuffle_port_number -I cashshuffle_info_port -W path_to_wallet
```

Here is an example:

```
python3 plugins/shuffle/bot.py --ssl -S cashshuffle.server.name -P 8080 -I 8081 -W my_wallet
```

### Specifying the testnet/mainnet

If you want to try it on testnet use `--testnet` key. Here is an example:

```
python3 plugins/shuffle/bot.py --testnet -S cashshuffle.server.name -P 8080 -I 8081 -W my_wallet
```

By default it operates on the mainnet.

### Specifying the pool parameters

You can set up the minimum number of players in the pool to support it with `-L` key. You can also set up the maximum number of players to support the mixing with `-M` key. And you can specify the fee value with `-F` key. Here is an example:  

```
python3 plugins/shuffle/bot.py  -S cashshuffle.server.name -P 8080 -I 8081 -W my_wallet -L 1 -M 2 -F 1000
```
It means we run bot which enters the mixing only if there is at least one player in the pool, and the bot can add 2 players maximum to the pool, and fee is set to be 1000 satoshi. By default this values are 1 fro `L` and `M` key and 1000 for `F` key.

### Specifying the wallet password

If your wallet is encrypteed (highly recomended!) you should specify the password with `--password` key. Here is an example:

```
python3 plugins/shuffle/bot.py  -S cashshuffle.server.name -P 8080 -I 8081 -W my_wallet --password pwd
```
Here in example we set the password to be `pwd`. If you missed this key bot will raise an error.

### Specifying the pending period

You can set up how often should bot check for someone in the pool for mixing. This value is in minutes. Here is an example:

```
python3 plugins/shuffle/bot.py  -S cashshuffle.server.name -P 8080 -I 8081 -W my_wallet -T 2
```

In this example we specifying 2 minutes pending period. It is 10 minutes by default.
