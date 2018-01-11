#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2015 Thomas Voegtlin
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from PyQt5.QtCore import *
from PyQt5.QtGui import *

from electroncash_gui.qt.util import *
from electroncash.i18n import _
from .client import protocolThread
# from electroncash_plugins.coinshuffle.client import protocolThread
from electroncash.bitcoin import regenerate_key
from electroncash.address import Address

import json
import os

class AmountSelect(QGroupBox):

    def __init__(self, values, parent = None, decimal_point = None ):
        QGroupBox.__init__(self)
        if decimal_point:
            self.decimal_point = decimal_point
        else:
            self.decimal_point = lambda: 8
        self.values = values
        buttons = [QRadioButton(self.add_units(value)) for value in values]
        buttons[0].setChecked(True)
        buttons_layout = QVBoxLayout()
        self.button_group = QButtonGroup()
        for i, button in enumerate(buttons):
            buttons_layout.addWidget(button)
            self.button_group.addButton(button, i)
        self.setLayout(buttons_layout)

    def update(self):
        for i, button in enumerate(self.button_group.buttons()):
            button.setText(self.add_units(self.values[i]))

    def add_units(self, value):
        p = self.decimal_point()
        if p not in [2, 5 , 8]:
            p = 8
        return str(value*(10**(-p)))+ " " + {2:"bits", 5:"mBCH", 8: "BCH" }[p]

    def get_amount(self):
        return self.values[self.button_group.checkedId()]

class InputAdressWidget(QComboBox):

    def __init__(self, decimal_point, parent = None):
        QComboBox.__init__(self, parent)
        self.decimal_point = decimal_point

    def amounted_value(self, value):
        p = self.decimal_point()
        units = {2:"bits", 5:"mBCH", 8:"BCH"}
        if p not in  [2,5,8]:
            p = 8
        return str(value * (10**(- p))) + " " + units[p]

    def update(self, wallet):
        current_input = self.get_input_address()
        currentindex = self.currentIndex()
        self.clear_addresses()
        self.setItmes(wallet)
        if current_input in self.inputsArray:
            self.setCurrentIndex(self.inputsArray.index(current_input))
        else:
            self.setCurrentIndex(0)

    def clear_addresses(self):
        self.inputsArray = []
        self.clear()

    def setItmes(self, wallet):
        self.inputsArray = wallet.get_utxos()
        for utxo in self.inputsArray:
            self.addItem(utxo.get('address').to_string(Address.FMT_LEGACY)+': '+ self.amounted_value(utxo['value']))

    def get_input_address(self):
        return self.inputsArray[self.currentIndex()]['address']

    def get_input_value(self):
        i = self.currentIndex()
        if i >= 0:
            return self.inputsArray[self.currentIndex()]['value']
        else:
            return 0

class OutputAdressWidget(QComboBox):

    def __init__(self, parent = None):
        QComboBox.__init__(self, parent)

    def clear_addresses(self):
        self.outputsArray = []
        self.clear()

    def setItems(self, wallet):
        self.outputsArray = wallet.get_unused_addresses()
        for address in self.outputsArray:
            self.addItem(address.to_string(Address.FMT_LEGACY))

    def get_output_address(self):
        return self.outputsArray[self.currentIndex()]

class ConsoleLogger(QObject):
    logUpdater  = pyqtSignal(str)

    def send(self, message):
        self.logUpdater.emit(str(message))

    def put(self, message):
        self.send(message)

class ConsoleOutput(QTextEdit):

    def __init__(self,  parent = None):
        QTextEdit.__init__(self, parent)
        self.setReadOnly(True)
        self.setText('Console output go here')

class ChangeAdressWidget(QComboBox):

    def clear_addresses(self):
        self.ChangesArray = []
        self.clear()

    def setItems(self, wallet):
        self.ChangesArray = wallet.get_change_addresses()
        self.addItem('Use input as change address')
        for addr in self.ChangesArray:
            self.addItem(addr.to_string(Address.FMT_LEGACY))

    def get_change_address(self):
        i = self.currentIndex()
        if i > 0:
            return self.ChangesArray[i-1]
        else:
            return None


class ShuffleList(MyTreeWidget):
    filter_columns = [0, 2]  # Address, Label

    def __init__(self, parent=None):
        MyTreeWidget.__init__(self, parent, self.create_menu, [ _('Address'), _('Label'), _('Amount'), _('Height'), _('Output point')], 1)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)

    def get_name(self, x):
        return x.get('prevout_hash') + ":%d"%x.get('prevout_n')

    def on_update(self):
        limit = 1e5 #(in satoshis)
        self.wallet = self.parent.wallet
        item = self.currentItem()
        self.clear()
        self.utxos = self.wallet.get_utxos()
        for x in self.utxos:
            address = x.get('address')
            height = x.get('height')
            name = self.get_name(x)
            label = self.wallet.get_label(x.get('prevout_hash'))
            amount = self.parent.format_amount(x['value'])
            utxo_item = QTreeWidgetItem([address, label, amount, '%d'%height, name[0:10] + '...' + name[-2:]])
            utxo_item.setFont(0, QFont(MONOSPACE_FONT))
            utxo_item.setFont(4, QFont(MONOSPACE_FONT))
            utxo_item.setData(0, Qt.UserRole, name)
            if self.wallet.is_frozen(address):
                utxo_item.setBackground(0, QColor('lightblue'))
            # if float(amount) >= limit:
            if x['value'] >= limit:
                self.addChild(utxo_item)

    def create_menu(self, position):
        selected = [str(x.data(0, Qt.UserRole)) for x in self.selectedItems()]
        if not selected:
            return
        menu = QMenu()
        coins = filter(lambda x: self.get_name(x) in selected, self.utxos)

        menu.addAction(_("Shuffle"), lambda: QMessageBox.information(self.parent,"1","2"))
        if len(selected) == 1:
            txid = selected[0].split(':')[0]
            tx = self.wallet.transactions.get(txid)
            menu.addAction(_("Details"), lambda: self.parent.show_transaction(tx))

        menu.exec_(self.viewport().mapToGlobal(position))

class ServersList(QComboBox):

    def __init__(self, parent = None):
        QComboBox.__init__(self, parent)
        self.servers_path ='servers.json'
        self.servers_list = None
        self.load_servers_list()

    def load_servers_list(self):
        try:

            with open(os.path.join(os.path.dirname(__file__),self.servers_path), 'r') as f:
                r = json.loads(f.read())
        except:
            r = {}
        self.servers_list = r

    def setItems(self):
        for server in self.servers_list:
            ssl = self.servers_list[server].get('ssl')
            item = server + ('   [ssl enabled]' if ssl else '   [ssl disabled]')
            self.addItem(item)

    def get_current_server(self):
        current_server =  self.currentText().split(' ')[0]
        server = self.servers_list.get(current_server)
        server['server' ] = current_server
        return server
