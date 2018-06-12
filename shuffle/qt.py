#!/usr/bin/env python
#
# Electrum - Lightweight Bitcoin Client
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

from __future__ import absolute_import

import time
import threading
import base64
from functools import partial

from PyQt5.QtGui import *
from PyQt5.QtCore import *
import PyQt5.QtCore as QtCore
import PyQt5.QtGui as QtGui
from PyQt5.QtWidgets import (QVBoxLayout, QLabel, QGridLayout, QLineEdit, QHBoxLayout, QWidget, QCheckBox)

from electroncash.plugins import BasePlugin, hook
from electroncash.i18n import _
from electroncash_gui.qt.util import EnterButton, Buttons, CloseButton
from electroncash_gui.qt.util import OkButton, WindowModalDialog
from .shuffle import InputAdressWidget, ChangeAdressWidget, OutputAdressWidget, ConsoleOutput, AmountSelect, ServersList

class ShuffleWidget(QWidget):

    def __init__(self, window):
        QWidget.__init__(self)
        self.window = window
        self.coinshuffle_fee_constant = 1000
        # This is for debug
        # self.coinshuffle_fee_constant = 1000

        # self.coinshuffle_amounts = [1e7, 1e6]
        # Use this in test mode
        self.coinshuffle_amounts = [1e6, 1e5, 1e3]
        self.shuffle_grid = QGridLayout()
        self.shuffle_grid.setSpacing(8)
        self.shuffle_grid.setColumnStretch(3, 1)

        self.coinshuffle_servers = ServersList()
        self.coinshuffle_inputs = InputAdressWidget(decimal_point = self.window.get_decimal_point)
        self.coinshuffle_changes = ChangeAdressWidget()
        self.coinshuffle_fresh_changes = QCheckBox(_('Show only fresh change addresses'))
        self.coinshuffle_outputs = OutputAdressWidget()
        self.coinshuffle_amount_radio = AmountSelect(self.coinshuffle_amounts, decimal_point = self.window.get_decimal_point)
        self.coinshuffle_fee = QLabel(_(self.window.format_amount_and_units(self.coinshuffle_fee_constant)))
        self.coinshuffle_text_output = ConsoleOutput()

        self.coinshuffle_inputs.currentIndexChanged.connect(self.check_sufficient_ammount)
        self.coinshuffle_amount_radio.button_group.buttonClicked.connect(self.check_sufficient_ammount)
        self.coinshuffle_fresh_changes.stateChanged.connect(lambda: self.coinshuffle_changes.update(self.window.wallet, fresh_only = self.coinshuffle_fresh_changes.isChecked()))

        self.coinshuffle_start_button = EnterButton(_("Shuffle"),lambda :self.start_coinshuffle_protocol())
        self.coinshuffle_cancel_button = EnterButton(_("Cancel"),lambda :self.cancel_coinshuffle_protocol())
        self.coinshuffle_start_button.setEnabled(False)
        self.coinshuffle_cancel_button.setEnabled(False)

        self.shuffle_grid.addWidget(QLabel(_('Shuffle server')), 1, 0)
        self.shuffle_grid.addWidget(QLabel(_('Shuffle input address')), 2, 0)
        self.shuffle_grid.addWidget(QLabel(_('Shuffle change address')), 3, 0)
        self.shuffle_grid.addWidget(QLabel(_('Shuffle output address')), 5, 0)
        self.shuffle_grid.addWidget(QLabel(_('Amount')), 6, 0)
        self.shuffle_grid.addWidget(QLabel(_('Fee')), 7, 0)
        self.shuffle_grid.addWidget(self.coinshuffle_servers, 1, 1,1,-1)
        self.shuffle_grid.addWidget(self.coinshuffle_fresh_changes, 4, 1)
        self.shuffle_grid.addWidget(self.coinshuffle_inputs,2,1,1,-1)
        self.shuffle_grid.addWidget(self.coinshuffle_changes,3,1,1,-1)
        self.shuffle_grid.addWidget(self.coinshuffle_outputs,5,1,1,-1)
        self.shuffle_grid.addWidget(self.coinshuffle_amount_radio,6,1)
        self.shuffle_grid.addWidget(self.coinshuffle_fee ,7, 1)
        self.shuffle_grid.addWidget(self.coinshuffle_start_button, 8, 0)
        self.shuffle_grid.addWidget(self.coinshuffle_cancel_button, 8, 1)
        self.shuffle_grid.addWidget(self.coinshuffle_text_output,9,0,1,-1)

        vbox0 = QVBoxLayout()
        vbox0.addLayout(self.shuffle_grid)
        hbox = QHBoxLayout()
        hbox.addLayout(vbox0)
        vbox = QVBoxLayout(self)
        vbox.addLayout(hbox)
        vbox.addStretch(1)

    def set_coinshuffle_addrs(self):
        self.coinshuffle_servers.setItems()
        self.coinshufle_input_addrs = map(lambda x: x.get('address'),self.window.wallet.get_utxos())
        self.coinshuffle_outputs_addrs = map(lambda x: x.get('address'),self.window.wallet.get_utxos())
        self.coinshuffle_inputs.setItmes(self.window.wallet)
        self.coinshuffle_changes.setItems(self.window.wallet)
        self.coinshuffle_outputs.setItems(self.window.wallet)

    def check_sufficient_ammount(self):
        coin_amount = self.coinshuffle_inputs.get_input_value()
        shuffle_amount = self.coinshuffle_amount_radio.get_amount()
        fee = self.coinshuffle_fee_constant
        if shuffle_amount and fee:
            if coin_amount > (fee + shuffle_amount):
                self.coinshuffle_start_button.setEnabled(True)
            else:
                self.coinshuffle_start_button.setEnabled(False)
        else:
            self.coinshuffle_start_button.setEnabled(False)

    def enable_coinshuffle_settings(self):
        self.coinshuffle_servers.setEnabled(True)
        self.coinshuffle_start_button.setEnabled(True)
        self.coinshuffle_inputs.setEnabled(True)
        self.coinshuffle_changes.setEnabled(True)
        self.coinshuffle_outputs.setEnabled(True)
        self.coinshuffle_amount_radio.setEnabled(True)

    def disable_coinshuffle_settings(self):
        self.coinshuffle_servers.setEnabled(False)
        self.coinshuffle_start_button.setEnabled(False)
        self.coinshuffle_inputs.setEnabled(False)
        self.coinshuffle_changes.setEnabled(False)
        self.coinshuffle_outputs.setEnabled(False)
        self.coinshuffle_amount_radio.setEnabled(False)


    def process_protocol_messages(self, message):

        if message.startswith("Error"):
            self.pThread.join()
            self.coinshuffle_text_output.setTextColor(QColor('red'))
            self.coinshuffle_text_output.append(message)
            self.enable_coinshuffle_settings()
        elif message[-17:] == "complete protocol":
            self.pThread.done.set()
            tx = self.pThread.protocol.tx
            if tx:
                # self.window.show_transaction(tx)
                self.pThread.join()
            else:
                print("No tx: " + str(tx.raw))
            self.enable_coinshuffle_settings()
            self.coinshuffle_cancel_button.setEnabled(False)
            self.coinshuffle_inputs.update(self.window.wallet)
            self.coinshuffle_outputs.update(self.window.wallet)
        else:
            header = message[:6]
            if header == 'Player':
                self.coinshuffle_text_output.setTextColor(QColor('green'))
            if header[:5] == 'Blame':
                self.coinshuffle_text_output.setTextColor(QColor('red'))
                if "insufficient" in message:
                    pass
                elif "wrong hash" in message:
                    pass
                else:
                    self.pThread.join()
                    self.enable_coinshuffle_settings()
                    self.coinshuffle_text_output.append(str(self.pThread.isAlive()))
            self.coinshuffle_text_output.append(message)
            self.coinshuffle_text_output.setTextColor(QColor('black'))


    def start_coinshuffle_protocol(self):

        from .client import ProtocolThread
        from electroncash.bitcoin import (regenerate_key, deserialize_privkey)
        from .shuffle import ConsoleLogger
        parent = self.window.top_level_window()
        password = None
        while self.window.wallet.has_password():
            password = self.window.password_dialog(parent=parent)
            if password is None:
                # User cancelled password input
                return
            try:
                self.window.wallet.check_password(password)
                break
            except Exception as e:
                self.window.show_error(str(e), parent=parent)
                continue
        try:
            server_params = self.coinshuffle_servers.get_current_server()
            server = server_params['server']
            port = server_params['port']
            ssl = server_params.get('ssl', False)
        except:
            self.coinshuffle_text_output.setText('Wrong server connection string')
            return
        input_address = self.coinshuffle_inputs.get_input_address()
        possible_change_address = self.coinshuffle_changes.get_change_address()
        if possible_change_address:
            change_address = possible_change_address
        else:
            change_address = self.coinshuffle_inputs.get_input_address_as_string()
        output_address = self.coinshuffle_outputs.get_output_address()
        #disable inputs
        self.disable_coinshuffle_settings()
        self.coinshuffle_cancel_button.setEnabled(True)

        amount = self.coinshuffle_amount_radio.get_amount()
        fee = self.coinshuffle_fee_constant
        self.logger = ConsoleLogger()
        self.logger.logUpdater.connect(lambda x: self.process_protocol_messages(x))
        priv_key = self.window.wallet.export_private_key(input_address, password)
        pub_key = self.window.wallet.get_public_key(input_address)
        sk = regenerate_key(deserialize_privkey(priv_key)[1])
        self.pThread = ProtocolThread(server, port, self.window.network, amount, fee, sk, pub_key, output_address, change_address, logger = self.logger, ssl = ssl)
        self.pThread.start()

    def cancel_coinshuffle_protocol(self):
        if self.pThread.is_alive():
            self.pThread.join()
            while self.pThread.is_alive():
                time.sleep(0.1)
            self.coinshuffle_cancel_button.setEnabled(False)
            self.enable_coinshuffle_settings()


class Plugin(BasePlugin):

    def fullname(self):
        return 'CashShuffle'

    def description(self):
        return _("Configure CashShuffle Protocol")

    def is_available(self):
        return True

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)
        self.window = None
        self.tab = None

    @hook
    def init_qt(self, gui):
        for window in gui.windows:
            self.on_new_window(window)

    @hook
    def on_new_window(self, window):
        self.update(window)

    @hook
    def on_close_window(self, window):
        self.update(window)

    def on_close(self):
        tabIndex= self.window.tabs.indexOf(self.tab)
        self.window.tabs.removeTab(tabIndex)

    def update(self, window):
        self.window = window
        self.tab = ShuffleWidget(window)
        self.tab.set_coinshuffle_addrs()
        icon = QIcon(":icons/tab_coins.png")
        description =  _("Shuffle")
        name = "shuffle"
        self.tab.tab_icon = icon
        self.tab.tab_description = description
        self.tab.tab_pos = len(self.window.tabs)
        self.tab.tab_name = name
        self.window.tabs.addTab(self.tab, icon, description.replace("&", ""))

    def requires_settings(self):
        return False
