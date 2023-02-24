##
## This file is part of the libsigrokdecode project.
##
## Copyright (C) 2023 Priit Laes <plaes@plaes.org>
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 3 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, see <http://www.gnu.org/licenses/>.
##
## This file is part of the libsigrokdecode project.
##

import sigrokdecode as srd
class Decoder(srd.Decoder):
    api_version = 3
    id = 'cctalk'
    name = 'ccTalk'
    longname = 'ccTalk'
    desc = 'ccTalk'
    license = 'gplv2+'
    inputs = ['uart']
    outputs = []
    # ?? tags =

    ## Packet fields:
    # dest address
    # data bytes - 0 .. ff
    # source address
    # command
    # checksum

    def __init__(self):
        self.reset()

    def reset(self):
        self.buf = []
        self.len = 0

    def start(self):
        self.out_ann = self.register(srd.OUTPUT_ANN)

    def decode(self, ss, es, data):
        ptype, _, pdata = data

        # We are only interested in data bytes..
        if ptype != 'DATA':
            return

        # Start building up the current packet byte by byte...
        self.buf.append(pdata[0])

        # ...and keep track of currently collected data length
        buflen = len(self.buf)

        if buflen == 1:
            return

        # Second byte contains packet length, so fill this in...
        if buflen == 2:
            self.len = 2 + pdata[0] + 3
            return

        # ... and check whether we have reached end.
        if buflen == self.len:
            # TODO: Figure out annotations...
            print("ccTalk packet:", self.buf)
            self.reset()
