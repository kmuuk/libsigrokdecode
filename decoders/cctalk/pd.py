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
from .lists import standard_commands

def csum8(data):
    return sum(data) % 256

def crc16(data):
    poly = 0x1021
    crc = 0
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if (crc & 0x8000) != 0:
                crc = ((crc << 1) ^ poly)
            else:
                crc <<= 1
    return crc & 0xffff

ann_dst, ann_len, ann_src, ann_cmd, ann_data, ann_csum, ann_packet = range(7)

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

    annotations = (
        ('dst', 'Destination address'),
        ('len', 'Number of data bytes'),
        ('src', 'Source address'),
        ('cmd', 'Command Header'),
        ('data', 'Command Data'),
        ('csum', 'Packet checksum'),
        # ccTalk packet description
        ('packet', 'Packet Info'),
    )

    annotation_rows = (
        ('packet', 'Packet Info', (ann_dst, ann_len, ann_src, ann_cmd, ann_data, ann_csum)),
        ('cmd', 'ccTalk command', (ann_packet,)),
    )

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
        self.buf.append((pdata[0], ss, es))

        # ...and keep track of currently collected data length
        buflen = len(self.buf)

        # Second byte contains packet length, so fill this in...
        if buflen == 2:
            self.len = 2 + pdata[0] + 3
            return

        # TODO: Use timing to detect broken packets
        # ccTalk spec mentions that inter-byte delay should be no greater than 10ms (at 9600baud)

        # ... and check whether we have reached end.
        if buflen == self.len:
            self.handle_packet()

    def handle_packet(self):
        raw = list(b[0] for b in self.buf)
        # TODO: Figure out how to annotate different types of checksums.. (separate annotation?)
        # TODO: Handle simple vs standard (and encrypted) packages)
        if csum8(raw) == 0:
            pass
        # Fill in command info...
        for i in range(4):
            b, ss, es = self.buf[i]
            self.put(ss, es, self.out_ann, [i, [f"{self.annotations[i][0]}: {b}"]])
        # Fill in packet info
        self.annotate_packet_info()
        self.reset()

    def annotate_packet_info(self):
        ## Fill in packet data...
        cmd = self.buf[3][0]
        ss = self.buf[0][1]
        es = self.buf[-1][2]
        cmd_info = standard_commands.get(cmd, 'Unhandled')
        # TODO: Add data bytes
        self.put(ss, es, self.out_ann, [ann_packet, [f"{cmd}: {cmd_info}"]])
