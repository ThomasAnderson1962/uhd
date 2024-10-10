#!/usr/bin/env python
#
# Copyright 2010-2014 Ettus Research LLC
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import argparse

import sys
import socket
import struct


X300_FW_COMMS_UDP_PORT = 49152

X300_FW_COMMS_FLAGS_ACK = 1
X300_FW_COMMS_FLAGS_ERROR = 2
X300_FW_COMMS_FLAGS_POKE32 = 4
X300_FW_COMMS_FLAGS_PEEK32 = 8

X300_FIXED_PORTS = 5

X300_ZPU_MISC_SR_BUS_OFFSET = 0xA000
X300_ZPU_XBAR_SR_BUS_OFFSET = 0xB000

# Settings register bus addresses (hangs off ZPU wishbone bus)
# Multiple by 4 as ZPU wishbone bus is word aligned
X300_SR_NUM_CE       = X300_ZPU_MISC_SR_BUS_OFFSET + 4 * 7
X300_SR_RB_ADDR_XBAR = X300_ZPU_MISC_SR_BUS_OFFSET + 4 * 128
# Readback addresses
X300_RB_CROSSBAR     = X300_ZPU_MISC_SR_BUS_OFFSET + 4 * 128

# UDP_CTRL_PORT = 49183
UDP_MAX_XFER_BYTES = 1024
UDP_TIMEOUT = 3

# REG_ARGS_FMT = '!LLLLLB15x'
# REG_IP_FMT = '!LLLL20x'
REG_PEEK_POKE_FMT = '!LLLL'


def _unpack_message(s):
	return struct.unpack(REG_PEEK_POKE_FMT, s)


def _pack_message(flags, seq, addr, data):
	return struct.pack(REG_PEEK_POKE_FMT, flags, seq, addr, data)


class ControlSocket(object):
	_seq = -1

	@classmethod
	def seq(cls):
		cls._seq += 1
		return cls._seq

	def __init__(self, addr, timeout = None):
		print >>sys.stderr, "Connecting..."
		self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self._sock.settimeout(timeout if timeout else UDP_TIMEOUT)
		self._sock.connect((addr, X300_FW_COMMS_UDP_PORT))

	def __del__(self):
		if self._sock is not None:
			print >>sys.stderr, "Closing..."
			self._sock.close()
			self._sock = None

	def _send(self, pkt):
		self._sock.send(pkt)

	def _send_ex(self, pkt):
		self._sock.send(pkt)
		return self._sock.recv(UDP_MAX_XFER_BYTES)

	def read_router_stats(self, blocks = None, ignore = None):
		# Readback number of CEs
		num_ports = self.peek(X300_SR_NUM_CE) + X300_FIXED_PORTS
		ports = ['eth0', 'eth1', 'pcie', 'radio0', 'radio1'] + ["Block{num}".format(num = x) for x in range(num_ports - X300_FIXED_PORTS)]
		if blocks is None:
			print("\nNote: Using default CE port names (use --blocks to specify)\n")
		else:
			user_ports = [x.strip() for x in blocks.split(",") if len(x.strip())]
			for idx, user_port in enumerate(user_ports):
				ports[idx + X300_FIXED_PORTS] = user_port
		if ignore is None:
			ignore = []
		else:
			ignore = [int(x.strip()) for x in ignore.split(",") if len(x.strip())]
		print("Egress Port "),
		# Write out xbar ports
		PORT_MAX_LEN = 12
		for idx, in_prt in enumerate(ports):
			if idx in ignore:
				continue
			print "{spaces}{name}".format(spaces = (" " * max(0, PORT_MAX_LEN - len(in_prt))), name = in_prt),
		print
		print(" " * (PORT_MAX_LEN + 1)),
		for in_prt in range(num_ports - len(ignore)):
			print("_" * (PORT_MAX_LEN - 1) + " "),
		print
		for in_prt, port_name in enumerate(ports):
			if in_prt in ignore:
				continue
			print "{spaces}{name} |".format(spaces = (" " * max(0, PORT_MAX_LEN - len(port_name))), name = port_name),
			for out_prt in range(num_ports):
				if out_prt in ignore:
					continue
				self.poke(X300_SR_RB_ADDR_XBAR, (in_prt * num_ports + out_prt))
				data = self.peek(X300_RB_CROSSBAR)
				print("%10d  " % data),
			print
		print
		print("Ingress Port")
		print

	def peek(self, peek_addr):
		out_pkt = _pack_message(X300_FW_COMMS_FLAGS_PEEK32 | X300_FW_COMMS_FLAGS_ACK, self.seq(), peek_addr, 0)
		in_pkt = self._send_ex(out_pkt)
		(flags, rxseq, addr, data) = _unpack_message(in_pkt)
		if flags & X300_FW_COMMS_FLAGS_ERROR == X300_FW_COMMS_FLAGS_ERROR:
			raise Exception("X300 peek of address %d returns error code" % addr)
		return data

	def poke(self, poke_addr, poke_data, wait = False):
		out_pkt = _pack_message(X300_FW_COMMS_FLAGS_POKE32 | X300_FW_COMMS_FLAGS_ACK, self.seq(), poke_addr, poke_data)
		if wait:
			in_pkt = self._send_ex(out_pkt)
			(flags, rxseq, addr, data) = _unpack_message(in_pkt)
			if flags & X300_FW_COMMS_FLAGS_ERROR == X300_FW_COMMS_FLAGS_ERROR:
				raise Exception("X300 peek of address %d returns error code" % addr)
			return data
		else:
			self._send(out_pkt)
			return None


def peek_print(control, peek_addr):
	peek_data = control.peek(peek_addr)
	print("PEEK of address %d(0x%x) reads %d(0x%x)" % (peek_addr, peek_addr, peek_data, peek_data))
	return peek_data


def poke_print(control, poke_addr, poke_data):
	print("POKE of address %d(0x%x) with %d(0x%x)" % (poke_addr, poke_addr, poke_data, poke_data))
	return control.poke(poke_addr, poke_data)


def parse_cli():
	parser = argparse.ArgumentParser(description = "USRP helper utility")

	parser.add_argument("-a", "--addr", help = "USRP-X300 device address", required = True)
	parser.add_argument("-r", "--reset", action = "store_true", help = "Reset the USRP", default = False)
	parser.add_argument("-s", "--stats", action = "store_true", help = "Display RFNoC Crossbar Stats", default = False)
	parser.add_argument("-p", "--peek", type = int, help = "Read from memory map", default = None)
	parser.add_argument("-w", "--poke", type = int, help = "Write to memory map", default = None)
	parser.add_argument("-d", "--data", type = int, help = "Data for poke", default = None)
	parser.add_argument("-b", "--blocks", help = "List names of blocks (post-radio)", default = None)
	parser.add_argument("-i", "--ignore", help = "List of ports to ignore", default = None)

	return parser.parse_args()



def main():
	args = parse_cli()

	if not args.addr:
		raise Exception('no address specified')

	control = ControlSocket(args.addr)

	if args.stats:
		control.read_router_stats(args.blocks, args.ignore)

	if args.peek is not None:
		addr = args.peek
		peek_print(control, addr)

	if args.poke is not None and args.data is not None:
		addr = args.poke
		data = args.data
		poke_print(control, addr, data)

	if args.reset:
		addr = 0x100058
		data = 1
		print >>sys.stderr, "Reseting..."
		control.poke(addr, data)

	control = None


if __name__ == '__main__':
	main()
