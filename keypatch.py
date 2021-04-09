#!/usr/bin/env python

# python stdlib stuff
import re
import sys
import math
# Qt stuff
from PySide2.QtWidgets import *
from PySide2.QtGui import QFont
# keystone stuff
from keystone import *
# binaryninja
from binaryninja.interaction import show_message_box
from binaryninja.enums import MessageBoxButtonSet, MessageBoxIcon

#------------------------------------------------------------------------------
# lookups
#------------------------------------------------------------------------------
hexchars = '0123456789ABCDEFabcdef'

# (name, description, arch, mode, option)
architecture_infos = [
	('x16', 'X86 16bit, Intel syntax', KS_ARCH_X86, KS_MODE_16),
	('x32', 'X86 32bit, Intel syntax', KS_ARCH_X86, KS_MODE_32),
	('x64', 'X86 64bit, Intel syntax', KS_ARCH_X86, KS_MODE_64),
	('x16att', 'X86 16bit, AT&T syntax', KS_ARCH_X86, KS_MODE_16),
	('x32att', 'X86 32bit, AT&T syntax', KS_ARCH_X86, KS_MODE_32),
	('x64att', 'X86 64bit, AT&T syntax', KS_ARCH_X86, KS_MODE_64),
	('x16nasm', 'X86 16bit, NASM syntax', KS_ARCH_X86, KS_MODE_16),
	('x32nasm', 'X86 32bit, NASM syntax', KS_ARCH_X86, KS_MODE_32),
	('x64nasm', 'X86 64bit, NASM syntax', KS_ARCH_X86, KS_MODE_64),
	('arm', 'ARM - little endian', KS_ARCH_ARM, KS_MODE_ARM),
	('armbe', 'ARM - big endian', KS_ARCH_ARM, KS_MODE_ARM),
	('thumb', 'Thumb - little endian', KS_ARCH_ARM, KS_MODE_THUMB),
	('thumbbe', 'Thumb - big endian', KS_ARCH_ARM, KS_MODE_THUMB),
	('armv8', 'ARM V8 - little endian', KS_ARCH_ARM, KS_MODE_ARM|KS_MODE_V8),
	('armv8be', 'ARM V8 - big endian', KS_ARCH_ARM, KS_MODE_ARM|KS_MODE_V8),
	('thumbv8', 'Thumb V8 - little endian', KS_ARCH_ARM, KS_MODE_THUMB|KS_MODE_V8),
	('thumbv8be', 'Thumb V8 - big endian', KS_ARCH_ARM, KS_MODE_THUMB|KS_MODE_V8),
	('arm64', 'AArch64', KS_ARCH_ARM64, 0),
	('hexagon', 'Hexagon', KS_ARCH_HEXAGON, 0),
	('mips', 'Mips - little endian', KS_ARCH_MIPS, KS_MODE_MIPS32),
	('mipsbe', 'Mips - big endian', KS_ARCH_MIPS, KS_MODE_MIPS32),
	('mips64', 'Mips64 - little endian', KS_ARCH_MIPS, KS_MODE_MIPS64),
	('mips64be', 'Mips64 - big endian', KS_ARCH_MIPS, KS_MODE_MIPS64),
	('ppc32be', 'PowerPC32 - big endian', KS_ARCH_PPC, KS_MODE_PPC32),
	('ppc64', 'PowerPC64 - little endian', KS_ARCH_PPC, KS_MODE_PPC64),
	('ppc64be', 'PowerPC64 - big endian', KS_ARCH_PPC, KS_MODE_PPC64),
	('sparc', 'Sparc - little endian', KS_ARCH_SPARC, KS_MODE_SPARC32),
	('sparcbe', 'Sparc - big endian', KS_ARCH_SPARC, KS_MODE_SPARC32),
	('sparc64be', 'Sparc64 - big endian', KS_ARCH_SPARC, KS_MODE_SPARC64),
	('systemz', 'SystemZ (S390x)', KS_ARCH_SYSTEMZ, 0),
	('evm', 'Ethereum Virtual Machine', KS_ARCH_EVM, 0)
]

# map architecture name to keystone context
architecture_to_ks = {}
for (name, descr, arch_const, mode_const) in architecture_infos:
	# default is little endian
	# decide whether to set big endian
	if name.endswith('be'):
		mode_const |= KS_MODE_BIG_ENDIAN
	else:
		mode_const |= KS_MODE_LITTLE_ENDIAN

	# initialize architecture
	ks = Ks(arch_const, mode_const)

	# set special syntax if indicated
	if 'AT&T syntax' in descr:
		#ks_option(KS_OPT_SYNTAX, KS_OPT_SYNTAX_ATT)
		ks.syntax = KS_OPT_SYNTAX_ATT
	if name.endswith('nasm'):
		#ks_option(KS_OPT_SYNTAX, KS_OPT_SYNTAX_NASM)
		ks.syntax = KS_OPT_SYNTAX_NASM

	architecture_to_ks[name] = ks

# map binary ninja architecture name to ks architecture name
# [x.name for x in binaryninja.Architecture]
binja_to_ks = {
	'aarch64': 'arm64',
	'armv7': 'arm',
	'armv7eb': 'armbe',
	'thumb2': 'thumb',
	'thumb2eb': 'thumbbe',
	'mipsel32': 'mips',
	'mips32': 'mipsbe',
	'ppc': 'ppc32be',
	'ppc_le': 'ERROR',
	'ppc64': 'ppc64be',
	'ppc64_le': 'ppc64',
	'sh4': 'ERROR',
	'x86_16': 'x16nasm',
	'x86': 'x32nasm',
	'x86_64': 'x64nasm'
}

# these words won't be substituted in assembly fixup
arch_to_reserved = {
	'aarch64': [ 'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7',
				 'r8', 'r9','r10','r11','r12','r13','r14','r15',
				'r16','r17','r18','r19','r20','r21','r22','r23',
				'r24','r25','r26','r27','r28','r29','r30','r31'
				 'w0', 'w1', 'w2', 'w3', 'w4', 'w5', 'w6', 'w7',
				 'w8', 'w9','w10','w11','w12','w13','w14','w15',
				'w16','w17','w18','w19','w20','w21','w22','w23',
				'w24','w25','w26','w27','w28','w29','w30','w31',
				 'x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7',
				 'x8', 'x9','x10','x11','x12','x13','x14','x15',
				'x16','x17','x18','x19','x20','x21','x22','x23',
				'x24','x25','x26','x27','x28','x29','x30','x31'],
	'armv7': ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9','r10','r11','r12',
				'sp', 'lr', 'pc', 'apsr'],
	'mips32': [],
	'ppc': [],
	#'ppc_le',
	'ppc64': [],
	#'sh4',
	'x86_16': [ 'ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di',
				'ah', 'al', 'ch', 'cl', 'dh', 'dl', 'bh', 'bl',
				'ss', 'cs', 'ds', 'es']
}
arch_to_reserved['thumb2'] = arch_to_reserved['armv7']
arch_to_reserved['thumb2eb'] = arch_to_reserved['thumb2']
arch_to_reserved['armv7eb'] = arch_to_reserved['armv7']
arch_to_reserved['mipsel32'] = arch_to_reserved['mips32']
arch_to_reserved['ppc64_le'] = arch_to_reserved['ppc64']
arch_to_reserved['x86'] = arch_to_reserved['x86_16'] + \
						['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi', 'fs', 'gs']
arch_to_reserved['x86_64'] = arch_to_reserved['x86'] + \
						['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi']

font_mono = QFont('Courier New')
font_mono.setStyleHint(QFont.TypeWriter)

#------------------------------------------------------------------------------
# utilities
#------------------------------------------------------------------------------

# test if given address is valid binaryview address, by searching sections
def is_valid_addr(bview, addr):
	for sname in bview.sections:
		section = bview.sections[sname]
		start = section.start
		end = section.start + len(section)
		if addr >= start and addr < end:
			return True
	return False

# given a valid address, return least address after the valid that is invalid
def get_invalid_addr(bview, addr):
	for sname in bview.sections:
		section = bview.sections[sname]
		start = section.start
		end = section.start + len(section)
		if addr >= start and addr < end:
			return end
	raise Exception('0x%X is not a valid address' % addr)

def disassemble_binja_single(bview, addr):
	end = get_invalid_addr(bview, addr)
	length = min(16, end - addr)
	data = bview.read(addr, length)
	(tokens, length) = bview.arch.get_instruction_text(data, addr)
	if not tokens or not length:
		return (None, None)
		raise Exception('disassembly of %s failed' % str(data))
	strs = [t.text for t in tokens]
	strs = [' ' if s.isspace() else s for s in strs]
	return (''.join(strs), length)

# get length of instruction at addr
def disassemble_length(bview, addr):
	(instxt, length) = disassemble_binja_single(bview, addr)
	return length

# get length of instruction sequence until limit size
def disassemble_length_until(bview, addr, limit):
	result = 0
	while result < limit:
		tmp = disassemble_length(bview, addr)
		addr += tmp
		result += tmp
	return result

def error(msg):
	show_message_box('KEYPATCH', msg, \
	  MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)

# b'\xaa\xbb\xcc\xdd' -> 'AA BB CC DD'
def bytes_to_str(data):
	return ' '.join(['%02X'%x for x in data])

def strbytes_pretty(string):
	return ' '.join(['%02X'%ord(x) for x in string])

def fixup(bview, assembly):
	reserved = arch_to_reserved[bview.arch.name]

	# collect substitutions we'll make
	substitutions = []
	for m in re.finditer(r'\w+', assembly):
		if m.start == 0: continue # do not replace mnemonic
		symname = m.group(0)
		if symname in reserved: continue # do not replace reserved words
		if not (symname in bview.symbols and hasattr(bview.symbols[symname], 'address')):
			continue
		substitutions.append(symname)

	# apply substitutions
	for s in substitutions:
		assembly = assembly.replace(s, hex(bview.symbols[s].address))

	# done
	return assembly

# arch is keystone namespace
def get_nop(arch):
	if arch in ['x16', 'x32', 'x64', 'x16att', 'x32att', 'x64att', 'x16nasm', 'x32nasm', 'x64nasm']:
		return b'\x90'
	elif arch in ['arm', 'armv8']:
		return b'\x00\xf0\x20\xe3'
	elif arch in ['armbe', 'armv8be']:
		return b'\xe3\x20\xf0\x00'
	elif arch in ['thumb', 'thumbv8']:
		return b'\x00\xbf'
	elif arch in ['thumbbe', 'thumbv8be']:
		return b'\xbf\x00'
	elif arch in ['arm64']
		return b'\x1f\x20\x03\xd5'
	elif arch in ['hexagon']:
		return b'\x00\xc0\x00\x7f'
	elif arch in ['mips', 'mipsbe', 'mips64', 'mips64be']:
		return b'\x00\x00\x00\x00'
	elif arch in ['ppc64']:
		return b'\x00\x00\x00\x60'
	elif arch in ['ppc32be', 'ppc64be']:
		return b'\x60\x00\x00\x00'
	elif arch in ['sparc']:
		return b'\x00\x00\x00\x01'
	elif arch in ['sparcbe', 'sparc64be']:
		return b'\x01\x00\x00\x00'

	raise Exception('no NOP for architecture: %s' % arch)

#------------------------------------------------------------------------------
# GUI
#------------------------------------------------------------------------------

class AssembleTab(QWidget):
	def __init__(self, context, parent=None):
		super(AssembleTab, self).__init__(parent)
		self.context = context
		self.bv = context.binaryView

		# other QLineEntry widgets to receive bytes upon assembling
		self.qles_bytes = []

		#----------------------------------------------------------------------
		# assemble tab
		#----------------------------------------------------------------------
		layout = QVBoxLayout()
		self.setLayout(layout)

		form = QFormLayout()
		self.qcb_arch = QComboBox()
		form.addRow('Architecture:', self.qcb_arch)
		self.qle_address = QLineEdit('00000000')
		form.addRow('Address:', self.qle_address)
		self.qle_assembly = QLineEdit()
		form.addRow('Assembly:', self.qle_assembly)
		self.check_nops = QCheckBox('NOPs padding until next instruction boundary')
		form.addRow(self.check_nops)
		self.check_save_original = QCheckBox('Save original instructions in binja comment')
		form.addRow(self.check_save_original)
		layout.addLayout(form)

		groupbox = QGroupBox('Preview:')
		form = QFormLayout()
		self.qle_fixedup = QLineEdit()
		form.addRow('Fixed Up:', self.qle_fixedup)
		self.qle_data = QLineEdit()
		form.addRow('Bytes:', self.qle_data)
		self.qle_datasz = QLineEdit()
		form.addRow('Size:', self.qle_datasz)
		groupbox.setLayout(form)
		layout.addWidget(groupbox)

		btn_patch = QPushButton('Patch')
		layout.addWidget(btn_patch)

		# connect everything
		self.qcb_arch.currentTextChanged.connect(self.reassemble)
		self.qle_address.textChanged.connect(self.reassemble)
		self.qle_assembly.textChanged.connect(self.reassemble)
		btn_patch.clicked.connect(self.patch)

		#----------------
		# set defaults
		#----------------

		# default architecture dropdown in assemble
		for (name, descr, arch_const, mode_const) in architecture_infos:
			line = '%s: %s' % (name, descr)
			self.qcb_arch.addItem(line)

		bv_arch_name = context.binaryView.arch.name
		ks_arch_name = binja_to_ks.get(bv_arch_name, 'x64')
		self.qcb_arch.setCurrentIndex(([x[0] for x in architecture_infos]).index(ks_arch_name))

		# default address to assemble
		self.qle_address.setText(hex(self.context.address))

		# default assembly
		ok = False
		try:
			(instxt, length) = disassemble_binja_single(self.bv, context.address)
			if not instxt:
				raise Exception('disassembly failed')
			self.qle_assembly.setText(instxt)
			self.qle_fixedup.setText(instxt)
			self.qle_datasz.setText('%d' % length)
			data = context.binaryView.read(context.address, length)
			self.qle_data.setText(' '.join(['%02X'%x for x in data]))
			ok = True
		except Exception as e:
			print(e)
			pass
		if not ok:
			self.qle_assembly.setText('nop')

		# assembly fields
		self.qle_data.setReadOnly(True)
		self.qle_data.setEnabled(False)
		self.qle_datasz.setReadOnly(True)
		self.qle_datasz.setEnabled(False)
		self.qle_fixedup.setReadOnly(True)
		self.qle_fixedup.setEnabled(False)

		# default
		self.check_nops.setChecked(True)
		self.check_save_original.setChecked(True)

		self.qle_assembly.setFocus()
		btn_patch.setDefault(True)

	#
	# accessors
	#
	def arch(self):
		# 'thumbv8: Thumb V8 - little endian' -> 'thumbv8'
		name_descr = self.qcb_arch.currentText()
		return name_descr.split(':')[0]

	def asm(self):
		return self.qle_assembly.text()

	def ks(self):
		return architecture_to_ks.get(self.arch())

	def addr(self):
		return int(self.qle_address.text(), 16)

	def data(self):
		try:
			values = [int(x, 16) for x in self.qle_data.text().split(' ')]
			return bytes(values)
		except Exception:
			return None

	# add another QLineEntry to receive assembled bytes
	def add_qles_bytes(self, widget):
		self.qles_bytes.append(widget)

	# qle_assembly -> fixup -> qle_data
	#
	def reassemble(self):
		try:
			# get input
			(ks, assembly, addr) = (self.ks(), self.asm(), self.addr())

			# apply fixup
			fixedup = fixup(self.bv, assembly)
			self.qle_fixedup.setText(fixedup)

			# assemble
			data, count = ks.asm(fixedup, addr)
			if not data: return
			for widget in self.qles_bytes:
				widget.setText(bytes_to_str(data))

			# pad with nops
			if self.check_nops.isChecked():
				length = disassemble_length(self.bv, self.addr())
				if length and length > len(data):
					nop = get_nop(self.arch())
					sled = (length // len(nop)) * nop
					sled = list(sled) # b'\xAA' -> [0xAA]
					data = data + sled[len(data):]

			# set
			self.qle_data.setText(bytes_to_str(data))
			self.qle_datasz.setText(hex(len(data)))

		except ValueError:
			self.error('invalid address')
		except KsError as e:
			self.error(str(e))
		except Exception as e:
			self.error(str(e))

	# qle_data -> binary view
	#
	def patch(self):
		data = self.data()

		comment = None
		try:
			if self.check_save_original.isChecked():
				(instxt, length) = disassemble_binja_single(self.bv, self.addr())
				comment = instxt
		except Exception as e:
			print(e)
			pass

		try:
			self.bv.write(self.addr(), data)

			if comment:
				self.bv.set_comment_at(self.addr(), comment)
		except Exception as e:
			return

	# report error to the bytes
	def error(self, msg):
		self.qle_datasz.setText('')
		if not ('error' in msg or 'ERROR' in msg):
			msg = 'ERROR: ' + msg
		self.qle_data.setText(msg)
		self.qle_data.home(True)

#------------------------------------------------------------------------------
# fill range tool
#------------------------------------------------------------------------------

class FillRangeTab(QWidget):
	def __init__(self, context, parent=None):
		super(FillRangeTab, self).__init__(parent)
		self.context = context
		self.bv = context.binaryView

		# this widget is VBox of QGroupBox
		layoutV = QVBoxLayout()
		self.setLayout(layoutV)

		self.qle_end = QLineEdit('00000000')
		self.qle_encoding = QLineEdit()
		self.qle_encoding.setReadOnly(True)
		self.qle_encoding.setEnabled(False)
		self.qle_bytes = QLineEdit('00')
		self.qle_fill_size = QLineEdit()
		self.qle_fill_size.setReadOnly(True)
		self.qle_fill_size.setEnabled(False)
		self.qle_preview = QLineEdit()
		self.qle_preview.setReadOnly(True)
		self.qle_preview.setEnabled(False)
		self.qle_datasz = QLineEdit()

		self.qcb_sections = QComboBox()
		layoutV.addWidget(self.qcb_sections)

		horiz = QHBoxLayout()
		horiz.addWidget(QLabel('['))
		self.qle_address = QLineEdit('00000000')
		horiz.addWidget(self.qle_address)
		horiz.addWidget(QLabel(','))
		horiz.addWidget(self.qle_end)
		horiz.addWidget(QLabel(')'))
		layoutV.addLayout(horiz)

		form = QFormLayout()
		self.chk_encoding = QCheckBox('Assembled:')
		form.addRow(self.chk_encoding, self.qle_encoding)
		self.chk_manual = QCheckBox('Manual Entry:')
		form.addRow(self.chk_manual, self.qle_bytes)
		form.addRow('Preview:', self.qle_preview)
		form.addRow('Size:', self.qle_datasz)
		layoutV.addLayout(form)

		# or QLayout::setAlignment
		layoutV.addStretch()
		btn_fill = QPushButton('Fill')
		layoutV.addWidget(btn_fill)

		# connect everything
		self.qcb_sections.currentTextChanged.connect(self.section_chosen)
		self.qle_address.textChanged.connect(self.preview)
		self.qle_end.textChanged.connect(self.preview)

		self.chk_encoding.toggled.connect(self.encoding_checked_toggle)
		self.chk_manual.toggled.connect(self.manual_checked_toggle)

		self.qle_bytes.textChanged.connect(self.preview)

		btn_fill.clicked.connect(self.fill)

		# set defaults
		nop = get_nop(binja_to_ks[self.bv.arch.name])
		if nop:
			self.qle_bytes.setText(bytes_to_str(nop))

		for (sname, section) in self.bv.sections.items():
			section = self.bv.sections[sname]
			line = '%s [0x%X, 0x%X)' % (sname, section.start, section.start + len(section))
			self.qcb_sections.addItem(line)

		self.chk_encoding.setChecked(False)
		self.chk_manual.setChecked(True)

		self.qle_address.setText(hex(self.context.address))
		self.qle_end.setText(hex(get_invalid_addr(self.bv, self.context.address)))
		btn_fill.setDefault(True)

	def encoding_checked_toggle(self, is_check):
		self.chk_manual.setChecked(not is_check)
		self.preview()

	def manual_checked_toggle(self, is_check):
		self.chk_encoding.setChecked(not is_check)
		self.preview()

	# report error to the preview field
	def error(self, msg):
		self.qle_preview.setText('ERROR: ' + msg)
		self.qle_preview.home(True)
		self.qle_datasz.setText('')

	# get the left, right, and length of the entered fill interval
	def interval(self):
		(a, b) = (0, 0)
		errval = (None, None, None)

		try:
			a = int(self.qle_address.text(), 16)
		except Exception:
			self.error('malformed number: %s' % self.qle_address.text())
			return errval

		try:
			b = int(self.qle_end.text(), 16)
		except Exception:
			return errval

		if (a,b) == (0, 0):
			# starting condition
			return errval

		if a == b-1:
			self.error('empty interval')
			return errval

		if a > b-1:
			self.error('negative interval')
			return errval

		if b - a > (16*1024*1024):
			self.error('too large (>16mb) interval')
			return errval

		return (a, b, b-a)

	# get the data (as bytes) from either:
	# - assembled bytes or manually
	# - manually entered bytes
	def data(self):
		text = None
		if self.chk_encoding.isChecked():
			text = self.qle_encoding.text()
		if self.chk_manual.isChecked():
			text = self.qle_bytes.text()

		buf = b''
		if not text: return buf
		for bstr in text.split(' '):
			if bstr.startswith('0x'):
				bstr = bstr[2:]
			if len(bstr) != 2 or \
			  not bstr[0] in hexchars or \
			  not bstr[1] in hexchars:
				self.error('malformed byte: %s' % bstr)
				return None
			buf += bytes([int(bstr, 16)])

		return buf

	# when user selects a section, populate [<address>, <end>)
	def section_chosen(self):
		line = self.qcb_sections.currentText()
		m = re.match(r'.* \[(.*), (.*)\)$', line)
		self.qle_address.setText(m.group(1))
		self.qle_end.setText(m.group(2))

	def encoding_checked_toggle(self, is_check):
		self.chk_manual.setChecked(not is_check)
		self.preview()

	def manual_checked_toggle(self, is_check):
		self.chk_encoding.setChecked(not is_check)
		self.preview()

	# selections -> preview field
	def preview(self):
		(_, _, fill_len) = self.interval()
		if not fill_len: return None
		data = self.data()
		if not data: return None

		self.qle_datasz.setText(hex(fill_len))

		if fill_len <= 8:
			self.qle_preview.setText(bytes_to_str(data[0:fill_len]))
		else:
			# fill length > 8
			if len(data) == 1:
				head = data * 6
				tail = data * 2
			else:
				head = (data * math.ceil(6/len(data)))[0:6]
				idx = len(data) + (fill_len % len(data)) - 2
				tail = (data+data)[idx:idx+2]

			self.qle_preview.setText(bytes_to_str(head) + ' ... ' + bytes_to_str(tail))

		self.qle_preview.home(True)

	def fill(self):
		# get, validate the interval
		(left, right, length) = self.interval()
		if left == None: return None
		for a in [left, right-1]:
			if not is_valid_addr(self.bv, a):
				self.error('0x%X invalid write address' % a)
				return

		# get, validate data
		data = self.data()
		if not data: return None

		# form the final write
		while len(data) < length:
			data = data*2
		data = data[0:length]

		# write it
		#print('writing 0x%X bytes to 0x%X' % (len(data), left))
		self.bv.write(left, data)

#------------------------------------------------------------------------------
# search tool
#------------------------------------------------------------------------------

class SearchTab(QWidget):
	def __init__(self, context, parent=None):
		super(SearchTab, self).__init__(parent)
		self.context = context
		self.bv = context.binaryView

		# this widget is VBox of QGroupBox
		layoutV = QVBoxLayout()

		form = QFormLayout()
		self.chk_encoding = QCheckBox('Assembled:')
		self.qle_encoding = QLineEdit()
		self.qle_encoding.setReadOnly(True)
		self.qle_encoding.setEnabled(False)
		form.addRow(self.chk_encoding, self.qle_encoding)
		self.chk_manual = QCheckBox('Bytes Regex:')
		self.qle_bytes = QLineEdit('48 (8b|8d)+ . . (F8|10)')
		form.addRow(self.chk_manual, self.qle_bytes)
		layoutV.addLayout(form)
		self.list_results = QListWidget()
		self.list_results.setFont(font_mono)
		layoutV.addWidget(self.list_results)
		btn_search = QPushButton('Search')
		layoutV.addWidget(btn_search)
		layoutV.addLayout(form)

		self.setLayout(layoutV)

		# connect everything
		self.chk_encoding.toggled.connect(self.encoding_checked_toggle)
		self.chk_manual.toggled.connect(self.manual_checked_toggle)
		self.list_results.itemDoubleClicked.connect(self.results_clicked)
		btn_search.clicked.connect(self.search)

		# set defaults
		self.chk_encoding.setChecked(False)
		self.chk_manual.setChecked(True)

		self.qle_bytes.setFocus()
		btn_search.setDefault(True)

	def encoding_checked_toggle(self, is_check):
		self.chk_manual.setChecked(not is_check)

	def manual_checked_toggle(self, is_check):
		self.chk_encoding.setChecked(not is_check)

	def search(self):
		# get search expression
		sexpr = None
		if self.chk_encoding.isChecked():
			sexpr = self.qle_encoding.text()
		if self.chk_manual.isChecked():
			sexpr = self.qle_bytes.text()

		# convert to binary regex
		sexpr = sexpr.strip()
		sexpr = re.sub(r'\s+', '', sexpr)
		regex = ''
		while sexpr:
			if len(sexpr) >= 2 and sexpr[0] in hexchars and sexpr[1] in hexchars:
				regex += chr(int(sexpr[0:2], 16))
				sexpr = sexpr[2:]
			else:
				regex += sexpr[0]
				sexpr = sexpr[1:]

		# validate regex
		try:
			regobj = re.compile(regex)
		except Exception:
			error('invalid regex: %s' % sexpr)
			return

		# clear old results
		self.list_results.clear()
		self.list_results.show()

		# loop through each section, searching it
		bview = self.bv
		width = max([len(sname) for sname in bview.sections])
		for sname in bview.sections:
			section = bview.sections[sname]
			start = section.start
			end = section.start + len(section)
			#print('searching section %s [0x%X, 0x%X)' % (sname, start, end))

			# TODO: find better way
			buf = ''.join([chr(x) for x in bview.read(start, end-start)])
			for m in regobj.finditer(buf):
				addr = section.start + m.start()
				info = '%s %08X: %s' % (sname.rjust(width), addr, strbytes_pretty(m.group()))
				self.list_results.addItem(QListWidgetItem(info))

	def results_clicked(self, item):
		#print('you double clicked %s' % item.text())
		m = re.match(r'^.* ([a-fA-F0-9]+):', item.text())
		addr = int(m.group(1), 16)
		self.bv.navigate(self.bv.view, addr)

#------------------------------------------------------------------------------
# top level tab gui
#------------------------------------------------------------------------------

class KeypatchDialog(QDialog):
	def __init__(self, context, parent=None):
		super(KeypatchDialog, self).__init__(parent)

		self.tab1 = AssembleTab(context)
		self.tab2 = FillRangeTab(context)
		self.tab3 = SearchTab(context)

		tabs = QTabWidget()
		tabs.addTab(self.tab1, "Assemble")
		tabs.addTab(self.tab2, "Fill")
		tabs.addTab(self.tab3, "Search")

		layout = QVBoxLayout()
		layout.addWidget(tabs)
		self.setLayout(layout)

		self.setWindowTitle('Keypatch')

		#
		self.tab1.add_qles_bytes(self.tab2.qle_encoding)
		self.tab1.add_qles_bytes(self.tab3.qle_encoding)
		self.tab1.reassemble()

		self.tab1.setFocus()
		self.tab1.qle_assembly.setFocus()

#------------------------------------------------------------------------------
# exported functions
#------------------------------------------------------------------------------

# input: binaryninjaui.UIActionContext (struct UIActionContext from api/ui/action.h)
def launch_keypatch(context):
	if context.binaryView == None:
		error('no binary')
		return

	dlg = KeypatchDialog(context)
	dlg.exec_()
