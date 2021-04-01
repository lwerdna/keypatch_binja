#!/usr/bin/env python

# python stdlib stuff
import sys
import math
# Qt stuff
from PySide2.QtWidgets import *
# keystone stuff
from keystone import *
# binaryninja
from binaryninja.interaction import show_message_box
from binaryninja.enums import MessageBoxButtonSet, MessageBoxIcon

#------------------------------------------------------------------------------
# lookups
#------------------------------------------------------------------------------

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
	#'ppc_le',
	'ppc64': 'ppc64be',
	'ppc64_le': 'ppc64',
	#'sh4',
	'x86_16': 'x16nasm',
	'x86': 'x32nasm',
	'x86_64': 'x64nasm'
}

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

def bytes_to_str(data):
	return ' '.join(['%02X'%x for x in data])

#------------------------------------------------------------------------------
# keypatch dialog parent class
#------------------------------------------------------------------------------

class KeypatchDialog(QDialog):
	def __init__(self, context, parent=None):
		super(KeypatchDialog, self).__init__(parent)
		self.context = context

		# set up the architecture
		combobox = QComboBox()
		for (name, descr, arch_const, mode_const) in architecture_infos:
			line = '%s: %s' % (name, descr)
			combobox.addItem(line)

		bv_arch_name = context.binaryView.arch.name
		ks_arch_name = binja_to_ks.get(bv_arch_name, 'x64')
		combobox.setCurrentIndex(([x[0] for x in architecture_infos]).index(ks_arch_name))

		self.qcb_arch = combobox

		# set up the address
		ledit = QLineEdit('00000000')
		ledit.setText(hex(self.context.address))
		self.qle_address = ledit

		# set up assembly fields
		self.qle_assembly = QLineEdit()
		self.qle_asm_size = QLineEdit()
		self.qle_asm_size.setReadOnly(True)
		self.qle_encoding = QLineEdit()
		self.qle_encoding.setReadOnly(True)

		ok = False
		try:
			(instxt, length) = disassemble_binja_single(context.binaryView, context.address)
			self.qle_assembly.setText(instxt)
			self.qle_asm_size.setText('%d' % length)
			data = context.binaryView.read(context.address, length)
			self.qle_encoding.setText(' '.join(['%02X'%x for x in data]))
			ok = True
		except Exception as e:
			print(e)
			pass
		if not ok:
			self.qle_assembly.setText('nop')
			self.reassemble()

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
			values = [int(x, 16) for x in self.qle_encoding.text().split(' ')]
			return bytes(values)
		except Exception:
			return None

	def bv(self):
		return self.context.binaryView

	#
	# functions
	#
	def nop(self):
		arch = self.arch()
		if arch in ['x16', 'x32', 'x64', 'x16att', 'x32att', 'x64att', 'x16nasm', 'x32nasm', 'x64nasm']:
			return b'\x90'
		elif arch in ['thumb', 'thumbv8']:
			return b'\x00\xbf'
		elif arch in ['thumbbe', 'thumbv8be']:
			return b'\xbf\x00'
		return None

	def reassemble(self):
		try:
			(ks, assembly, addr) = (self.ks(), self.asm(), self.addr())
			encoding, count = ks.asm(assembly, addr)
			self.qle_encoding.setText(' '.join(['%02X'%x for x in encoding]))
			self.qle_asm_size.setText('%d' % len(encoding))
		except ValueError:
			self.qle_asm_size.setText('')
			self.qle_encoding.setText('invalid address')
		except KsError as e:
			self.qle_asm_size.setText('')
			self.qle_encoding.setText(str(e))
			self.qle_encoding.home(True)
		except Exception as e:
			self.qle_asm_size.setText('')
			self.qle_encoding.setText(str(e))
			self.qle_encoding.home(True)

	def cancel(self):
		self.close()

#------------------------------------------------------------------------------
# patcher tool
#------------------------------------------------------------------------------

class PatcherDialog(KeypatchDialog):
	def __init__(self, context, parent=None):
		super(PatcherDialog, self).__init__(context, parent)

		self.setWindowTitle('KEYPATCH:: Patcher')

		layoutF = QFormLayout()
		self.setLayout(layoutF)

		self.check_nops = QCheckBox('NOPs padding until next instruction boundary')
		self.check_nops.setChecked(True)
		self.check_save_original = QCheckBox('Save original instructions in binja comment')
		self.check_save_original.setChecked(True)
		btn_cancel = QPushButton('Cancel')
		btn_patch = QPushButton('Patch')

		layoutF.addRow('Architecture:', self.qcb_arch)
		layoutF.addRow('Address:', self.qle_address)
		layoutF.addRow('Assembly:', self.qle_assembly)
		layoutF.addRow('Encoding:', self.qle_encoding)
		layoutF.addRow('Size:', self.qle_asm_size)
		layoutF.addRow(self.check_nops)
		layoutF.addRow(self.check_save_original)
		layoutF.addRow(btn_patch, btn_cancel)

		# connect everything
		self.qcb_arch.currentTextChanged.connect(self.reassemble)
		self.qle_address.textChanged.connect(self.reassemble)
		self.qle_assembly.textChanged.connect(self.reassemble)
		btn_cancel.clicked.connect(self.cancel)
		btn_patch.clicked.connect(self.patch)

		# set defaults
		self.qle_assembly.setFocus()
		btn_patch.setDefault(True)

	def patch(self):
		data = self.data()

		# fill with NOP's?
		try:
			if self.check_nops.isChecked():
				length = disassemble_length_until(self.bv(), self.addr(), len(data))
				if length > len(data):
					nop = self.nop()
					sled = (length // len(nop)) * nop
					data = data + sled[len(data):]
		except Exception:
			pass

		comment = None
		try:
			if self.check_save_original.isChecked():
				(instxt, length) = disassemble_binja_single(self.bv(), self.addr())
				comment = instxt
		except Exception as e:
			print(e)
			pass

		try:
			self.bv().write(self.addr(), data)

			if comment:
				self.bv().set_comment_at(self.addr(), comment)
		except Exception as e:
			return

#------------------------------------------------------------------------------
# fill range tool
#------------------------------------------------------------------------------

class FillRangeDialog(KeypatchDialog):
	def __init__(self, context, parent=None):
		super(FillRangeDialog, self).__init__(context, parent)

		self.setWindowTitle('KEYPATCH:: Fill Range')

		# this widget is VBox of QGroupBox
		layoutV = QVBoxLayout()
		self.setLayout(layoutV)

		self.qle_end = QLineEdit('00000000')
		self.qle_bytes = QLineEdit('DE AD BE EF')
		self.qle_fill_size = QLineEdit()
		self.qle_fill_size.setReadOnly(True)
		self.qle_preview = QLineEdit()
		self.qle_preview.setReadOnly(True)

		btn_cancel = QPushButton('Cancel')
		btn_patch = QPushButton('Patch')

		groupbox = QGroupBox('range:')
		horiz = QHBoxLayout()
		horiz.addWidget(QLabel('['))
		horiz.addWidget(self.qle_address)
		horiz.addWidget(QLabel(','))
		horiz.addWidget(self.qle_end)
		horiz.addWidget(QLabel(')'))
		groupbox.setLayout(horiz)
		layoutV.addWidget(groupbox)

		self.group_a = QGroupBox('assemble:')
		self.group_a.setCheckable(True)
		form = QFormLayout()
		form.addRow('Architecture:', self.qcb_arch)
		form.addRow('Assembly:', self.qle_assembly)
		form.addRow('Encoding:', self.qle_encoding)
		self.group_a.setLayout(form)
		layoutV.addWidget(self.group_a)

		self.group_m = QGroupBox('manual:')
		self.group_m.setCheckable(True)
		form = QFormLayout()
		form.addRow('Bytes:', self.qle_bytes)
		self.group_m.setLayout(form)
		layoutV.addWidget(self.group_m)

		form = QFormLayout()
		form.addRow('Preview:', self.qle_preview)
		form.addRow(btn_patch, btn_cancel)
		layoutV.addLayout(form)

		# connect everything
		self.qcb_arch.currentTextChanged.connect(self.reassemble)
		self.qle_assembly.textChanged.connect(self.reassemble)
		self.qle_encoding.textChanged.connect(self.preview)

		self.qle_address.textChanged.connect(self.preview)
		self.qle_end.textChanged.connect(self.preview)

		self.group_a.toggled.connect(self.assembly_checked_toggle)
		self.group_m.toggled.connect(self.manual_checked_toggle)

		self.qle_bytes.textChanged.connect(self.preview)

		btn_cancel.clicked.connect(self.cancel)
		btn_patch.clicked.connect(self.fill)

		# set defaults
		self.group_a.setCheckable(True)
		self.group_m.setChecked(False)

		self.qle_end.setText(hex(get_invalid_addr(self.bv(), self.addr())))
		self.qle_assembly.setFocus()
		btn_patch.setDefault(True)

	# report error to the preview field
	def error(self, msg):
		self.qle_preview.setText('ERROR: ' + msg)

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
		hexchars = '0123456789ABCDEFabcdef'

		text = None
		if self.group_a.isChecked():
			text = self.qle_encoding.text()
		if self.group_m.isChecked():
			text = self.qle_bytes.text()

		buf = b''
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

	def assembly_checked_toggle(self, is_check):
		self.group_m.setChecked(not is_check)
		self.preview()

	def manual_checked_toggle(self, is_check):
		self.group_a.setChecked(not is_check)
		self.preview()

	def preview(self):
		(_, _, length) = self.interval()
		if not length: return None
		data = self.data()
		if not data: return None

		if length <= 8:
			self.qle_preview.setText(bytes_to_str(data))
		else:
			head = data * math.ceil(6/len(data))
			idx = len(data) + (length % len(data)) - 2
			tail = (data+data)[idx:idx+2]
			self.qle_preview.setText(bytes_to_str(head) + ' ... ' + bytes_to_str(tail))

	def fill(self):
		# get, validate the interval
		(left, right, length) = self.interval()
		if left == None: return None
		for a in [left, right]:
			if not is_valid_addr(self.bv(), a):
				self.error('0x%X invalid write address' % left)
				return

		# get, validate data
		data = self.data()
		if not data: return None

		# form the final write
		while len(data) < length:
			data = data*2
		data = data[0:length]

		# write it
		print('writing %d bytes to 0x%X' % (len(data), left))
		self.bv().write(left, data)

#------------------------------------------------------------------------------
# exported functions
#------------------------------------------------------------------------------

# input: binaryninjaui.UIActionContext (struct UIActionContext from api/ui/action.h)
def launch_patcher(context):
	if context.binaryView == None:
		error('no binary')
		return

	dlg = PatcherDialog(context)
	dlg.exec_()

def launch_fill_range(context):
	if context.binaryView == None:
		error('no binary')
		return

	dlg = FillRangeDialog(context)
	dlg.exec_()
