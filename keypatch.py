#!/usr/bin/env python

# python stdlib stuff
import sys
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

#------------------------------------------------------------------------------
# patcher tool
#------------------------------------------------------------------------------

class PatcherDialog(QDialog):
	def __init__(self, context, parent=None):
		super(PatcherDialog, self).__init__(parent)
		self.context = context

		self.setWindowTitle('KEYPATCH:: Patcher')

		layoutF = QFormLayout()
		self.setLayout(layoutF)

		self.qcb_arch = QComboBox()
		for (name, descr, arch_const, mode_const) in architecture_infos:
			line = '%s: %s' % (name, descr)
			self.qcb_arch.addItem(line)

		self.qle_address = QLineEdit('00000000')

		self.qle_assembly = QLineEdit('nop')
		self.qle_encoding = QLineEdit()
		self.qle_encoding.setReadOnly(True)
		self.qle_size = QLineEdit()
		self.qle_size.setReadOnly(True)
		check_nops = QCheckBox('NOPs padding until next instruction boundary')
		check_nops.setChecked(True)
		check_save_original = QCheckBox('Save original instructions in binja comment')
		check_save_original.setChecked(True)
		btn_cancel = QPushButton('Cancel')
		btn_patch = QPushButton('Patch')

		layoutF.addRow('Architecture:', self.qcb_arch)
		layoutF.addRow('Address:', self.qle_address)
		layoutF.addRow('&Assembly:', self.qle_assembly)
		layoutF.addRow('Encoding:', self.qle_encoding)
		layoutF.addRow('Size:', self.qle_size)
		layoutF.addRow(check_nops)
		layoutF.addRow(check_save_original)
		layoutF.addRow(btn_cancel, btn_patch)

		# initialize fields
		# initialize address
		self.qle_address.setText(hex(self.context.address))

		# initialize architecture
		bv_arch_name = context.binaryView.arch.name
		ks_arch_name = binja_to_ks.get(bv_arch_name, 'x64')
		self.qcb_arch.setCurrentIndex(([x[0] for x in architecture_infos]).index(ks_arch_name))

		# initialize disassembly
		ok = False
		try:
			(instxt, length) = disassemble_binja_single(context.binaryView, context.address)
			self.qle_assembly.setText(instxt)
			self.qle_size.setText('%d' % length)
			data = context.binaryView.read(context.address, length)
			self.qle_encoding.setText(' '.join(['%02X'%x for x in data]))
			ok = True
		except Exception as e:
			print(e)
			pass

		if not ok:
			self.qle_assembly.setText('nop')
			self.reassemble()

		# connect everything
		self.qcb_arch.currentTextChanged.connect(self.reassemble)
		self.qle_address.textChanged.connect(self.reassemble)
		self.qle_assembly.textChanged.connect(self.reassemble)
		btn_cancel.clicked.connect(self.cancel)
		btn_patch.clicked.connect(self.patch)

	def reassemble(self):
		do_clear = False
		try:
			arch_name_descr = self.qcb_arch.currentText()
			arch_name = arch_name_descr.split(':')[0]
			ks = architecture_to_ks[arch_name]

			addr = int(self.qle_address.text(), 16)

			assembly = self.qle_assembly.text()

			#print('(%s, %s, %s)' % (arch_name, addr, assembly))
			encoding, count = ks.asm(assembly)
			self.qle_encoding.setText(' '.join(['%02X'%x for x in encoding]))
			self.qle_size.setText('%d' % count)
		except ValueError:
			self.qle_size.setText('')
			self.qle_encoding.setText('invalid address')
		except KsError as e:
			self.qle_size.setText('')
			self.qle_encoding.setText(str(e))
			self.qle_encoding.home(True)
		except Exception as e:
			self.qle_size.setText('')
			self.qle_encoding.setText(str(e))
			self.qle_encoding.home(True)

	def patch(self):
		try:
			addr = int(self.qle_address.text(), 16)
			values = [int(x, 16) for x in self.qle_encoding.text().split(' ')]
			data = bytes(values)
			self.context.binaryView.write(addr, data)
		except Exception as e:
			print(e)

	def cancel(self):
		self.close()

#------------------------------------------------------------------------------
# exported functions
#------------------------------------------------------------------------------

# input: binaryninjaui.UIActionContext (struct UIActionContext from api/ui/action.h)
def launch_patcher(context):
	if context.binaryView == None:
		show_message_box('KEYPATCH', 'no binary', MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)
		return

	dlg = PatcherDialog(context)
	dlg.exec_()

