#!/usr/bin/env python

import math
# python stdlib stuff
import re

from PySide6.QtGui import QFont
# Qt stuff
from PySide6.QtWidgets import *
from binaryninja.enums import MessageBoxButtonSet, MessageBoxIcon
from binaryninja.interaction import show_message_box
from binaryninjaui import UIContext
# capstone/keystone stuff
from capstone import *
from keystone import *

# ------------------------------------------------------------------------------
# lookups
# ------------------------------------------------------------------------------
hexchars = '0123456789ABCDEFabcdef'

# (name, description, arch, mode, option)
architecture_infos = [('x16', 'X86 16bit, Intel syntax', CS_ARCH_X86, CS_MODE_16, KS_ARCH_X86, KS_MODE_16),
                      ('x32', 'X86 32bit, Intel syntax', CS_ARCH_X86, CS_MODE_32, KS_ARCH_X86, KS_MODE_32),
                      ('x64', 'X86 64bit, Intel syntax', CS_ARCH_X86, CS_MODE_64, KS_ARCH_X86, KS_MODE_64),
                      ('x16att', 'X86 16bit, AT&T syntax', CS_ARCH_X86, CS_MODE_16, KS_ARCH_X86, KS_MODE_16),
                      ('x32att', 'X86 32bit, AT&T syntax', CS_ARCH_X86, CS_MODE_32, KS_ARCH_X86, KS_MODE_32),
                      ('x64att', 'X86 64bit, AT&T syntax', CS_ARCH_X86, CS_MODE_64, KS_ARCH_X86, KS_MODE_64),
                      ('x16nasm', 'X86 16bit, NASM syntax', CS_ARCH_X86, CS_MODE_16, KS_ARCH_X86, KS_MODE_16),
                      ('x32nasm', 'X86 32bit, NASM syntax', CS_ARCH_X86, CS_MODE_32, KS_ARCH_X86, KS_MODE_32),
                      ('x64nasm', 'X86 64bit, NASM syntax', CS_ARCH_X86, CS_MODE_64, KS_ARCH_X86, KS_MODE_64),
                      ('arm', 'ARM - little endian', CS_ARCH_ARM, CS_MODE_ARM, KS_ARCH_ARM, KS_MODE_ARM),
                      ('armbe', 'ARM - big endian', CS_ARCH_ARM, CS_MODE_ARM, KS_ARCH_ARM, KS_MODE_ARM),
                      ('thumb', 'Thumb - little endian', CS_ARCH_ARM, CS_MODE_THUMB, KS_ARCH_ARM, KS_MODE_THUMB),
                      ('thumbbe', 'Thumb - big endian', CS_ARCH_ARM, CS_MODE_THUMB, KS_ARCH_ARM, KS_MODE_THUMB),
                      ('armv8', 'ARM V8 - little endian', CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_V8, KS_ARCH_ARM,
                       KS_MODE_ARM | KS_MODE_V8),
                      ('armv8be', 'ARM V8 - big endian', CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_V8, KS_ARCH_ARM,
                       KS_MODE_ARM | KS_MODE_V8), (
                          'thumbv8', 'Thumb V8 - little endian', CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_V8, KS_ARCH_ARM,
                          KS_MODE_THUMB | KS_MODE_V8), (
                          'thumbv8be', 'Thumb V8 - big endian', CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_V8, KS_ARCH_ARM,
                          KS_MODE_THUMB | KS_MODE_V8), ('arm64', 'AArch64', CS_ARCH_ARM64, 0, KS_ARCH_ARM64, 0),
                      ('hexagon', 'Hexagon', None, 0, KS_ARCH_HEXAGON, 0),
                      ('mips', 'Mips - little endian', CS_ARCH_MIPS, CS_MODE_MIPS32, KS_ARCH_MIPS, KS_MODE_MIPS32),
                      ('mipsbe', 'Mips - big endian', CS_ARCH_MIPS, CS_MODE_MIPS32, KS_ARCH_MIPS, KS_MODE_MIPS32),
                      ('mips64', 'Mips64 - little endian', CS_ARCH_MIPS, CS_MODE_MIPS64, KS_ARCH_MIPS, KS_MODE_MIPS64),
                      ('mips64be', 'Mips64 - big endian', CS_ARCH_MIPS, CS_MODE_MIPS64, KS_ARCH_MIPS, KS_MODE_MIPS64),
                      ('ppc32be', 'PowerPC32 - big endian', CS_ARCH_PPC, CS_MODE_32, KS_ARCH_PPC, KS_MODE_PPC32),
                      ('ppc64', 'PowerPC64 - little endian', CS_ARCH_PPC, CS_MODE_64, KS_ARCH_PPC, KS_MODE_PPC64),
                      ('ppc64be', 'PowerPC64 - big endian', CS_ARCH_PPC, CS_MODE_64, KS_ARCH_PPC, KS_MODE_PPC64),
                      ('sparc', 'Sparc - little endian', CS_ARCH_SPARC, 0, KS_ARCH_SPARC, KS_MODE_SPARC32),
                      ('sparcbe', 'Sparc - big endian', CS_ARCH_SPARC, 0, KS_ARCH_SPARC, KS_MODE_SPARC32),
                      ('sparc64be', 'Sparc64 - big endian', None, 0, KS_ARCH_SPARC, KS_MODE_SPARC64),
                      ('systemz', 'SystemZ (S390x)', None, 0, KS_ARCH_SYSTEMZ, 0),
                      ('evm', 'Ethereum Virtual Machine', CS_ARCH_EVM, 0, KS_ARCH_EVM, 0)]

# map architecture names (capstone namespace) to capstone/keystone context
architecture_to_cs = {}
architecture_to_ks = {}
for (name, descr, cs_arch, cs_mode, ks_arch, ks_mode) in architecture_infos:
    # default is little endian
    # decide whether to set big endian
    if name.endswith('be'):
        cs_mode |= CS_MODE_BIG_ENDIAN
        ks_mode |= KS_MODE_BIG_ENDIAN
    else:
        cs_mode |= CS_MODE_LITTLE_ENDIAN
        ks_mode |= KS_MODE_LITTLE_ENDIAN

    # initialize architecture
    (cs, ks) = (None, None)
    if cs_arch != None:
        cs = Cs(cs_arch, cs_mode)
    # print('Ks() on %s %s' % (name, descr))
    ks = Ks(ks_arch, ks_mode)

    # set special syntax if indicated
    if 'AT&T syntax' in descr:
        # ks_option(KS_OPT_SYNTAX, KS_OPT_SYNTAX_ATT)
        ks.syntax = KS_OPT_SYNTAX_ATT
    if name.endswith('nasm'):
        # ks_option(KS_OPT_SYNTAX, KS_OPT_SYNTAX_NASM)
        ks.syntax = KS_OPT_SYNTAX_NASM

    architecture_to_cs[name] = cs
    architecture_to_ks[name] = ks

font_mono = QFont('Courier New')
font_mono.setStyleHint(QFont.TypeWriter)

# ------------------------------------------------------------------------------
# utilities
# ------------------------------------------------------------------------------

# return the name of the architecture, in the capstone/keystone namespace
def determine_arch(bview):
    arch = None

    # determine the architecture name in the binja namespace

    # if there's a current function, use that architecture, as it can distinguish
    # between arm/thumb, whereas bv.arch would just be arm
    try:
        ac = UIContext.activeContext().contentActionHandler().actionContext()
        current_function = ac.function
        arch = current_function.arch
    except Exception as e:
        pass

    # use architecture from binaryview
    if arch == None:
        arch = bview.arch

    # sometimes the binaryview has no arch, like when File->New->Binary Data
    if arch == None:
        arch = binaryninja.Architecture['x86_64']

    # map how binja names architectures to how keystone names architectures:
    return {
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
    }[arch.name]

# test if given address is valid binaryview address
def is_valid_addr(bview, addr):
    # if the binaryview has sections, validity is whether the address is in a section
    if bview.sections:
        for sname in bview.sections:
            section = bview.sections[sname]
            start = section.start
            end = section.start + section.length
            if addr >= start and addr < end:
                return True
        return False
    # otherwise
    else:
        return addr >= bview.start and addr < (bview.start + bview.length)

# given a valid address, return least address after the valid that is invalid
def get_invalid_addr(bview, addr):
    if not is_valid_addr(bview, addr):
        return None

    # if the binaryview has sections, next invalid address is end of current section
    if bview.sections:
        for sname in bview.sections:
            section = bview.sections[sname]
            start = section.start
            end = section.start + section.length
            if addr >= start and addr < end:
                return end
    # otherwise
    else:
        return bview.start + bview.length

# disassemble some given data
# returns (<instruction_string>, <instruction_length>)
# returns (None, None) if unable to disassemble
def disassemble(bview, arch, data, addr):
    md = architecture_to_cs[arch]
    try:
        (addr, size, mnemonic, op_str) = next(md.disasm_lite(data, addr, 1))
        if not size:
            return (None, None)
    except StopIteration:
        return (None, None)
    return (mnemonic + ' ' + op_str, size)

# disassemble from an address in the BinaryView, with the given arch
# returns (<instruction_string>, <instruction_length>)
# returns (None, None) if unable to disassemble
def disassemble_bview(bview, arch, addr):
    if not is_valid_addr(bview, addr):
        return (None, None)
    end = get_invalid_addr(bview, addr)
    length = min(16, end - addr)
    data = bview.read(addr, length)
    return disassemble(bview, arch, data, addr)

# get length of instruction at addr
# returns None if unable to disassemble
def disassemble_length(bview, arch, addr):
    (instxt, length) = disassemble_bview(bview, arch, addr)
    return length

def error(msg):
    show_message_box('KEYPATCH', msg, MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)

# b'\xaa\xbb\xcc\xdd' -> 'AA BB CC DD'
def bytes_to_str(data):
    return ' '.join(['%02X' % x for x in data])

def strbytes_pretty(string):
    return ' '.join(['%02X' % ord(x) for x in string])

def fixup(bview, arch_name, assembly):
    reserved = {
        'mips': [],
        'arm':     ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'sp', 'lr', 'pc', 'apsr'],
        'armbe':   ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'sp', 'lr', 'pc', 'apsr'],
        'thumb':   ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'sp', 'lr', 'pc', 'apsr'],
        'thumbbe': ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'sp', 'lr', 'pc', 'apsr'],
        'arm64':   ['x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7', 'x8', 'x9', 'x10', 'x11', 'x12', 'x13', 'x14', 'x15', 'x16', 'x17', 'x18', 'x19', 'x20', 'x21', 'x22', 'x23', 'x24', 'x25', 'x26', 'x27', 'x28', 'x29', 'x30', 'x31', 'fp', 'lr', 'pc', 'w0', 'w1', 'w2', 'w3', 'w4', 'w5', 'w6', 'w7', 'w8', 'w9', 'w10', 'w11', 'w12', 'w13', 'w14', 'w15', 'w16', 'w17', 'w18', 'w19', 'w20', 'w21', 'w22', 'w23', 'w24', 'w25', 'w26', 'w27', 'w28', 'w29', 'w30', 'w31'],
        'x16nasm': ['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di', 'ah', 'al', 'ch', 'cl', 'dh', 'dl', 'bh', 'bl', 'ss', 'cs', 'ds', 'es'],
        'x32nasm': ['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di', 'ah', 'al', 'ch', 'cl', 'dh', 'dl', 'bh', 'bl', 'ss', 'cs', 'ds', 'es', 'eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi', 'fs'],
        'x64nasm': ['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di', 'ah', 'al', 'ch', 'cl', 'dh', 'dl', 'bh', 'bl', 'ss', 'cs', 'ds', 'es', 'eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi', 'fs', 'rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi']
    }.get(arch_name)

    # collect substitutions we'll make
    substitutions = []

    # loop over every word character token
    for m in re.finditer(r'\w+', assembly):
        if m.start() == 0: continue  # do not replace mnemonic
        symname = m.group(0)

        # is reserved word? ignore
        if symname in reserved:
            continue

        # is it just a hex constant? ignore
        if re.match(r'^0x[a-fA-F0-9]+$', symname):
            continue

        # is in symbols? replace with first available address
        if symname in bview.symbols:
            # multiple symbols at given address possible
            for sym in bview.symbols[symname]:
                if hasattr(sym, 'address'):
                    substitutions.append((sym.name, sym.address))
                    break

        # is a data variable?
        m = re.match(r'^data_([a-fA-F0-9]+)$', symname)
        if m:
            addr = int(m.group(1), 16)
            if addr in bview.data_vars:
                substitutions.append((symname, addr))

    # apply substitutions
    for (name, addr) in substitutions:
        assembly = assembly.replace(name, hex(addr))

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
    elif arch in ['arm64']:
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

# ------------------------------------------------------------------------------
# GUI
# ------------------------------------------------------------------------------

class AssembleTab(QWidget):
    def __init__(self, context, parent=None):
        super(AssembleTab, self).__init__(parent)
        self.context = context
        self.bview = context.binaryView

        # other QLineEntry widgets to receive bytes upon assembling
        self.qles_bytes = []

        # ----------------------------------------------------------------------
        # assemble tab
        # ----------------------------------------------------------------------
        layout = QVBoxLayout()
        self.setLayout(layout)

        form = QFormLayout()
        self.qcb_arch = QComboBox()
        form.addRow('Architecture:', self.qcb_arch)
        self.qle_address = QLineEdit('00000000')
        form.addRow('Address:', self.qle_address)
        self.qle_assembly = QLineEdit()
        form.addRow('Assembly:', self.qle_assembly)
        # Add a new QLineEdit to receive  bytes
        self.edit_bytes = QLineEdit()
        form.addRow('Edit Bytes:', self.edit_bytes)
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
        self.qcb_arch.currentTextChanged.connect(self.re_assemble)
        self.qle_address.textChanged.connect(self.re_assemble)
        self.qle_assembly.textChanged.connect(self.re_assemble)
        self.edit_bytes.textChanged.connect(self.re_disassemble)
        btn_patch.clicked.connect(self.patch)

        # ----------------
        # set defaults
        # ----------------

        # default architecture dropdown in assemble
        for (name, descr, _, _, _, _) in architecture_infos:
            line = '%s: %s' % (name, descr)
            self.qcb_arch.addItem(line)

        ks_arch_name = determine_arch(context.binaryView)
        self.qcb_arch.setCurrentIndex(([x[0] for x in architecture_infos]).index(ks_arch_name))

        # default address to assemble
        self.qle_address.setText(hex(self.context.address))

        # default assembly
        (instxt, length) = disassemble_bview(self.bview, self.arch(), context.address)
        if instxt:
            self.qle_assembly.setText(instxt)
            self.qle_fixedup.setText(instxt)
            self.qle_datasz.setText('%d' % length)
            ok = True
        else:
            length = 10
            self.qle_assembly.setText('nop')
        data = context.binaryView.read(context.address, length)
        self.qle_data.setText(' '.join(['%02X' % x for x in data]))
        self.edit_bytes.setText(self.qle_data.text())
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

    # get selected architecture from drop-down menu
    # (this was set initially by sensing the environment)
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
    def re_assemble(self):
        try:
            # get input
            (ks, assembly, addr) = (self.ks(), self.asm(), self.addr())

            # apply fixup
            fixedup = fixup(self.bview, self.arch(), assembly)
            self.qle_fixedup.setText(fixedup)

            # assemble
            data, count = ks.asm(fixedup, addr)
            if not data: return
            for widget in self.qles_bytes:
                widget.setText(bytes_to_str(data))

            # pad with nops
            if self.check_nops.isChecked():
                length = disassemble_length(self.bview, self.arch(), self.addr())
                if length != None and length > len(data):
                    nop = get_nop(self.arch())
                    sled = (length // len(nop)) * nop
                    sled = list(sled)  # b'\xAA' -> [0xAA]
                    data = data + sled[len(data):]

            # set
            self.qle_data.setText(bytes_to_str(data))
            self.edit_bytes.setText(bytes_to_str(data))
            self.qle_datasz.setText(hex(len(data)))

        except ValueError:
            self.error('invalid address')
        except KsError as e:
            self.error(str(e))
        except Exception as e:
            self.error(str(e))

    # update the self.qle_data.text() and self.qle_fixedup.text() through self.edit_bytes.text()
    def re_disassemble(self):
        try:
            # get input
            addr = self.addr()
            data = bytes.fromhex(self.edit_bytes.text())

            (disasm, length) = disassemble(self.bview, self.arch(), data, addr)
            # pad with nops
            if self.check_nops.isChecked():
                length = disassemble_length(self.bview, self.arch(), self.addr())
                if length != None and length > len(data):
                    nop = get_nop(self.arch())
                    sled = (length // len(nop)) * nop
                    data = data + sled[len(data):]
            self.qle_data.setText(bytes_to_str(data))
            self.qle_datasz.setText(hex(len(data)))
            if disasm is not None:
                self.qle_fixedup.setText(disasm)
            else:
                self.qle_fixedup.setText("...")
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
                (instxt, length) = disassemble_bview(self.bview, self.arch(), self.addr())
                if instxt and length:
                    comment = 'previously: ' + instxt
        except Exception as e:
            print(e)
            pass

        try:
            with self.bview.undoable_transaction():
                self.bview.write(self.addr(), data)
                if comment:
                    self.bview.set_comment_at(self.addr(), comment)
        except Exception as e:
            return

    # report error to the bytes
    def error(self, msg):
        self.qle_datasz.setText('')
        if not ('error' in msg or 'ERROR' in msg):
            msg = 'ERROR: ' + msg
        self.qle_data.setText(msg)
        self.qle_data.home(True)

# ------------------------------------------------------------------------------
# fill range tool
# ------------------------------------------------------------------------------

class FillRangeTab(QWidget):
    def __init__(self, context, parent=None):
        super(FillRangeTab, self).__init__(parent)
        self.context = context
        self.bview = context.binaryView

        # this widget is VBox of QGroupBox
        layoutV = QVBoxLayout()
        self.setLayout(layoutV)

        self.qle_end = QLineEdit('00000000')
        self.qle_encoding = QLineEdit()
        self.qle_encoding.setReadOnly(True)
        self.qle_encoding.setEnabled(False)
        self.qle_bytes = QLineEdit('00')
        # not used
        # self.qle_fill_size = QLineEdit()
        # self.qle_fill_size.setReadOnly(True)
        # self.qle_fill_size.setEnabled(False)
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
        self.qle_datasz.textChanged.connect(self.preview_by_size_change)

        self.chk_encoding.toggled.connect(self.encoding_checked_toggle)
        self.chk_manual.toggled.connect(self.manual_checked_toggle)

        self.qle_bytes.textChanged.connect(self.preview)

        btn_fill.clicked.connect(self.fill)

        # set defaults
        nop = get_nop(determine_arch(self.bview))
        if nop:
            self.qle_bytes.setText(bytes_to_str(nop))

        for (sname, section) in self.bview.sections.items():
            section = self.bview.sections[sname]
            line = '%s [0x%X, 0x%X)' % (sname, section.start, section.start + section.length)
            self.qcb_sections.addItem(line)

        self.chk_encoding.setChecked(False)
        self.chk_manual.setChecked(True)

        self.qle_address.setText(hex(self.context.address))
        end = get_invalid_addr(self.bview, self.context.address)
        if end != None:
            self.qle_end.setText(hex(end))
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

    # get the left, right, and length of the entered fill interval
    # calculate length through left and right
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

        if (a, b) == (0, 0):
            # starting condition
            return errval

        if a == b:
            self.error('empty interval')
            return errval

        if a > b:
            self.error('negative interval')
            return errval

        if b - a > (16 * 1024 * 1024):
            self.error('too large (>16mb) interval')
            return errval
        return (a, b, b - a)

    # get the left, right, and length(size) of the entered fill interval
    # calculate right through left and length(size)
    def interval_by_size_change(self):
        (a, b) = (0, 0)
        errval = (None, None, None)

        try:
            a = int(self.qle_address.text(), 16)
        except Exception:
            self.error('malformed number: %s' % self.qle_address.text())
            return errval

        try:
            size = int(self.qle_datasz.text(), 16)
        except Exception:
            return errval
        if size <= 0:
            self.error('length must > 0')
            return errval
        b = a + size
        if (a, b) == (0, 0):
            # starting condition
            return errval

        if a == b:
            self.error('empty interval')
            return errval

        if a > b:
            self.error('negative interval')
            return errval

        if b - a > (16 * 1024 * 1024):
            self.error('too large (>16mb) interval')
            return errval
        return (a, b, size)

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
            if len(bstr) != 2 or not bstr[0] in hexchars or not bstr[1] in hexchars:
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

    # elections -> preview field
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
                head = (data * math.ceil(6 / len(data)))[0:6]
                idx = len(data) + (fill_len % len(data)) - 2
                tail = (data + data)[idx:idx + 2]

            self.qle_preview.setText(bytes_to_str(head) + ' ... ' + bytes_to_str(tail))

        self.qle_preview.home(True)

    def preview_by_size_change(self):
        (st, ed, fill_len) = self.interval_by_size_change()
        if not fill_len: return None
        data = self.data()
        if not data: return None
        self.qle_end.setText(hex(ed))
        if fill_len <= 8:
            self.qle_preview.setText(bytes_to_str(data[0:fill_len]))
        else:
            # fill length > 8
            if len(data) == 1:
                head = data * 6
                tail = data * 2
            else:
                head = (data * math.ceil(6 / len(data)))[0:6]
                idx = len(data) + (fill_len % len(data)) - 2
                tail = (data + data)[idx:idx + 2]

            self.qle_preview.setText(bytes_to_str(head) + ' ... ' + bytes_to_str(tail))

        self.qle_preview.home(True)

    def fill(self):
        # get, validate the interval
        left, right, length = self.interval()
        #print(f'filling [0x{left:X}, 0x{right:X}) length 0x{length:X}')
        if left == None: return None
        for a in [left, right - 1]:
            if not is_valid_addr(self.bview, a):
                self.error('0x%X invalid write address' % a)
                return

        # get, validate data
        data = self.data()
        if not data: return None

        # form the final write
        while len(data) < length:
            data = data * 2
        data = data[0:length]

        # write it
        #print('writing 0x%X bytes to 0x%X' % (len(data), left))
        with self.bview.undoable_transaction():
            self.bview.write(left, data)

# ------------------------------------------------------------------------------
# search tool
# ------------------------------------------------------------------------------

class SearchTab(QWidget):
    def __init__(self, context, parent=None):
        super(SearchTab, self).__init__(parent)
        self.context = context
        self.bview = context.binaryView

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

        # get rid of bad chars and whitespace in input line
        sexpr = sexpr.strip()
        sexpr = re.sub(r'\s+', '', sexpr)

        # parse regex input line

        my_encoding = 'utf8'
        regex = b''
        while sexpr:
            if len(sexpr) >= 2 and sexpr[0] in hexchars and sexpr[1] in hexchars:
                regex += re.escape(bytes.fromhex(sexpr[0:2]))
                sexpr = sexpr[2:]
            else:
                regex += sexpr[0:1].encode(my_encoding)
                sexpr = sexpr[1:]

        # validate regex
        try:
            regobj = re.compile(regex)
        except Exception:
            error('invalid regex')
            return

        # clear old results
        self.list_results.clear()
        self.list_results.show()

        # loop through each section, searching it
        bview = self.bview

        intervals = []
        if bview.sections:
            width = max([len(sname) for sname in bview.sections])
            intervals = [(n, s.start, s.start + s.length) for n,s in bview.sections.items()]
        else:
            # some views don't have sections, like File -> New Binary Data
            width = 3
            intervals = [('raw', bview.start, bview.end)]

        for name, start, end in intervals:
            #print(f'searching bytes in [0x{start:X}, 0x{end:X})')

            buf = bview.read(start, end - start)

            for m in regobj.finditer(buf):
                addr = start + m.start()

                # m.group is bytes type
                info = '%s %08X: %s' % (name.rjust(width), addr, bytes_to_str(m.group()))
                self.list_results.addItem(QListWidgetItem(info))

    def results_clicked(self, item):
        # print('you double clicked %s' % item.text())
        m = re.match(r'^.* ([a-fA-F0-9]+):', item.text())
        addr = int(m.group(1), 16)
        self.bview.navigate(self.bview.view, addr)

# ------------------------------------------------------------------------------
# top level tab gui
# ------------------------------------------------------------------------------

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
        self.tab1.re_assemble()

        self.tab1.setFocus()
        self.tab1.qle_assembly.setFocus()

# ------------------------------------------------------------------------------
# exported functions
# ------------------------------------------------------------------------------

# input: binaryninjaui.UIActionContext (struct UIActionContext from api/ui/action.h)
def launch_keypatch(context):
    if context.binaryView == None:
        error('no binary')
        return

    dlg = KeypatchDialog(context)
    dlg.exec()
