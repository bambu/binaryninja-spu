from __future__ import print_function
import struct
from collections import namedtuple

from binaryninja import (
    Architecture, RegisterInfo, InstructionInfo,
    core, InstructionTextToken,

    RegisterToken, IntegerToken, OperandSeparatorToken,
    TextToken, PossibleAddressToken,

    FunctionReturn, CallDestination, UnconditionalBranch,
    TrueBranch, FalseBranch, IndirectBranch, LowLevelILExpr, CallingConvention)


EM_SPU = 23


# extract bitfield occupying bits high..low from val (inclusive, start from 0)
def BITS(val, high, low):
    return (val >> low) & ((1 << (high - low + 1)) - 1)


# extract one bit
def BIT(val, bit):
    return (val >> bit) & 1


# sign extend b low bits in x
# from "Bit Twiddling Hacks"
def SIGNEXT(x, b):
    m = 1 << (b - 1)
    x &= (1 << b) - 1
    return (x ^ m) - m


# check if operand is register reg
# def is_reg(op, reg):
#     return op.type == o_reg and op.reg == reg


# check if operand is immediate value val
# def is_imm(op, val):
#     return op.type == o_imm and op.value == val


# is sp delta fixed by the user?
# def is_fixed_spd(ea):
#     return (get_aflags(ea) & AFL_FIXEDSPD) != 0


def IBITS(val, high, low):
    return BITS(val, 31 - high, 31 - low)


def decode_RR(opcode):
    # OP, B, A, T
    return IBITS(opcode, 0, 10), IBITS(opcode, 11, 17), IBITS(opcode, 18, 24), IBITS(opcode, 25, 31)


def decode_RRR(opcode):
    # OP, T, B, A, C
    return (
        IBITS(opcode, 0, 3), IBITS(opcode, 4, 10), IBITS(opcode, 11, 17),
        IBITS(opcode, 18, 24), IBITS(opcode, 25, 31)
    )


def decode_RI7(opcode):
    # OP I RA RT
    return IBITS(opcode, 0, 10), IBITS(opcode, 11, 17), IBITS(opcode, 18, 24), IBITS(opcode, 25, 31)


def decode_RI8(opcode):
    # OP I RA RT
    return IBITS(opcode, 0, 9), IBITS(opcode, 10, 17), IBITS(opcode, 18, 24), IBITS(opcode, 25, 31)


def decode_RI10(opcode):
    # OP I RA RT
    return IBITS(opcode, 0, 7), IBITS(opcode, 8, 17), IBITS(opcode, 18, 24), IBITS(opcode, 25, 31)


def decode_RI16(opcode):
    # OP I RT
    return IBITS(opcode, 0, 8), IBITS(opcode, 9, 24), IBITS(opcode, 25, 31)


def decode_RI18(opcode):
    # OP I RT
    return IBITS(opcode, 0, 6), IBITS(opcode, 7, 24), IBITS(opcode, 25, 31)


def decode_I16RO(opcode):
    # OP ROH I16 ROL
    return IBITS(opcode, 0, 6), IBITS(opcode, 7, 8), IBITS(opcode, 9, 24), IBITS(opcode, 25, 31)


def decode_STOP(opcode):
    # OP TYPE
    return IBITS(opcode, 0, 10), IBITS(opcode, 18, 31)


registers = (
    ('lr', 'sp') +
    tuple('r{}'.format(d) for d in xrange(2, 128)) +
    tuple('sp{}'.format(d) for d in xrange(2, 128)) +
    tuple('ch{}'.format(d) for d in xrange(2, 128))
)


instruction_il = {
    'ori': lambda il, addr, (_, imm, ra, rt): il.set_reg(
        16, rt,
        il.or_expr(16, il.reg(16, ra), il.const(16, imm))
    ),
    # TODO: Link part
    'brsl': lambda il, addr, (_, imm, rt): il.call(il.const(4, imm)),
    'br': lambda il, addr, (_, imm, rt): il.jump(il.const(4, imm << 2)),
    'lqd': lambda il, addr, (_, imm, ra, rt): il.set_reg(
        16, rt,
        il.load(16, il.add(16, il.reg(16, ra), il.const(16, imm << 4))),
    ),
    'lqx': lambda il, addr, (_, ra, rb, rt): il.set_reg(
        16, rt,
        il.load(16, il.add(16, il.reg(16, ra), il.reg(16, rb))),
    ),
    'stqd': lambda il, addr, (_, imm, ra, rt): il.store(
        8,
        il.add(16, il.reg(16, ra), il.const(16, imm*0x10)),
        il.reg(16, rt)
    ),
    'bi': lambda il, addr, (_, __, ___, rt): il.ret(il.reg(16, rt)),
    'ai': lambda il, addr, (_, imm, ra, rt): il.set_reg(
        16, rt,
        il.add(16, il.reg(16, ra), il.const(4, imm))
    ),
    'il': lambda il, addr, (_, imm, rt): il.set_reg(
        16, rt, il.sign_extend(4, il.const(2, imm))
    ),
    'ila': lambda il, addr, (_, imm, rt): il.set_reg(16, rt, il.const(16, imm)),
    'a': lambda il, addr, (_, rb, ra, rt): il.set_reg(
        4, rt,
        il.add(16, il.reg(16, ra), il.reg(16, rb))
    ),
    'wrch': lambda il, addr, (_, imm, ra, rt): il.set_reg(16, ra, il.reg(16, rt)),

    # 'shufb': lambda il, addr, decoded:,
    # 'cwd': lambda il, addr, decoded:,
    # '': lambda il, addr, decoded:
}


TwoImmediates = namedtuple('TwoImmediates', 'op_idx imm imm2')
ImmediateRegister = namedtuple('ImmediateRegister', 'op_idx imm, rt')
ImmediateTwoRegisters = namedtuple('ImmediateTwoRegisters', 'op_idx imm ra rt')
ThreeRegisters = namedtuple('ThreeRegisters', 'op_idx imm ra rt')
FourRegisters = namedtuple('FourRegisters', 'op_idx, rt, rb, ra, rc')


class SPU(Architecture):
    name = 'spu'
    address_size = 4
    default_int_size = 4
    max_instr_length = 4

    regs = dict((reg, RegisterInfo(reg, 16)) for reg in registers)

    stack_pointer = 'sp'

    flags = ('c', 'z', 'i', 'd', 'b', 'v', 's')
    flag_write_types = ('*', 'czs', 'zvs', 'zs')
    flag_roles = {
        'c': core.SpecialFlagRole,  # Not a normal carry flag, subtract result is inverted
        'z': core.ZeroFlagRole,
        'v': core.OverflowFlagRole,
        's': core.NegativeSignFlagRole
    }

    flags_required_for_flag_condition = {
        core.LLFC_UGE: ['c'],
        core.LLFC_ULT: ['c'],
        core.LLFC_E: ['z'],
        core.LLFC_NE: ['z'],
        core.LLFC_NEG: ['s'],
        core.LLFC_POS: ['s']
    }

    flags_written_by_flag_write_type = {
        '*': ['c', 'z', 'v', 's'],
        'czs': ['c', 'z', 's'],
        'zvs': ['z', 'v', 's'],
        'zs': ['z', 's']
    }

    _comma_separator = InstructionTextToken(OperandSeparatorToken, ', ')

    def __init__(self, *args, **kwargs):
        super(SPU, self).__init__(*args, **kwargs)
        self.init_instructions()

    def init_instructions(self):
        # Start idef classes
        class idef(object):
            def __init__(self, name):
                self.name = name

            def decode(self):
                raise NotImplementedError

            def get_text(self):
                raise NotImplementedError

        class idef_RR(idef):
            def decode(self, opcode, addr):
                op, rb, ra, rt = decode_RR(opcode)
                return ThreeRegisters(op, registers[rb], registers[ra], registers[rt])

            def get_text(self, opcode, addr):
                _, rb, ra, rt = self.decode(opcode, addr)
                return (
                    InstructionTextToken(TextToken, '{:10s}'.format(self.name)),
                    InstructionTextToken(RegisterToken, rt),
                    SPU._comma_separator,
                    InstructionTextToken(RegisterToken, ra),
                    SPU._comma_separator,
                    InstructionTextToken(RegisterToken, rb),
                )

        class idef_ROHROL(idef_RR):
            def decode(self, opcode, addr):
                op, roh, ra, rol = decode_RR(opcode)
                # prefetch = roh & 0x40 != 0

                roh &= 3
                val = roh << 7 | rol
                if val & 0x100:
                    val -= 0x200
                val = (val << 2) + addr

                # if prefetch:
                #    if p.cmd.Op2.reg == 0:
                #         p.cmd.Op2.type = o_void
                #         if val == 0:
                #             p.cmd.Op1.type = o_void

                rohrol_decoded = namedtuple('ROHROLDecoded', 'op_idx brinst brtarg')
                return rohrol_decoded(op, val, registers[ra])

            def get_text(self, opcode, addr):
                op, brinst, brtarg = self.decode(opcode, addr)

                return (
                    InstructionTextToken(TextToken, '{:10s}'.format(self.name)),
                    InstructionTextToken(PossibleAddressToken, '{:#x}'.format(brinst), brinst),
                    SPU._comma_separator,
                    InstructionTextToken(RegisterToken, brtarg),
                )

        class idef_R(idef_RR):
            def __init__(self, name, noRA=False):
                self.name = name
                self.noRA = noRA

            # def decode(self, opcode, addr):
            #     op, rb, ra, rt = decode_RR(opcode)
            #     return op, ra, rt

            def get_text(self, opcode, addr):
                _, _, ra, rt = self.decode(opcode, addr)

                tokens = [InstructionTextToken(TextToken, '{:10s}'.format(self.name))]
                if not self.noRA:
                    tokens.extend((
                        InstructionTextToken(RegisterToken, ra),
                        SPU._comma_separator
                    ))

                tokens.append(InstructionTextToken(RegisterToken, rt))
                return tokens

        class idef_SPR(idef):
            def __init__(self, name, swap=False, offset=128):
                self.name = name
                self.swap = swap
                self.offset = offset

            def decode(self, opcode, addr):
                op, iii, sa, rt = decode_RR(opcode)
                sa += self.offset
                if self.swap:
                    rt, sa = sa, rt

                return ImmediateTwoRegisters(op, iii, registers[sa], registers[rt])

            def get_text(self, opcode, addr):
                _, _, sa, rt = self.decode(opcode, addr)

                return (
                    InstructionTextToken(TextToken, '{:10s}'.format(self.name)),
                    InstructionTextToken(RegisterToken, rt),
                    SPU._comma_separator,
                    InstructionTextToken(RegisterToken, sa),
                )

        class idef_CH(idef_SPR):
            def __init__(self, name, swap=False):
                idef_SPR.__init__(self, name, swap, 256)

        class idef_noops(idef):
            def __init__(self, name, cbit=False):
                self.name = name
                self.cbit = cbit
                self.cf = 0

            # def decode(self, opcode, addr):
            #     op, iii1, iii2, iii3 = decode_RR(opcode)
            #     # if self.cbit and p.cmd.Op3.reg & 0x40 != 0:
            #     #     iii1 &= ~0x40
            #     return op

            def get_text(self, opcode, addr):
                # TODO: To add false targets or not to add.. that is the question
                return InstructionTextToken(TextToken, '{:10s}'.format(self.name)),

        class idef_RRR(idef):
            def decode(self, opcode, addr):
                op, rt, rb, ra, rc = decode_RRR(opcode)
                return FourRegisters(op, registers[rt], registers[rb],
                                     registers[ra], registers[rc])

            def get_text(self, opcode, addr):
                _, rt, rb, ra, rc = self.decode(opcode, addr)
                return (
                    InstructionTextToken(TextToken, '{:10s}'.format(self.name)),
                    InstructionTextToken(RegisterToken, rt),
                    SPU._comma_separator,
                    InstructionTextToken(RegisterToken, ra),
                    SPU._comma_separator,
                    InstructionTextToken(RegisterToken, rb),
                    SPU._comma_separator,
                    InstructionTextToken(RegisterToken, rc),
                )

        class idef_Branch(idef_RR):
            def __init__(self, name, no2=False, uncond=False):
                self.name = name
                self.no2 = no2

            def get_text(self, opcode, addr):
                _, rb, ra, rt = self.decode(opcode, addr)

                tokens = [InstructionTextToken(TextToken, '{:10s}'.format(self.name))]
                if not self.no2:
                    tokens.extend((
                        InstructionTextToken(RegisterToken, ra),
                        SPU._comma_separator,
                        InstructionTextToken(RegisterToken, rb)
                    ))

                tokens.append(InstructionTextToken(RegisterToken, rt))
                return tokens

        class idef_RI7(idef):
            def __init__(self, name, signed=True):
                self.name = name
                self.signed = signed

            def decode(self, opcode, addr):
                op, i7, ra, rt = decode_RI7(opcode)
                if self.signed and i7 & 0x40:
                    i7 -= 0x80
                return ImmediateTwoRegisters(op, i7, registers[ra], registers[rt])

            def get_text(self, opcode, addr):
                _, i7, ra, rt = self.decode(opcode, addr)
                return (
                    InstructionTextToken(TextToken, '{:10s}'.format(self.name)),
                    InstructionTextToken(RegisterToken, rt),
                    SPU._comma_separator,
                    InstructionTextToken(RegisterToken, ra),
                    SPU._comma_separator,
                    InstructionTextToken(IntegerToken, '{:#x}'.format(i7), i7),
                )

        class idef_RI8(idef):
            def __init__(self, name, bias):
                self.name = name
                self.bias = bias
                # self.cf = CF_CHG1 | CF_USE2 | CF_USE3

            def decode(self, opcode):
                # TODO: Finish this one
                op, i8, ra, rt = decode_RI8(opcode)
                i8 = self.bias - i8

                return ImmediateTwoRegisters(op, i8, registers[ra], registers[rt])

        class idef_RI7_ls(idef_RI7):
            pass
            # def decode(self, opcode, addr):
            #     # _, p.cmd.Op2.addr, p.cmd.Op2.reg, p.cmd.Op1.reg = decode_RI7(opcode)
            #     return decode_RI7(opcode)
            #     # p.cmd.Op1.type = o_reg
            #     # p.cmd.Op2.type = o_displ
            #     # p.cmd.Op2.dtyp = dt_byte16
            #     # if p.cmd.Op2.addr & 0x40:
            #     #     p.cmd.Op2.addr -= 0x80
            #     #     p.cmd.Op2.specval |= spu_processor_t.FL_SIGNED

        class idef_RI10(idef):
            def __init__(self, name, signed=True):
                self.name = name
                self.signed = signed

            def decode(self, opcode, addr):
                op, i10, ra, rt = decode_RI10(opcode)
                if self.signed:
                    if i10 & 0x200:
                        i10 -= 0x400
                return ImmediateTwoRegisters(op, i10, registers[ra], registers[rt])

            def get_text(self, opcode, addr):
                _, i10, ra, rt = self.decode(opcode, addr)

                name = self.name
                if i10 == 0 and name is 'ori':
                    name = 'lr'

                tokens = [
                    InstructionTextToken(TextToken, '{:10s}'.format(name)),
                    InstructionTextToken(RegisterToken, rt),
                    SPU._comma_separator,
                    InstructionTextToken(RegisterToken, ra)
                ]

                if name is not 'lr':
                    tokens.extend((
                        SPU._comma_separator,
                        InstructionTextToken(IntegerToken, '{:#x}'.format(i10), i10)
                    ))

                return tokens

        # TODO: ri10_ls
        class idef_RI10_ls(idef_RI10):
            pass
            # def decode(self, p, opcode):
            #     op, i10, ra, rt = decode_RI10(opcode)
            #     # p.cmd.Op1.type = o_reg
            #     # p.cmd.Op2.type = o_displ
            #     ra <<= 4
            #     # p.cmd.Op2.dtyp = dt_byte16
            #     if ra & 0x2000:
            #         ra -= 0x4000
            #     return op, i10, ra, rt

        class idef_RI16(idef):
            def __init__(self, name, flags=0, noRA=False, isBranch=True, signext=False):
                self.name = name
                self.noRA = noRA
                self.isBranch = isBranch
                self.signext = signext

            def decode(self, opcode, addr):
                op, i16, rt = decode_RI16(opcode)
                if self.signext and i16 & 0x8000:
                    i16 -= 0x10000
                # self.fixRA()
                return ImmediateRegister(op, i16, registers[rt])

            def get_text(self, opcode, addr):
                _, i16, rt = self.decode(opcode, addr)
                tokens = [InstructionTextToken(TextToken, '{:10s}'.format(self.name))]
                if not self.noRA:
                    tokens.extend((
                        InstructionTextToken(RegisterToken, rt),
                        SPU._comma_separator
                    ))
                tokens.append(InstructionTextToken(PossibleAddressToken, '{:#x}'.format(i16), i16))
                return tokens

        class idef_RI16_abs(idef_RI16):
            def decode(self, opcode, addr):
                op, i16, rt = idef_RI16.decode(self, opcode, addr)
                i16 <<= 2
                return ImmediateRegister(op, i16, rt)

        class idef_RI16_rel(idef_RI16_abs):
            def decode(self, opcode, addr):
                op, i16, rt = idef_RI16.decode(self, opcode, addr)
                i16 = (i16 << 2) + addr
                if i16 & 0x40000:
                    i16 &= ~0x40000
                return ImmediateRegister(op, i16, rt)

            def get_text(self, opcode, addr):
                _, i16, rt = self.decode(opcode, addr)

                tokens = [InstructionTextToken(TextToken, '{:10s}'.format(self.name))]
                if not self.noRA:
                    tokens.extend((
                        InstructionTextToken(RegisterToken, rt),
                        SPU._comma_separator
                    ))

                tokens.append(InstructionTextToken(PossibleAddressToken, '{:#x}'.format(i16), i16))
                return tokens

        class idef_RI18(idef):
            def decode(self, opcode, addr):
                op, i18, rt = decode_RI18(opcode)
                return ImmediateRegister(op, i18, registers[rt])

            def get_text(self, opcode, addr):
                _, i18, rt = self.decode(opcode, addr)
                return (
                    InstructionTextToken(TextToken, '{:10s}'.format(self.name)),
                    InstructionTextToken(RegisterToken, rt),
                    SPU._comma_separator,
                    InstructionTextToken(PossibleAddressToken, '{:#x}'.format(i18), i18),
                )

        class idef_I16RO(idef):
            def __init__(self, name, rel=False):
                self.name = name
                self.cf = 0
                self.rel = rel

            def decode(self, opcode, addr):
                op, roh, i16, rol = decode_I16RO(opcode)

                val = (roh << 7) | rol
                if val & 0x200:
                    val -= 0x400
                val = (val << 2) + addr

                if self.rel:
                    # i16 is signed relative offset
                    if i16 & 0x8000:
                        i16 -= 0x10000
                    i16 = addr + (i16 << 2)
                else:
                    i16 <<= 2

                return TwoImmediates(op, val, i16)

            def get_text(self, opcode, addr):
                _, brinst, brtarg = self.decode(opcode, addr)

                return (
                    InstructionTextToken(TextToken, '{:10s}'.format(self.name)),
                    InstructionTextToken(PossibleAddressToken, '{:#x}'.format(brinst), brinst),
                    SPU._comma_separator,
                    InstructionTextToken(PossibleAddressToken, '{:#x}'.format(brtarg), brtarg),
                )

        class idef_stop(idef):
            def decode(self, opcode, addr):
                op, t = decode_STOP(opcode)
                # p.cmd.Op1.type = o_imm
                # p.cmd.Op1.value = t
                return op, t

            def get_text(self, opcode, addr):
                _, t = self.decode(opcode, addr)
                return tuple()

        # End idef classes

        self.itable_RI10 = {
            0x04: idef_RI10('ori'),
            0x05: idef_RI10('orhi'),
            0x06: idef_RI10('orbi'),
            0x0c: idef_RI10('sfi'),
            0x0d: idef_RI10('sfhi'),
            0x14: idef_RI10('andi'),
            0x15: idef_RI10('andhi'),
            0x16: idef_RI10('andbi'),
            0x1c: idef_RI10('ai'),
            0x1d: idef_RI10('ahi'),
            0x24: idef_RI10_ls('stqd'),
            0x34: idef_RI10_ls('lqd'),
            0x44: idef_RI10('xori'),
            0x45: idef_RI10('xorhi'),
            0x46: idef_RI10('xorbi', signed=False),
            0x4c: idef_RI10('cgti'),
            0x4d: idef_RI10('cgthi'),
            0x4e: idef_RI10('cgtbi'),
            0x4f: idef_RI10('hgti'),  # false target
            0x5c: idef_RI10('clgti'),
            0x5d: idef_RI10('clgthi'),
            0x5e: idef_RI10('clgtbi'),
            0x5f: idef_RI10('hlgti'),  # false target
            0x74: idef_RI10('mpyi'),
            0x75: idef_RI10('mpyui'),
            0x7c: idef_RI10('ceqi'),
            0x7d: idef_RI10('ceqhi'),
            0x7e: idef_RI10('ceqbi'),
            0x7f: idef_RI10('heqi'),
        }

        # 11-bit opcodes (bits 0:10)
        self.itable_RR = {
            0x000: idef_stop('stop'),
            0x001: idef_noops('lnop'),  # no regs
            0x002: idef_noops('sync', cbit=True),  # C/#C
            0x003: idef_noops('dsync'),  # no regs
            0x00c: idef_SPR('mfspr'),  # SA = number
            0x00d: idef_CH('rdch'),  # //, CA, RT
            0x00f: idef_CH('rchcnt'),  # //, CA, RT
            0x040: idef_RR('sf'),
            0x041: idef_RR('or'),
            0x042: idef_RR('bg'),
            0x048: idef_RR('sfh'),
            0x049: idef_RR('nor'),
            0x053: idef_RR('absdb'),
            0x058: idef_RR('rot'),
            0x059: idef_RR('rotm'),
            0x05a: idef_RR('rotma'),
            0x05b: idef_RR('shl'),
            0x05c: idef_RR('roth'),
            0x05d: idef_RR('rothm'),
            0x05e: idef_RR('rotmah'),
            0x05f: idef_RR('shlh'),
            0x07f: idef_RR('shlhi'),
            0x0c0: idef_RR('a'),
            0x0c1: idef_RR('and'),
            0x0c2: idef_RR('cg'),
            0x0c8: idef_RR('ah'),
            0x0c9: idef_RR('nand'),
            0x0d3: idef_RR('avgb'),
            0x10c: idef_SPR('mtspr', swap=True),  # SA = number
            0x10d: idef_CH('wrch', swap=True),  # // CA RT
            0x128: idef_Branch('biz'),  # branch
            0x129: idef_Branch('binz'),  # branch
            0x12a: idef_Branch('bihz'),  # branch
            0x12b: idef_Branch('bihnz'),  # branch
            0x140: idef_RR('stopd'),
            0x144: idef_RR('stqx'),
            0x1a8: idef_Branch('bi', no2=True, uncond=True),  # branch
            0x1a9: idef_Branch('bisl'),  # branch
            0x1aa: idef_Branch('iret', no2=True, uncond=True),  # branch
            0x1ab: idef_Branch('bisled'),  # branch
            0x1ac: idef_ROHROL('hbr'),  # ROH/ROL form
            0x1b0: idef_R('gb'),  # no first reg
            0x1b1: idef_R('gbh'),  # no first reg
            0x1b2: idef_R('gbb'),  # no first reg
            0x1b4: idef_R('fsm'),  # no first reg
            0x1b5: idef_R('fsmh'),  # no first reg
            0x1b6: idef_R('fsmb'),  # no first reg
            0x1b8: idef_R('frest'),  # no first reg
            0x1b9: idef_R('frsqest'),  # no first reg
            0x1c4: idef_RR('lqx'),
            0x1cc: idef_RR('rotqbybi'),
            0x1cd: idef_RR('rotqmbybi'),
            0x1cf: idef_RR('shlqbybi'),
            0x1d4: idef_RR('cbx'),
            0x1d5: idef_RR('chx'),
            0x1d6: idef_RR('cwx'),
            0x1d7: idef_RR('cdx'),
            0x1d8: idef_RR('rotqbi'),
            0x1d9: idef_RR('rotqmbi'),
            0x1db: idef_RR('shlqbi'),
            0x1dc: idef_RR('rotqby'),
            0x1dd: idef_RR('rotqmby'),
            0x1df: idef_RR('shlqby'),
            0x1f0: idef_R('orx'),  # no first reg
            0x201: idef_noops('nop'),  # no regs
            0x240: idef_RR('cgt'),
            0x241: idef_RR('xor'),
            0x248: idef_RR('cgth'),
            0x249: idef_RR('eqv'),
            0x250: idef_RR('cgtb'),
            0x253: idef_RR('sumb'),
            0x258: idef_RR('hgt'),
            0x2a5: idef_R('clz'),  # no first reg
            0x2a6: idef_R('xswd'),  # no first reg
            0x2ae: idef_R('xshw'),  # no first
            0x2b4: idef_R('cntb'),  # no first reg
            0x2b6: idef_R('xsbh'),  # no first reg
            0x2c0: idef_RR('clgt'),
            0x2c1: idef_RR('andc'),
            0x2c2: idef_RR('fcgt'),
            0x2c3: idef_RR('dfcgt'),
            0x2c4: idef_RR('fa'),
            0x2c5: idef_RR('fs'),
            0x2c6: idef_RR('fm'),
            0x2c8: idef_RR('clgth'),
            0x2c9: idef_RR('orc'),
            0x2ca: idef_RR('fcmgt'),
            0x2cb: idef_RR('dfcmgt'),
            0x2cc: idef_RR('dfa'),
            0x2cd: idef_RR('dfs'),
            0x2ce: idef_RR('dfm'),
            0x2d0: idef_RR('clgtb'),
            0x2d8: idef_RR('hlgt'),  # false target
            0x340: idef_RR('addx'),
            0x341: idef_RR('sfx'),
            0x342: idef_RR('cgx'),
            0x343: idef_RR('bgx'),
            0x346: idef_RR('mpyhha'),
            0x34e: idef_RR('mpyhhau'),
            0x35c: idef_RR('dfma'),
            0x35d: idef_RR('dfms'),
            0x35e: idef_RR('dfnms'),
            0x35f: idef_RR('dfnma'),
            0x398: idef_R('fscrrd', noRA=True),  # no first and second
            0x3b8: idef_R('fesd'),  # no first
            0x3b9: idef_R('frds'),  # no first
            0x3ba: idef_R('fscrwr'),  # no first, rt is false target
            0x3c0: idef_RR('ceq'),
            0x3c2: idef_RR('fceq'),
            0x3c3: idef_RR('dfceq'),
            0x3c4: idef_RR('mpy'),
            0x3c5: idef_RR('mpyh'),
            0x3c7: idef_RR('mpys'),
            0x3c6: idef_RR('mpyhh'),
            0x3c8: idef_RR('ceqh'),
            0x3ca: idef_RR('fcmeq'),
            0x3cb: idef_RR('dfcmeq'),
            0x3cc: idef_RR('mpyu'),
            0x3ce: idef_RR('mpyhhu'),
            0x3d0: idef_RR('ceqb'),
            0x3d4: idef_RR('fi'),
            0x3d8: idef_RR('heq'),  # rt is false target
        }

        # 4-bit opcodes (bits 0:3)
        self.itable_RRR = {
            0x8: idef_RRR('selb'),
            0xb: idef_RRR('shufb'),
            0xc: idef_RRR('mpya'),
            0xd: idef_RRR('fnms'),
            0xe: idef_RRR('fma'),
            0xf: idef_RRR('fms'),
        }

        self.itable_RI16 = {
            0x040: idef_RI16_rel('brz'),
            0x041: idef_RI16_abs('stqa', isBranch=False),
            0x042: idef_RI16_rel('brnz'),
            0x044: idef_RI16_rel('brhz'),
            0x046: idef_RI16_rel('brhnz'),
            0x047: idef_RI16_rel('stqr', isBranch=False),
            0x060: idef_RI16_abs('bra', noRA=True),
            0x061: idef_RI16_abs('lqa', isBranch=False),
            0x062: idef_RI16_abs('brasl'),
            0x064: idef_RI16_rel('br', noRA=True),
            0x065: idef_RI16('fsmbi'),
            0x066: idef_RI16_rel('brsl'),
            0x067: idef_RI16_rel('lqr', isBranch=False),
            0x081: idef_RI16('il', signext=True),
            0x082: idef_RI16('ilhu'),
            0x083: idef_RI16('ilh'),
            0x0c1: idef_RI16('iohl'),
        }

        self.itable_RI7 = {
            0x078: idef_RI7('roti'),
            0x079: idef_RI7('rotmi'),
            0x07a: idef_RI7('rotmai'),
            0x07b: idef_RI7('shli'),
            0x07c: idef_RI7('rothi'),
            0x07d: idef_RI7('rothmi'),
            0x07e: idef_RI7('rotmahi'),
            0x1f4: idef_RI7_ls('cbd'),
            0x1f5: idef_RI7_ls('chd'),
            0x1f6: idef_RI7_ls('cwd'),
            0x1f7: idef_RI7_ls('cdd'),
            0x1f8: idef_RI7('rotqbii'),
            0x1f9: idef_RI7('rotqmbii'),
            0x1fb: idef_RI7('shlqbii'),
            0x1fc: idef_RI7('rotqbyi'),
            0x1fd: idef_RI7('rotqmbyi'),
            0x1ff: idef_RI7('shlqbyi'),
            0x3bf: idef_RI7('dftsv', signed=False),
        }

        self.itable_RI18 = {
            0x21: idef_RI18('ila'),
            0x08: idef_I16RO('hbra'),  # roh/rol
            0x09: idef_I16RO('hbrr', rel=True),  # roh/rol
        }

        # 10-bit opcodes (bits 0:9)
        self.itable_RI8 = {
            0x1d8: idef_RI8('cflts', 173),
            0x1d9: idef_RI8('cfltu', 173),
            0x1da: idef_RI8('csflt', 155),
            0x1db: idef_RI8('cuflt', 155),
        }

        self.itable = [None] * 2048
        for i in range(2048):
            opcode = i << 21
            RR = decode_RR(opcode)
            RRR = decode_RRR(opcode)
            RI7 = decode_RI7(opcode)
            RI8 = decode_RI8(opcode)
            RI10 = decode_RI10(opcode)
            RI16 = decode_RI16(opcode)
            RI18 = decode_RI18(opcode)

            ins = self.itable_RR.get(RR[0])
            ins = self.itable_RRR.get(RRR[0], ins)
            ins = self.itable_RI7.get(RI7[0], ins)
            ins = self.itable_RI8.get(RI8[0], ins)
            ins = self.itable_RI10.get(RI10[0], ins)
            ins = self.itable_RI16.get(RI16[0], ins)
            ins = self.itable_RI18.get(RI18[0], ins)

            if ins:
                self.itable[i] = ins

    def retrieve_instruction(self, data):
        try:
            opcode = struct.unpack('>I', data[:self.address_size])[0]
        except struct.error:
            return

        return self.itable[IBITS(opcode, 0, 10)], opcode

    def perform_get_instruction_info(self, data, addr):
        instruction, opcode = self.retrieve_instruction(data)
        if not instruction:
            return

        result = InstructionInfo()
        result.length = self.address_size

        inst_name = instruction.name
        if inst_name in ('bi', 'iret'):
            result.add_branch(FunctionReturn)
        elif inst_name in ('brsl', 'brasl'):
            _, branch_addr, _ = instruction.decode(opcode, addr)
            result.add_branch(CallDestination, branch_addr)
        elif inst_name == ('bisl', 'biz', 'binz', 'bihnz', 'bisled'):
            _, _, ra, _ = instruction.decode(opcode, addr)
            result.add_branch(IndirectBranch, ra)
        elif inst_name in ('brz', 'brnz', 'brhz', 'brhnz'):
            _, branch_addr, _ = instruction.decode(opcode, addr)
            result.add_branch(TrueBranch, branch_addr)
            result.add_branch(FalseBranch, addr + self.address_size)
        elif inst_name in ('br', 'bra'):
            _, branch_addr, _ = instruction.decode(opcode, addr)
            result.add_branch(UnconditionalBranch, branch_addr)

        return result

    def perform_get_instruction_text(self, data, addr):
        instruction, opcode = self.retrieve_instruction(data)
        if instruction is None:
            return

        return instruction.get_text(opcode, addr), self.address_size

    def perform_get_instruction_low_level_il(self, data, addr, il):
        instruction, opcode = self.retrieve_instruction(data)
        if instruction is None:
            return

        il_func = instruction_il.get(instruction.name, None)
        if il_func:
            decoded = instruction.decode(opcode, addr)
            lifted = il_func(il, addr, decoded)
            if isinstance(lifted, LowLevelILExpr):
                il.append(lifted)
            else:
                for llil in lifted:
                    il.append(llil)
        else:
            il.append(il.unimplemented())

        return self.address_size


class DefaultCallingConvention(CallingConvention):
    name = 'default'
    int_arg_regs = registers[3:75]
    int_return_reg = 'r3'
