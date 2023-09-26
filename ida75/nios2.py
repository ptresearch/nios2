# ----------------------------------------------------------------------
# Nios II Classic/Gen2 Processor  Module
# Copyright (c) 2018 Anton Dorfman, Positive Technologies
#
# IDA Pro 7.5+ fix and Python 3 Port by Blue DeviL // SCT
#

import sys
import idaapi
from idaapi import *

# For Version 7.5+
try:
    from ida_bytes import *
    from ida_ua import *
    from ida_idp import *
    from ida_auto import *
    from ida_nalt import *
    from ida_funcs import *
    from ida_lines import *
    from ida_problems import *
    from ida_offset import *
    from ida_segment import *
    from ida_name import *
    from ida_netnode import *
    from ida_xref import *
    from ida_idaapi import *
    import ida_frame
    import idc
except:
    print("[-] Cannot find new idapython libraries")

# ----------------------------------------------------------------------
# Auxiliary functions bits and sign manupilation
#


# Extract bitfield occupying bits high..low from val (inclusive, start from 0)
def BITS(val, high, low):
    return (val >> low) & ((1 << (high - low + 1)) - 1)


# Extract one bit
def BIT(val, bit):
    return (val >> bit) & 1


# Aign extend b low bits in x from "Bit Twiddling Hacks"
def SIGNEXT(x, b):
    m = 1 << (b - 1)
    x = x & ((1 << b) - 1)
    return (x ^ m) - m


# ----------------------------------------------------------------------
# IDP specific information
#

# Global pointer index
GP_IDX = 1

# General-purpose registers quantity
GenRegsNum = 32

# IDP specific operand types
o_ctlreg = idaapi.o_idpspec0  # Control registers
o_custreg = idaapi.o_idpspec1  # Custom registers


# ----------------------------------------------------------------------
# Common instruction formats decoding
#


def decode_format_I(InstructionCode):
    Opcode = BITS(InstructionCode, 5, 0)
    Imm16 = BITS(InstructionCode, 21, 6)
    OperandB = BITS(InstructionCode, 26, 22)
    OperandA = BITS(InstructionCode, 31, 27)
    return OperandB, OperandA, Imm16


def decode_format_R(InstructionCode):
    Opcode = BITS(InstructionCode, 5, 0)
    ExtendedOpcode = BITS(InstructionCode, 16, 10)
    Imm5 = BITS(InstructionCode, 10, 6)
    OperandC = BITS(InstructionCode, 21, 17)
    OperandB = BITS(InstructionCode, 26, 22)
    OperandA = BITS(InstructionCode, 31, 27)
    return OperandC, OperandA, OperandB, Imm5


def decode_format_J(InstructionCode):
    Opcode = BITS(InstructionCode, 5, 0)
    Imm26 = BITS(InstructionCode, 31, 6)
    return Imm26


def decode_instr_custom(InstructionCode):
    Opcode = BITS(InstructionCode, 5, 0)
    CmdN = BITS(InstructionCode, 13, 6)
    ReadRA = BIT(InstructionCode, 16)
    ReadRB = BIT(InstructionCode, 15)
    ReadRC = BIT(InstructionCode, 14)
    OperandC = BITS(InstructionCode, 21, 17)
    OperandB = BITS(InstructionCode, 26, 22)
    OperandA = BITS(InstructionCode, 31, 27)
    return OperandC, OperandA, OperandB, CmdN, ReadRA, ReadRB, ReadRC


# ----------------------------------------------------------------------
# NIOS II processor module class
#


class nios2_processor_t(idaapi.processor_t):
    # IDP id ( Numbers above 0x8000 are reserved for the third-party modules)
    id = 0x8000 + 555

    # Processor features
    flag = (
        PR_ASSEMBLE
        | PR_SEGS
        | PR_DEFSEG32
        | PR_USE32
        | PRN_HEX
        | PR_RNAMESOK
        | PR_NO_SEGMOVE
    )

    # Number of bits in a byte for code segments (usually 8)
    # IDA supports values up to 32 bits
    cnbits = 8

    # Number of bits in a byte for non-code segments (usually 8)
    # IDA supports values up to 32 bits
    dnbits = 8

    # short processor names
    # Each name should be shorter than 9 characters
    psnames = ["nios2"]

    # long processor names
    # No restriction on name lengthes.
    plnames = ["Altera Nios II Classic/Gen2 Processor"]

    # size of a segment register in bytes
    segreg_size = 0

    # icode of the first instruction
    instruc_start = 0

    #
    # Number of digits in floating numbers after the decimal point.
    # If an element of this array equals 0, then the corresponding
    # floating point data is not used for the processor.
    # This array is used to align numbers in the output.
    # 	real_width[0] - number of digits for short floats (only PDP-11 has them)
    # 	real_width[1] - number of digits for "float"
    # 	real_width[2] - number of digits for "double"
    # 	real_width[3] - number of digits for "long double"
    # Example: IBM PC module has { 0,7,15,19 }
    #
    # (optional)
    real_width = (0, 7, 15, 0)

    # only one assembler is supported
    assembler = {
        # flag
        "flag": ASH_HEXF3 | ASD_DECF0 | AS_UNEQU | AS_COLON | ASB_BINF0 | AS_N2CHR,
        # user defined flags (local only for IDP) (optional)
        "uflag": 0,
        # Assembler name (displayed in menus)
        "name": "Altera Nios II Classic/Gen2 Processor assembler",
        # array of automatically generated header lines they appear at the start of disassembled text (optional)
        "header": [".NIOS II"],
        # org directive
        "origin": ".org",
        # end directive
        "end": ".end",
        # comment string (see also cmnt2)
        "cmnt": "#",
        # ASCII string delimiter
        "ascsep": '"',
        # ASCII char constant delimiter
        "accsep": "'",
        # ASCII special chars (they can't appear in character and ascii constants)
        "esccodes": "\"'",
        #
        # 	Data representation (db,dw,...):
        #
        # ASCII string directive
        "a_ascii": ".ascii",
        # byte directive
        "a_byte": ".byte",
        # word directive
        "a_word": ".hword",
        # remove if not allowed
        "a_dword": ".word",
        # float; 4bytes; remove if not allowed
        "a_float": ".float",
        # double; 8bytes; NULL if not allowed
        "a_double": ".double",
        # array keyword. the following
        # sequences may appear:
        # 	#h - header
        # 	#d - size
        # 	#v - value
        # 	#s(b,w,l,q,f,d,o) - size specifiers
        # 						for byte,word,
        # 							dword,qword,
        # 							float,double,oword
        "a_dups": "#d dup(#v)",
        # uninitialized data directive (should include '%s' for the size of data)
        "a_bss": "%s dup ?",
        # 'equ' Used if AS_UNEQU is set (optional)
        "a_equ": ".equ",
        # 'seg ' prefix (example: push seg seg001)
        "a_seg": "seg",
        #
        # translation to use in character and string constants.
        # usually 1:1, i.e. trivial translation
        # If specified, must be 256 chars long
        # (optional)
        # 	'XlatAsciiOutput': "".join([chr(x) for x in xrange(256)]),
        # current IP (instruction pointer) symbol in assembler
        "a_curip": "$",
        # "public" name keyword. NULL-gen default, ""-do not generate
        "a_public": "public",
        # "weak"	name keyword. NULL-gen default, ""-do not generate
        "a_weak": ".weak",
        # "extrn" name keyword
        "a_extrn": "extrn",
        # "comm" (communal variable)
        "a_comdef": "",
        # "align" keyword
        "a_align": ".align",
        # Left and right braces used in complex expressions
        "lbrace": "(",
        "rbrace": ")",
        # % mod	assembler time operation
        "a_mod": "%",
        # & bit and assembler time operation
        "a_band": "&",
        # | bit or assembler time operation
        "a_bor": "|",
        # ^ bit xor assembler time operation
        "a_xor": "^",
        # ~ bit not assembler time operation
        "a_bnot": "~",
        # << shift left assembler time operation
        "a_shl": "<<",
        # >> shift right assembler time operation
        "a_shr": ">>",
        # size of type (format string) (optional)
        "a_sizeof_fmt": ".size %s",
        "flag2": 0,
        # comment close string (optional)
        # this is used to denote a string which closes comments, for example, if the comments are represented with (* ... *)
        # then cmnt = "(*" and cmnt2 = "*)"
        "cmnt2": "",
        # low8 operation, should contain %s for the operand (optional fields)
        "low8": "",
        "high8": "",
        "low16": "%lo",
        "high16": "%hi",
        # the include directive (format string) (optional)
        "a_include_fmt": ".include %s",
        # if a named item is a structure and displayed in the verbose (multiline) form then display the name
        # as printf(a_strucname_fmt, typename)
        # (for asms with type checking, e.g. tasm ideal)
        # (optional)
        "a_vstruc_fmt": "",
        # 3-byte data (optional)
        "a_3byte": "",
        # 'rva' keyword for image based offsets (optional)
        # (see nalt.hpp, REFINFO_RVA)
        "a_rva": "rva",
    }  # Assembler

    # ----------------------------------------------------------------------
    # Special flags used by the decoder, emulator and output
    #
    FL_SIGNED = 0x01  # value/address is signed; output as such
    FL_VAL32 = 0x02  # 32 bit value / offset from low and high parts
    FL_SUB = 0x04  # subtract offset from base

    # Global Pointer Node Definition
    GlobalPointerNode = None

    # Global Pointer Value
    GlobalPointer = BADADDR

    # ----------------------------------------------------------------------
    # The following callbacks are optional.
    # *** Please remove the callbacks that you don't plan to implement ***

    def notify_get_autocmt(self, insn):
        """
        Get instruction comment. 'insn' describes the instruction in question
        @return: None or the comment string
        """
        if "cmt" in self.instruc[insn.itype]:
            return self.instruc[insn.itype]["cmt"]

    def can_have_type(self, op):
        """
        Can the operand have a type as offset, segment, decimal, etc.
        (for example, a register AX can't have a type, meaning that the user can't
        change its representation. see bytes.hpp for information about types and flags)
        Returns: bool
        """
        return True

    # ----------------------------------------------------------------------
    # Global pointer manipulations, init, save, load
    #

    def notify_init(self, idp_file):
        self.GlobalPointerNode = idaapi.netnode("$ Global Pointer", 0, True)
        return 1

    def notify_oldfile(self, filename):
        """An old file is loaded (already)"""
        self.GlobalPointer = self.GlobalPointerNode.altval(GP_IDX)
        pass

    def notify_savebase(self):
        """The database is being saved. Processor module should save its local data"""
        self.GlobalPointerNode.altset(GP_IDX, self.GlobalPointer)
        pass

    # ----------------------------------------------------------------------
    # Output to screen functions
    #

    def notify_out_operand(self, ctx, op):
        """
        Generate text representation of an instructon operand.
        This function shouldn't change the database, flags or anything else.
        All these actions should be performed only by the emu() function.
        The output text is placed in the output buffer initialized with init_output_buffer()
        This function uses out_...() functions from ua.hpp to generate the operand text
        Returns: 1-ok, 0-operand is hidden.
        """
        optype = op.type
        SignedFlag = OOF_SIGNED if op.specflag1 & self.FL_SIGNED != 0 else 0
        if optype == o_reg:
            ctx.out_register(self.reg_names[op.reg])
            if (
                ctx.insn.itype == self.itype_jmp
                and get_switch_info(ctx.insn.ea) == None
            ):
                JumpOff = get_first_fcref_from(ctx.insn.ea)
                ctx.out_symbol(" ")
                ctx.out_symbol("#")
                ctx.out_symbol(" ")
                r = ctx.out_name_expr(op, JumpOff, BADADDR)
                if not r:
                    ctx.out_tagon(COLOR_ERROR)
                    ctx.out_btoa(op.addr, 16)
                    ctx.out_tagoff(COLOR_ERROR)
                    remember_problem(PR_NONAME, ctx.insn.ea)
        elif optype == o_imm:
            ctx.out_value(op, OOFW_IMM | OOFW_16 | SignedFlag)
            if op.specflag1 & self.FL_VAL32:
                if is_mapped(op.specval) == False:
                    ctx.out_symbol(" ")
                    ctx.out_symbol("#")
                    ctx.out_symbol(" ")
                    ctx.out_btoa(op.specval, 16)
        elif optype in [o_near, o_mem]:
            r = ctx.out_name_expr(op, op.addr, BADADDR)
            if not r:
                ctx.out_tagon(COLOR_ERROR)
                ctx.out_btoa(op.addr, 16)
                ctx.out_tagoff(COLOR_ERROR)
                remember_problem(PR_NONAME, ctx.insn.ea)
        elif optype == o_displ:
            ctx.out_value(op, OOF_ADDR | OOFW_16 | SignedFlag)
            ctx.out_symbol("(")
            ctx.out_register(self.reg_names[op.reg])
            ctx.out_symbol(")")
            if op.specflag1 & self.FL_VAL32:
                if is_mapped(op.specval) == False:
                    ctx.out_symbol(" ")
                    ctx.out_symbol("#")
                    ctx.out_symbol(" ")
                    ctx.out_btoa(op.specval, 16)
        elif optype == o_ctlreg:
            ctlregindex = op.reg + GenRegsNum
            ctx.out_register(self.reg_names[ctlregindex])
        elif optype == o_custreg:
            customregname = "c" + str(op.reg)
            ctx.out_register(customregname)
        return True

    def out_mnem(self, ctx):
        postfix = ""
        if ctx.insn.itype == self.itype_custom:
            postfix = " " + str(ctx.insn.Op1.specval)
        ctx.out_mnem(12, postfix)

    def notify_out_insn(self, ctx):
        """
                Generate text representation of an instruction in 'ctx.insn' structure.
        This function shouldn't change the database, flags or anything else.
        All these actions should be performed only by emu() function.
        Returns: nothing
        """
        ctx.out_mnemonic()
        if ctx.insn.Op1.type != o_void:
            ctx.out_one_operand(0)
        for i in range(1, 4):
            if ctx.insn[i].type == o_void:
                break
            ctx.out_symbol(",")
            ctx.out_char(" ")
            ctx.out_one_operand(i)
        ctx.set_gen_cmt()  # generate comment at the next call to MakeLine()
        ctx.flush_outbuf()

    # ----------------------------------------------------------------------
    # Stack variable and pointer manipulations
    #

    def add_stkvar(self, insn, op, OpOff, flag):
        pfn = get_func(insn.ea)
        if pfn and insn.create_stkvar(op, OpOff, flag):
            op_stkvar(insn.ea, op.n)

    def add_stkpnt(self, insn, pfn, spofs):
        end = insn.ea + insn.size
        if not is_fixed_spd(end):
            ida_frame.add_auto_stkpnt(pfn, end, spofs)

    def check_stkvar_off(self, insn):
        if (
            insn.Op1.is_reg(self.ireg_sp) == False
            and insn.Op2.is_reg(self.ireg_sp)
            and insn.Op3.type == o_imm
        ):
            if insn.itype == self.itype_addi and may_create_stkvars():
                # addi rx, sp, yy
                self.add_stkvar(insn, insn.Op3, insn.Op3.value, 0)

    def trace_sp(self, insn):
        """
        Trace the value of the SP and create an SP change point if the current
        instruction modifies the SP.
        """
        pfn = get_func(insn.ea)
        if not pfn:
            return

        if (
            insn.Op1.is_reg(self.ireg_sp)
            and insn.Op2.is_reg(self.ireg_sp)
            and insn.Op3.type == o_imm
        ):
            if insn.itype == self.itype_addi:
                spofs = insn.Op3.value
            elif insn.itype == self.itype_subi:
                spofs = -insn.Op3.value
            else:
                return
            self.add_stkpnt(insn, pfn, spofs)

    # ----------------------------------------------------------------------
    # Detect jump to address in register and make code xrefs
    #

    def is_op_reg(self, op, reg):
        if reg != None and op.type == o_reg and op.reg == reg:
            return True
        return False

    def check_jmp_reg(self, insn):
        if get_switch_info(insn.ea):
            return
        # SavedCmd = insn.copy()
        JmpRegOk = False
        if insn.itype == self.itype_jmp:
            JumpAddrRegLow = insn.Op1.reg
            CurFunc = idaapi.get_func(insn.ea)
            CurCmdCnt = 0
            if CurFunc:
                CurFuncStart = CurFunc.start_ea
                MAX_SEARCH_CMD_RANGE = 32
            else:
                CurFuncStart = 0
                MAX_SEARCH_CMD_RANGE = 16
            NumOfCases = 0
            # Init State Variables
            JumpAddrRegHigh = None
            JumpOffLow = None
            JumpOffHigh = None
            JumpAddr = None
            JmpRegOk = False
            prev = insn_t()
            decode_insn(prev, insn.ea)
            while (
                prev.ea > CurFuncStart
                and decode_preceding_insn(prev, prev.ea) != BADADDR
                and CurCmdCnt < MAX_SEARCH_CMD_RANGE
            ):
                if (
                    (
                        prev.itype == self.itype_addi
                        or prev.itype == self.itype_subi
                        or prev.itype == self.itype_ori
                    )
                    and self.is_op_reg(prev.Op1, JumpAddrRegLow)
                    and JumpAddrRegHigh == None
                ):
                    JumpAddrRegHigh = prev.Op2.reg
                    if prev.itype == self.itype_subi:
                        SubiFlag = 1
                    else:
                        SubiFlag = 0
                    JumpOffLow = prev.Op3.value & 0xFFFFFFFF
                elif (
                    prev.itype == self.itype_movhi
                    and self.is_op_reg(prev.Op1, JumpAddrRegHigh)
                    and JumpOffHigh == None
                ):
                    JumpOffHigh = prev.Op2.value & 0xFFFFFFFF
                    if SubiFlag:
                        JumpAddr = (JumpOffHigh << 16) - JumpOffLow
                    else:
                        JumpAddr = (JumpOffHigh << 16) + JumpOffLow
                if JumpAddr != None:
                    CurFuncStart = prev.ea
                    JmpRegOk = True
                CurCmdCnt += 1
        # insn.assign(SavedCmd)
        if JmpRegOk:
            insn.add_cref(JumpAddr, 0, fl_JN)
        return JmpRegOk

    # ----------------------------------------------------------------------
    # Detect switches and set switch info
    #

    def check_switch(self, insn):
        # 		mov		MaxCaseNumReg,NumOfCases -or- cmpgeui MaxCaseNumReg, CurCaseReg, NumOfCases
        # 		bltu 	MaxCaseNumReg,CurCaseReg,DefCase -or- bne	 MaxCaseNumReg, zero, DefCase -or-  bgeu		MaxCaseNumReg, CurCaseReg, NotDefCase
        # 		slli 	TempCaseReg,CurCaseReg,2
        # 		movhi   JTableAddrRegHigh, 2
        # 		addi	JTableAddrRegLow, JTableAddrRegHigh, 0x6EB8 -or-  subi	JTableAddrRegLow, JTableAddrRegHigh, 0x6EB8
        # 		add	 JumpOffReg, TempCaseReg, JTableAddrRegLow
        # 		ldw	 RegJump, 0(JumpOffReg)
        # 		jmp	 RegJump

        if get_switch_info(insn.ea):
            return
        si = switch_info_t()
        # SavedCmd = insn.copy()
        SwitchOk = False
        if insn.itype == self.itype_jmp:
            RegJump = insn.Op1.reg
            CurFunc = idaapi.get_func(insn.ea)
            CurCmdCnt = 0
            if CurFunc:
                CurFuncStart = CurFunc.start_ea
                MAX_SEARCH_CMD_RANGE = 128
            else:
                CurFuncStart = 0
                MAX_SEARCH_CMD_RANGE = 64
            NumOfCases = 0
            # Init State Variables
            JumpOffReg = None
            JTableAddrRegLow = None
            JTableAddrRegHigh = None
            JTableOffLow = None
            JTableOffHigh = None
            JTableAddr = None
            TempCaseReg = None
            MaxCaseNumReg = None
            RegToCheck = None
            CurCaseReg = None
            SwitchOk = False
            NoNeedToCheck = True
            prev = insn_t()
            decode_insn(prev, insn.ea)
            while (
                prev.ea > CurFuncStart
                and decode_preceding_insn(prev, prev.ea) != BADADDR
                and CurCmdCnt < MAX_SEARCH_CMD_RANGE
            ):
                if (
                    prev.itype == self.itype_ldw
                    and self.is_op_reg(prev.Op1, RegJump)
                    and prev.Op2.addr == 0
                    and JumpOffReg == None
                ):
                    JumpOffReg = prev.Op2.reg
                elif (
                    prev.itype == self.itype_add
                    and self.is_op_reg(prev.Op1, JumpOffReg)
                    and JTableAddrRegLow == None
                ):
                    TempCaseReg = prev.Op2.reg
                    JTableAddrRegLow = prev.Op3.reg
                elif (
                    (
                        prev.itype == self.itype_addi
                        or prev.itype == self.itype_subi
                        or prev.itype == self.itype_ori
                    )
                    and self.is_op_reg(prev.Op1, JTableAddrRegLow)
                    and JTableAddrRegHigh == None
                ):
                    JTableAddrRegHigh = prev.Op2.reg
                    if prev.itype == self.itype_subi:
                        SubiFlag = 1
                    else:
                        SubiFlag = 0
                    JTableOffLow = prev.Op3.value & 0xFFFFFFFF
                elif (
                    prev.itype == self.itype_movhi
                    and self.is_op_reg(prev.Op1, JTableAddrRegHigh)
                    and JTableOffHigh == None
                ):
                    JTableOffHigh = prev.Op2.value & 0xFFFFFFFF
                    if SubiFlag:
                        JTableAddr = (JTableOffHigh << 16) - JTableOffLow
                    else:
                        JTableAddr = (JTableOffHigh << 16) + JTableOffLow
                elif (
                    (
                        prev.itype == self.itype_slli
                        or prev.itype == self.itype_sll
                        or prev.itype == self.itype_mul
                    )
                    and self.is_op_reg(prev.Op1, TempCaseReg)
                    and CurCaseReg == None
                ):
                    CurCaseReg = prev.Op2.reg
                elif (
                    prev.itype == self.itype_bltu
                    and self.is_op_reg(prev.Op2, CurCaseReg)
                ) and MaxCaseNumReg == None:
                    DefJump = prev.Op3.addr
                    MaxCaseNumReg = prev.Op1.reg
                elif (
                    prev.itype == self.itype_bne
                    and prev.Op2.is_reg(0)
                    and MaxCaseNumReg == None
                ):
                    DefJump = prev.Op3.addr
                    MaxCaseNumReg = prev.Op1.reg
                elif (
                    prev.itype == self.itype_bgeu
                    and self.is_op_reg(prev.Op2, CurCaseReg)
                    and MaxCaseNumReg == None
                ):
                    DefJump = next_head(prev.ea, BADADDR)
                    MaxCaseNumReg = prev.Op1.reg
                elif (
                    prev.itype == self.itype_movi
                    and self.is_op_reg(prev.Op1, MaxCaseNumReg)
                    and NumOfCases == 0
                ):
                    NumOfCases = cmd.Op2.value + 1
                    NoNeedToCheck = True
                elif (
                    prev.itype == self.itype_cmpgeui
                    and self.is_op_reg(prev.Op1, MaxCaseNumReg)
                    and NumOfCases == 0
                ):
                    if self.is_op_reg(prev.Op2, CurCaseReg):
                        NoNeedToCheck = True
                    else:
                        NoNeedToCheck = False
                        RegToCheck = prev.Op2.reg
                    NumOfCases = cmd.Op3.value
                elif prev.itype == self.itype_mov and (
                    (
                        self.is_op_reg(prev.Op1, CurCaseReg)
                        and self.is_op_reg(prev.Op2, RegToCheck)
                    )
                    or (
                        self.is_op_reg(prev.Op1, RegToCheck)
                        and self.is_op_reg(prev.Op2, CurCaseReg)
                    )
                ):
                    NoNeedToCheck = True
                if (
                    NumOfCases != 0
                    and JTableAddr != None
                    and DefJump != None
                    and NoNeedToCheck
                ):
                    CurFuncStart = prev.ea
                    SwitchOk = True
                CurCmdCnt += 1
            if SwitchOk:
                si.defjump = DefJump
                si.ncases = NumOfCases
                si.flags |= SWI_DEFAULT | SWI_EXTENDED | SWI_J32
                si.lowcase = 0
                si.startea = prev.ea
                si.set_expr(RegJump, dt_dword)
        # insn.assign(SavedCmd)
        if SwitchOk:
            si.jumps = JTableAddr
            op_plain_offset(insn.ea, 0, insn.cs)
            set_switch_info(insn.ea, si)
            create_switch_table(insn.ea, si)
        return

    # ----------------------------------------------------------------------
    # Operand handling
    #

    def handle_operand(self, insn, op, isRead):
        uFlag = get_flags(insn.ea)
        is_offs = is_off(uFlag, op.n)
        is_stroffs = is_stroff(uFlag, op.n)
        dref_flag = dr_R if isRead else dr_W
        def_arg = is_defarg(uFlag, op.n)
        optype = op.type
        if optype == o_imm:
            if is_offs:
                insn.add_off_drefs(op, dr_O, 0)
            if op.specflag1 & self.FL_VAL32:
                if is_mapped(op.specval):
                    ri = idaapi.refinfo_t()
                    init_flags = REF_OFF32 | REFINFO_NOBASE
                    if op.specflag1 & self.FL_SUB:
                        init_flags = init_flags | REFINFO_SUBTRACT
                        OffBase = op.specval + op.value
                    else:
                        OffBase = op.specval - op.value
                    ri.init(init_flags, OffBase)
                    idaapi.op_offset_ex(insn.ea, op.n, ri)
        elif optype == o_displ:
            if is_offs:
                OffAddr = op.specval
                if OffAddr == 0:
                    ri = idaapi.refinfo_t()
                    Status = idaapi.get_refinfo(insn.ea, op.n, ri)
                    OffAddr = ri.base + op.addr
                insn.create_op_data(OffAddr, op)
                insn.add_dref(OffAddr, op.offb, dref_flag)
            elif is_stroffs:
                insn.add_off_drefs(op, dref_flag, OOF_ADDR)
            if op.specflag1 & self.FL_VAL32:
                if is_mapped(op.specval):
                    ri = idaapi.refinfo_t()
                    init_flags = REF_OFF32 | REFINFO_NOBASE
                    if op.specflag1 & self.FL_SIGNED:
                        OffBase = op.specval + (0xFFFF & (-op.addr))
                    else:
                        OffBase = op.specval - op.addr
                    ri.init(init_flags, OffBase)
                    idaapi.op_offset_ex(insn.ea, op.n, ri)
            elif may_create_stkvars() and not def_arg and op.reg == self.ireg_sp:
                self.add_stkvar(insn, op, op.addr, STKVAR_VALID_SIZE)
        elif optype == o_near:
            if insn.get_canon_feature() & CF_CALL:
                XrefType = fl_CN
            else:
                XrefType = fl_JN
            insn.add_cref(op.addr, op.offb, XrefType)

    # ----------------------------------------------------------------------
    # Instruction emulator
    #

    def notify_emu(self, insn):
        """
        Emulate instruction, create cross-references, plan to analyze
        subsequent instructions, modify flags etc. Upon entrance to this function
        all information about the instruction is in 'cmd' structure.
        If zero is returned, the kernel will delete the instruction.
        """
        Feature = insn.get_canon_feature()
        if Feature & CF_USE1:
            self.handle_operand(insn, insn.Op1, 1)
        if Feature & CF_CHG1:
            self.handle_operand(insn, insn.Op1, 0)
        if Feature & CF_USE2:
            self.handle_operand(insn, insn.Op2, 1)
        if Feature & CF_CHG2:
            self.handle_operand(insn, insn.Op2, 0)
        if Feature & CF_USE3:
            self.handle_operand(insn, insn.Op3, 1)
        if Feature & CF_CHG3:
            self.handle_operand(insn, insn.Op3, 0)
        if Feature & CF_USE4:
            self.handle_operand(insn, insn.Op4, 1)
        if Feature & CF_CHG4:
            self.handle_operand(insn, insn.Op4, 0)
        if Feature & CF_JUMP:
            remember_problem(PR_JUMP, insn.ea)
        IsUncondJmp = insn.itype in [self.itype_br, self.itype_jmp, self.itype_jmpi]
        IsFlow = (Feature & CF_STOP == 0) and not IsUncondJmp
        if IsFlow:
            add_cref(insn.ea, insn.ea + insn.size, fl_F)
        else:
            IsJmpReg = self.check_jmp_reg(insn)
            if IsJmpReg == False:
                self.check_switch(insn)
        if may_trace_sp():
            if IsFlow:
                self.trace_sp(insn)
            else:
                recalc_spd(insn.ea)
        self.check_stkvar_off(insn)
        return 1

    # ----------------------------------------------------------------------
    # Check for offsets with high and low parts
    #

    def check_off32(self, insn):
        OffBase = None
        if insn.itype in [self.itype_addi, self.itype_subi, self.itype_ori]:
            if insn.Op2.type == o_reg and insn.Op3.type == o_imm:
                OffReg = insn.Op2.reg
                # SavedCmd = insn.copy()
                prev = insn_t()
                if decode_prev_insn(prev, insn.ea) != BADADDR:
                    if prev.itype == self.itype_movhi:
                        if (
                            prev.Op1.type == o_reg
                            and prev.Op1.is_reg(OffReg)
                            and prev.Op2.type == o_imm
                        ):
                            OffBase = (prev.Op2.value & 0xFFFFFFFF) << 16
                # insn.assign(SavedCmd)
                if (
                    OffReg == self.ireg_gp
                    and OffBase == None
                    and self.GlobalPointer != BADADDR
                ):
                    OffBase = self.GlobalPointer
                if OffBase != None:
                    OffValue = insn.Op3.value
                    if insn.itype == self.itype_subi:
                        OffAddr = OffBase - OffValue
                        insn.Op3.specflag1 |= self.FL_SUB
                    else:
                        OffAddr = OffBase + OffValue
                    insn.Op3.specflag1 |= self.FL_VAL32
                    insn.Op3.specval = OffAddr
                    if insn.Op1.is_reg(self.ireg_gp):
                        if self.GlobalPointer == BADADDR:
                            self.GlobalPointer = insn.Op3.specval
                        else:
                            GlobalPointerTemp = insn.Op3.specval
                            if GlobalPointerTemp != self.GlobalPointer:
                                self.GlobalPointer = GlobalPointerTemp
        else:
            if insn.Op2.type == o_displ:
                OffReg = insn.Op2.phrase
                # SavedCmd = insn.copy()
                prev = insn_t()
                if decode_prev_insn(prev, insn.ea) != BADADDR:
                    if prev.itype == self.itype_movhi:
                        if (
                            prev.Op1.type == o_reg
                            and prev.Op1.is_reg(OffReg)
                            and prev.Op2.type == o_imm
                        ):
                            OffBase = (prev.Op2.value & 0xFFFFFFFF) << 16
                # insn.assign(SavedCmd)
                if (
                    OffReg == self.ireg_gp
                    and OffBase == None
                    and self.GlobalPointer != BADADDR
                ):
                    OffBase = self.GlobalPointer
                if OffBase != None:
                    OffValue = insn.Op2.addr
                    if insn.Op2.specflag1 & self.FL_SIGNED:
                        OffValue = 0xFFFF & (-OffValue)
                        OffAddr = OffBase - OffValue
                    else:
                        OffAddr = OffBase + OffValue
                    insn.Op2.specflag1 |= self.FL_VAL32
                    insn.Op2.specval = OffAddr
        return

    # ----------------------------------------------------------------------
    # Replace some instructions by simplified mnemonics - pseudo instructions
    #

    def simplify(self, insn):
        if insn.Op2.type == o_reg and insn.Op2.reg == 0:
            if insn.itype == self.itype_addi:
                insn.itype = self.itype_movi
                insn.Op2.assign(insn.Op3)
                insn.Op3.type = o_void
            elif insn.itype == self.itype_orhi:
                insn.itype = self.itype_movhi
                insn.Op2.assign(insn.Op3)
                insn.Op3.type = o_void
            elif insn.itype == self.itype_ori:
                insn.itype = self.itype_movui
                insn.Op2.assign(insn.Op3)
                insn.Op3.type = o_void
            elif insn.itype == self.itype_add:
                if insn.Op3.reg == insn.Op1.reg and insn.Op1.reg == 0:
                    insn.itype = self.itype_nop
                    insn.Op1.type = insn.Op2.type = insn.Op3.type = o_void
        if insn.Op3.type == o_reg and insn.Op3.reg == 0:
            if insn.itype == self.itype_add:
                insn.itype = self.itype_mov
                insn.Op3.type = o_void
        if insn.itype == self.itype_addi:
            if insn.Op3.specflag1 & self.FL_SIGNED:
                insn.itype = self.itype_subi
                insn.Op3.value = 0xFFFF & (-insn.Op3.value)
                insn.Op3.specflag1 &= ~self.FL_SIGNED
        # Check custom cmd
        if insn.itype == self.itype_custom:
            CmdNumber = insn.Op1.specval
            if self.itable_custom.get(CmdNumber) != None:
                CurInstruction = self.itable_custom[CmdNumber]
                insn.itype = getattr(self, "itype_" + CurInstruction.name)

    # ----------------------------------------------------------------------
    # Instruction decoder
    #

    def notify_ana(self, insn):
        """
        Decodes an instruction into insn.
        Returns: insn.size (=the size of the decoded instruction) or zero
        """
        # Check for alignment
        if (insn.ea & 0x3) != 0:
            return 0
        InstructionCode = insn.get_next_dword()
        CurInstruction = None
        if BITS(InstructionCode, 5, 0) == 0x3A:
            if self.itable_R_Type.get(BITS(InstructionCode, 16, 11)) != None:
                CurInstruction = self.itable_R_Type[BITS(InstructionCode, 16, 11)]
        else:
            if self.itable_I_Type.get(BITS(InstructionCode, 5, 0)) != None:
                CurInstruction = self.itable_I_Type[BITS(InstructionCode, 5, 0)]
        if CurInstruction is None:
            return 0
        insn.itype = getattr(self, "itype_" + CurInstruction.name)
        for c in insn:
            c.type = o_void
        CurInstruction.decode(insn, InstructionCode)
        self.simplify(insn)
        if insn.size != 0:
            self.check_off32(insn)
        return insn.size

    # ----------------------------------------------------------------------
    # Classes for instruction decoding
    #

    def init_instructions(self):
        class idef:
            pass

        # I-Type instructions
        class idef_I_type(idef):
            def __init__(self, name, comment):
                self.name = name
                self.cf = CF_CHG1 | CF_USE2 | CF_USE3
                self.comment = comment

            def decode(self, insn, opcode):
                OperandB, OperandA, Imm16 = decode_format_I(opcode)
                insn.Op1.reg = OperandB
                insn.Op2.reg = OperandA
                insn.Op3.value = Imm16
                insn.Op1.type = insn.Op2.type = o_reg
                insn.Op3.type = o_imm
                insn.Op1.dtyp = insn.Op2.dtyp = dt_dword
                insn.Op3.dtyp = dt_word

        class idef_I_type_sign(idef_I_type):
            def decode(self, insn, opcode):
                idef_I_type.decode(self, insn, opcode)
                if insn.Op3.value & 0x8000:
                    insn.Op3.specflag1 |= nios2_processor_t.FL_SIGNED

        class idef_I_type_load(idef):
            def __init__(self, name, comment, datatype):
                self.name = name
                self.cf = CF_CHG1 | CF_USE2
                self.comment = comment
                self.datatype = datatype

            def decode(self, insn, opcode):
                OperandB, OperandA, Imm16 = decode_format_I(opcode)
                insn.Op1.reg = OperandB
                insn.Op2.phrase = OperandA
                insn.Op2.addr = Imm16
                insn.Op1.type = o_reg
                insn.Op2.type = o_displ
                insn.Op1.dtyp = dt_dword
                insn.Op2.dtyp = self.datatype
                if Imm16 & 0x8000:
                    insn.Op2.specflag1 |= nios2_processor_t.FL_SIGNED

        class idef_I_type_store(idef_I_type_load):
            def __init__(self, name, comment, datatype):
                idef_I_type_load.__init__(self, name, comment, datatype)
                self.cf = CF_USE1 | CF_CHG2

        class idef_I_type_cache(idef):
            def __init__(self, name, comment):
                self.name = name
                self.cf = CF_USE1
                self.comment = comment

            def decode(self, insn, opcode):
                OperandB, OperandA, Imm16 = decode_format_I(opcode)
                insn.Op1.phrase = OperandA
                insn.Op1.addr = Imm16
                insn.Op1.type = o_displ
                insn.Op1.dtyp = dt_word
                if Imm16 & 0x8000:
                    insn.Op1.specflag1 |= nios2_processor_t.FL_SIGNED
                if OperandB != 0:
                    insn.size = 0

        class idef_I_type_condjump(idef):
            def __init__(self, name, comment):
                self.name = name
                self.cf = CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP
                self.comment = comment

            def decode(self, insn, opcode):
                OperandB, OperandA, Imm16 = decode_format_I(opcode)
                insn.Op1.reg = OperandA
                insn.Op2.reg = OperandB
                insn.Op3.addr = insn.ea + 4 + SIGNEXT(Imm16, 16)
                insn.Op1.type = insn.Op2.type = o_reg
                insn.Op3.type = o_near
                insn.Op1.dtyp = insn.Op2.dtyp = dt_dword
                insn.Op3.dtyp = dt_code

        class idef_I_type_br(idef):
            def __init__(self, name, comment):
                self.name = name
                self.cf = CF_USE1 | CF_JUMP | CF_STOP
                self.comment = comment

            def decode(self, insn, opcode):
                OperandB, OperandA, Imm16 = decode_format_I(opcode)
                insn.Op1.addr = insn.ea + 4 + SIGNEXT(Imm16, 16)
                insn.Op1.type = o_near
                insn.Op1.dtyp = dt_code
                if OperandB != 0 or OperandA != 0:
                    insn.size = 0

        # R-Type instructions
        class idef_R_type(idef):
            def __init__(self, name, comment):
                self.name = name
                self.cf = CF_CHG1 | CF_USE2 | CF_USE3
                self.comment = comment

            def decode(self, insn, opcode):
                OperandC, OperandA, OperandB, Imm5 = decode_format_R(opcode)
                insn.Op1.reg = OperandC
                insn.Op2.reg = OperandA
                insn.Op3.reg = OperandB
                insn.Op1.type = insn.Op2.type = insn.Op3.type = o_reg
                insn.Op1.dtyp = insn.Op2.dtyp = insn.Op3.dtyp = dt_dword
                if Imm5 != 0:
                    insn.size = 0

        class idef_R_type_shift(idef_R_type):
            def __init__(self, name, comment):
                idef_R_type.__init__(self, name, comment)
                self.cf |= CF_SHFT

        class idef_R_type_shift_imm(idef_R_type_shift):
            def decode(self, insn, opcode):
                OperandC, OperandA, OperandB, Imm5 = decode_format_R(opcode)
                insn.Op1.reg = OperandC
                insn.Op2.reg = OperandA
                insn.Op3.value = Imm5
                insn.Op1.type = insn.Op2.type = o_reg
                insn.Op3.type = o_imm
                insn.Op1.dtyp = insn.Op2.dtyp = dt_dword
                insn.Op3.dtyp = dt_byte
                if OperandB != 0:
                    insn.size = 0

        class idef_R_type_wrprs(idef):
            def __init__(self, name, comment):
                self.name = name
                self.cf = CF_CHG1 | CF_USE2
                self.comment = comment

            def decode(self, insn, opcode):
                OperandC, OperandA, OperandB, Imm5 = decode_format_R(opcode)
                insn.Op1.reg = OperandC
                insn.Op2.reg = OperandA
                insn.Op1.type = insn.Op2.type = o_reg
                insn.Op1.dtyp = insn.Op2.dtyp = dt_dword
                if OperandB != 0 or Imm5 != 0:
                    insn.size = 0

        class idef_R_type_rdctl(idef_R_type_wrprs):
            def decode(self, insn, opcode):
                OperandC, OperandA, OperandB, Imm5 = decode_format_R(opcode)
                insn.Op1.reg = OperandC
                insn.Op2.reg = Imm5
                insn.Op1.type = o_reg
                insn.Op2.type = o_ctlreg
                insn.Op1.dtyp = insn.Op2.dtyp = dt_dword
                if OperandA != 0 or OperandB != 0:
                    insn.size = 0

        class idef_R_type_wrctl(idef_R_type_wrprs):
            def decode(self, insn, opcode):
                OperandC, OperandA, OperandB, Imm5 = decode_format_R(opcode)
                insn.Op1.reg = Imm5
                insn.Op2.reg = OperandA
                insn.Op1.type = o_ctlreg
                insn.Op2.type = o_reg
                insn.Op1.dtyp = insn.Op2.dtyp = dt_dword
                if OperandB != 0 or OperandC != 0:
                    insn.size = 0

        class idef_R_type_stub(idef):
            def __init__(self, name, comment):
                self.name = name
                self.cf = 0
                self.comment = comment

            def decode(self, insn, opcode):
                OperandC, OperandA, OperandB, Imm5 = decode_format_R(opcode)
                if OperandA != 0 or OperandB != 0 or OperandC != 0 or Imm5 != 0:
                    insn.size = 0

        class idef_R_type_trap(idef):
            def __init__(self, name, comment):
                self.name = name
                self.cf = CF_USE1
                self.comment = comment

            def decode(self, insn, opcode):
                OperandC, OperandA, OperandB, Imm5 = decode_format_R(opcode)
                insn.Op1.value = Imm5
                insn.Op1.type = o_imm
                insn.Op1.dtyp = dt_byte
                if OperandA != 0 or OperandB != 0 or OperandC != 0x1D:
                    insn.size = 0

        class idef_R_type_break(idef_R_type_trap):
            def decode(self, insn, opcode):
                OperandC, OperandA, OperandB, Imm5 = decode_format_R(opcode)
                insn.Op1.value = Imm5
                insn.Op1.type = o_imm
                insn.Op1.dtyp = dt_byte
                if OperandA != 0 or OperandB != 0 or OperandC != 0x1E:
                    insn.size = 0

        class idef_R_type_ret(idef):
            def __init__(self, name, comment):
                self.name = name
                self.cf = CF_STOP
                self.comment = comment

            def decode(self, insn, opcode):
                OperandC, OperandA, OperandB, Imm5 = decode_format_R(opcode)
                if OperandA != 0x1F or OperandB != 0 or OperandC != 0 or Imm5 != 0:
                    insn.size = 0

        class idef_R_type_eret(idef_R_type_ret):
            def decode(self, insn, opcode):
                OperandC, OperandA, OperandB, Imm5 = decode_format_R(opcode)
                # NIOS II Manual
                # if OperandA != 0x1d or OperandB != 0x1e or OperandC != 0 or Imm5 != 0:
                # Reality
                if OperandA != 0x1D or OperandC != 0 or Imm5 != 0:
                    insn.size = 0

        class idef_R_type_bret(idef_R_type_ret):
            def decode(self, insn, opcode):
                OperandC, OperandA, OperandB, Imm5 = decode_format_R(opcode)
                if OperandA != 0x1E or OperandB != 0 or OperandC != 0x1E or Imm5 != 0:
                    insn.size = 0

        class idef_R_type_jmp(idef):
            def __init__(self, name, comment):
                self.name = name
                self.cf = CF_USE1 | CF_JUMP | CF_STOP
                self.comment = comment

            def decode(self, insn, opcode):
                OperandC, OperandA, OperandB, Imm5 = decode_format_R(opcode)
                insn.Op1.reg = OperandA
                insn.Op1.type = o_reg
                insn.Op1.dtyp = dt_code
                if OperandC != 0 or OperandB != 0 or Imm5 != 0:
                    insn.size = 0

        class idef_R_type_callr(idef):
            def __init__(self, name, comment):
                self.name = name
                self.cf = CF_USE1 | CF_CALL
                self.comment = comment

            def decode(self, insn, opcode):
                OperandC, OperandA, OperandB, Imm5 = decode_format_R(opcode)
                insn.Op1.reg = OperandA
                insn.Op1.type = o_reg
                insn.Op1.dtyp = dt_code
                if OperandC != 0x1F or OperandB != 0 or Imm5 != 0:
                    insn.size = 0

        class idef_R_type_cache(idef):
            def __init__(self, name, comment):
                self.name = name
                self.cf = CF_USE1
                self.comment = comment

            def decode(self, insn, opcode):
                OperandC, OperandA, OperandB, Imm5 = decode_format_R(opcode)
                insn.Op1.reg = OperandA
                insn.Op1.type = o_reg
                # insn.Op1.dtyp = ???
                if OperandB != 0 or OperandC != 0 or Imm5 != 0:
                    insn.size = 0

        class idef_R_type_nextpc(idef):
            def __init__(self, name, comment, new_cf=None):
                self.name = name
                self.cf = CF_CHG1
                self.comment = comment

            def decode(self, insn, opcode):
                OperandC, OperandA, OperandB, Imm5 = decode_format_R(opcode)
                insn.Op1.reg = OperandC
                insn.Op1.type = o_reg
                insn.Op1.dtyp = dt_code
                if OperandA != 0 or OperandB != 0 or Imm5 != 0:
                    insn.size = 0

        # J-Type instructions
        class idef_J_type(idef):
            def __init__(self, name, comment, new_cf=None):
                self.name = name
                if new_cf != None:
                    self.cf = new_cf
                else:
                    self.cf = CF_USE1 | CF_CALL
                self.comment = comment

            def decode(self, insn, opcode):
                ImmValue = decode_format_J(opcode)
                insn.Op1.addr = (insn.ea & 0xF0000000) | (ImmValue << 2)
                insn.Op1.type = o_near
                insn.Op1.dtyp = dt_code

        # Special instruction - custom N xC, xA, xB
        class idef_custom(idef):
            def __init__(self, name, comment):
                self.name = name
                self.cf = CF_CHG1 | CF_USE2 | CF_USE3
                self.comment = comment

            def decode(self, insn, opcode):
                (
                    OperandC,
                    OperandA,
                    OperandB,
                    CmdN,
                    ReadRA,
                    ReadRB,
                    ReadRC,
                ) = decode_instr_custom(opcode)
                insn.Op1.specval = CmdN
                insn.Op1.reg = OperandC
                insn.Op2.reg = OperandA
                insn.Op3.reg = OperandB
                if ReadRC == 1:
                    insn.Op1.type = o_reg
                else:
                    insn.Op1.type = o_custreg
                if ReadRA == 1:
                    insn.Op2.type = o_reg
                else:
                    insn.Op2.type = o_custreg
                if ReadRB == 1:
                    insn.Op3.type = o_reg
                else:
                    insn.Op3.type = o_custreg
                insn.Op1.dtyp = insn.Op2.dtyp = insn.Op3.dtyp = dt_dword

        # Pseudo Instruction (Emulated)
        class idef_emul_type(idef):
            def __init__(self, name, comment, new_cf=None):
                self.name = name
                if new_cf != None:
                    self.cf = new_cf
                else:
                    self.cf = CF_CHG1 | CF_USE2
                self.comment = comment

        # OP Encodings Table
        self.itable_I_Type = {
            0x00: idef_J_type("call", "call subroutine"),
            0x01: idef_J_type("jmpi", "jump immediate", CF_USE1 | CF_JUMP | CF_STOP),
            0x03: idef_I_type_load("ldbu", "load unsigned byte from memory", dt_byte),
            0x04: idef_I_type_sign("addi", "add immediate"),
            0x05: idef_I_type_store("stb", "store byte to memory", dt_byte),
            0x06: idef_I_type_br("br", "unconditional branch"),
            0x07: idef_I_type_load("ldb", "load byte from memory", dt_byte),
            0x08: idef_I_type_sign(
                "cmpgei", "compare greater than or equal signed immediate"
            ),
            0x0B: idef_I_type_load(
                "ldhu", "load unsigned halfword from memory", dt_word
            ),
            0x0C: idef_I_type("andi", "bitwise logical and immediate"),
            0x0D: idef_I_type_store("sth", "store halfword to memory", dt_word),
            0x0E: idef_I_type_condjump("bge", "branch if greater than or equal signed"),
            0x0F: idef_I_type_load("ldh", "load halfword from memory", dt_word),
            0x10: idef_I_type_sign("cmplti", "compare less than signed immediate"),
            0x13: idef_I_type_cache("initda", "initialize data cache address"),
            0x14: idef_I_type("ori", "bitwise logical or immediate"),
            0x15: idef_I_type_store("stw", "store word to memory", dt_dword),
            0x16: idef_I_type_condjump("blt", "branch if less than signed"),
            0x17: idef_I_type_load("ldw", "load 32-bit word from memory", dt_dword),
            0x18: idef_I_type_sign("cmpnei", "compare not equal immediate"),
            0x1B: idef_I_type_cache("flushda", "flush data cache address"),
            0x1C: idef_I_type("xori", "bitwise logical exclusive or immediate"),
            0x1E: idef_I_type_condjump("bne", "branch if not equal"),
            0x20: idef_I_type_sign("cmpeqi", "compare equal immediate"),
            0x23: idef_I_type_load(
                "ldbuio", "load unsigned byte from I/O peripheral", dt_byte
            ),
            0x24: idef_I_type_sign("muli", "multiply immediate"),
            0x25: idef_I_type_store("stbio", "store byte to I/O peripheral", dt_byte),
            0x26: idef_I_type_condjump("beq", "branch if equal"),
            0x27: idef_I_type_load("ldbio", "load byte from I/O peripheral", dt_byte),
            0x28: idef_I_type(
                "cmpgeui", "compare greater than or equal unsigned immediate"
            ),
            0x2B: idef_I_type_load(
                "ldhuio", "load unsigned halfword from I/O peripheral", dt_word
            ),
            0x2C: idef_I_type(
                "andhi", "bitwise logical and immediate into high halfword"
            ),
            0x2D: idef_I_type_store(
                "sthio", "store halfword to I/O peripheral", dt_word
            ),
            0x2E: idef_I_type_condjump(
                "bgeu", "branch if greater than or equal unsigned"
            ),
            0x2F: idef_I_type_load(
                "ldhio", "load halfword from I/O peripheral", dt_word
            ),
            0x30: idef_I_type("cmpltui", "compare less than unsigned immediate"),
            0x32: idef_custom("custom", "custom instruction"),
            0x33: idef_I_type_cache("initd", "initialize data cache line"),
            0x34: idef_I_type(
                "orhi", "bitwise logical or immediate into high halfword"
            ),
            0x35: idef_I_type_store("stwio", "store word to I/O peripheral", dt_dword),
            0x36: idef_I_type_condjump("bltu", "branch if less than unsigned"),
            0x37: idef_I_type_load(
                "ldwio", "load 32-bit word from I/O peripheral", dt_dword
            ),
            0x38: idef_I_type_sign("rdprs", "read from previous register set"),
            0x3B: idef_I_type_cache("flushd", "flush data cache line"),
            0x3C: idef_I_type(
                "xorhi", "bitwise logical exclusive or immediate into high halfword"
            ),
        }

        # OPX Encodings Table
        self.itable_R_Type = {
            0x01: idef_R_type_eret("eret", "exception return"),
            0x02: idef_R_type_shift_imm("roli", "rotate left immediate"),
            0x03: idef_R_type_shift("rol", "rotate left"),
            0x04: idef_R_type_stub("flushp", "flush pipeline"),
            0x05: idef_R_type_ret("ret", "return from subroutine"),
            0x06: idef_R_type("nor", "bitwise logical nor"),
            0x07: idef_R_type("mulxuu", "multiply extended unsigned/unsigned"),
            0x08: idef_R_type("cmpge", "compare greater than or equal signed"),
            0x09: idef_R_type_bret("bret", "breakpoint return"),
            0x0B: idef_R_type_shift("ror", "rotate right"),
            0x0C: idef_R_type_cache("flushi", "flush instruction cache line"),
            0x0D: idef_R_type_jmp("jmp", "computed jump"),
            0x0E: idef_R_type("and", "bitwise logical and"),
            0x10: idef_R_type("cmplt", "compare less than signed"),
            0x12: idef_R_type_shift_imm("slli", "shift left logical immediate"),
            0x13: idef_R_type_shift("sll", "shift left logical"),
            0x14: idef_R_type_wrprs("wrprs", "write to previous register set"),
            0x16: idef_R_type("or", "bitwise logical or"),
            0x17: idef_R_type("mulxsu", "multiply extended signed/unsigned"),
            0x18: idef_R_type("cmpne", "compare not equal"),
            0x1A: idef_R_type_shift_imm("srli", "shift right logical immediate"),
            0x1B: idef_R_type_shift("srl", "shift right logical"),
            0x1C: idef_R_type_nextpc("nextpc", "get address of following instruction"),
            0x1D: idef_R_type_callr("callr", "call subroutine in register"),
            0x1E: idef_R_type("xor", "bitwise logical exclusive or"),
            0x1F: idef_R_type("mulxss", "multiply extended signed/signed"),
            0x20: idef_R_type("cmpeq", "compare equal"),
            0x24: idef_R_type("divu", "divide unsigned"),
            0x25: idef_R_type("div", "divide"),
            0x26: idef_R_type_rdctl("rdctl", "read from control register"),
            0x27: idef_R_type("mul", "multiply"),
            0x28: idef_R_type("cmpgeu", "compare greater than or equal unsigned"),
            0x29: idef_R_type_cache("initi", "initialize instruction cache line"),
            0x2D: idef_R_type_trap("trap", "trap"),
            0x2E: idef_R_type_wrctl("wrctl", "write to control register"),
            0x30: idef_R_type("cmpltu", "compare less than unsigned"),
            0x31: idef_R_type("add", "add register"),
            0x34: idef_R_type_break("break", "debugging breakpoint"),
            0x36: idef_R_type_stub("sync", "memory synchronization"),
            0x39: idef_R_type("sub", "subtract"),
            0x3A: idef_R_type_shift_imm("srai", "shift right arithmetic immediate"),
            0x3B: idef_R_type_shift("sra", "shift right arithmetic"),
        }

        # Pseudo Instructions (Emulated) Table
        self.itable_emulated = {
            0x01: idef_emul_type("mov", "move register to register"),
            0x02: idef_emul_type("movhi", "move immediate into high halfword"),
            0x03: idef_emul_type("movi", "move signed immediate into word"),
            0x04: idef_emul_type("movia", "move immediate address into word"),
            0x05: idef_emul_type("movui", "move unsigned immediate into word"),
            0x06: idef_emul_type("nop", "no operation", 0),
            0x07: idef_emul_type(
                "subi", "subtract immediate", CF_CHG1 | CF_USE2 | CF_USE3
            ),
        }

        # Floating Point Hardware Custom Instruction 2 (FPH2)
        self.itable_custom = {
            0xFF: idef_custom("fdivs", "floating point divide (FPH2 custom)"),
            0xFE: idef_custom("fsubs", "floating point subtract (FPH2 custom)"),
            0xFD: idef_custom("fadds", "floating point add (FPH2 custom)"),
            0xFC: idef_custom("fmuls", "floating point multiply (FPH2 custom)"),
            0xFB: idef_custom("fsqrts", "floating point square root (FPH2 custom)"),
            0xFA: idef_custom("floatis", "integer to float (FPH2 custom)"),
            0xF9: idef_custom(
                "fixsi", "float to integer truncation rounding  (FPH2 custom)"
            ),
            0xF8: idef_custom(
                "round", "float to integer nearest rounding (FPH2 custom)"
            ),
            0xE9: idef_custom("fmins", "floating point minimum (FPH2 custom)"),
            0xE8: idef_custom("fmaxs", "floating point maximum (FPH2 custom)"),
            0xE7: idef_custom(
                "fcmplts", "floating point less than compare (FPH2 custom)"
            ),
            0xE6: idef_custom(
                "fcmples", "floating point less than or equal compare (FPH2 custom)"
            ),
            0xE5: idef_custom(
                "fcmpgts", "floating point greater than compare (FPH2 custom)"
            ),
            0xE4: idef_custom(
                "fcmpges", "floating point greater than or equal compare (FPH2 custom)"
            ),
            0xE3: idef_custom("fcmpeqs", "floating point equal compare (FPH2 custom)"),
            0xE2: idef_custom(
                "fcmpnes", "floating point not equal compare (FPH2 custom)"
            ),
            0xE1: idef_custom("fnegs", "floating point negate (FPH2 custom)"),
            0xE0: idef_custom("fabss", "floating point absolute (FPH2 custom)"),
        }

        # Now create an instruction table compatible with IDA processor module requirements
        Instructions = []
        i = 0
        for x in (
            list(self.itable_I_Type.values())
            + list(self.itable_R_Type.values())
            + list(self.itable_emulated.values())
            + list(self.itable_custom.values())
        ):
            d = dict(name=x.name, feature=x.cf)
            if x.comment != None:
                d["cmt"] = x.comment
            Instructions.append(d)
            setattr(self, "itype_" + x.name, i)
            i += 1

        # icode of the last instruction + 1
        self.instruc_end = len(Instructions) + 1

        # Array of instructions
        self.instruc = Instructions
        empty = {"name": "", "feature": 0, "cmt": ""}
        self.instruc.append(empty)

        # Icode of return instruction. It is ok to give any of possible return
        # instructions
        self.icode_return = self.itype_ret

    # ----------------------------------------------------------------------
    # Registers definition
    #

    def init_registers(self):
        """This function parses the
        register table and creates
        corresponding ireg_XXX constants"""
        # register names
        self.reg_names = [
            # General-Purpose Registers
            "zero",  # aka r0
            "at",  # aka r1
            "r2",
            "r3",
            "r4",
            "r5",
            "r6",
            "r7",
            "r8",
            "r9",
            "r10",
            "r11",
            "r12",
            "r13",
            "r14",
            "r15",
            "r16",
            "r17",
            "r18",
            "r19",
            "r20",
            "r21",
            "r22",
            "r23",
            "et",  # aka r24
            "bt",  # aka r25
            "gp",  # aka r26
            "sp",  # aka r27
            "fp",  # aka r28
            "ea",  # aka r29
            "sstatus",  # aka 30
            "ra",  # aka r31
            # Control Registers
            "status",  # aka ctl0
            "estatus",  # aka ctl1
            "bstatus",  # aka ctl2
            "ienable",  # aka ctl3
            "ipending",  # aka ctl4
            "cpuid",  # aka ctl5
            "ctl6",
            "exception",  # aka ctl7
            "pteaddr",  # aka ctl8
            "tlbacc",  # aka ctl9
            "tlbmisc",  # aka ctl10
            "eccinj",  # aka ctl11
            "badaddr",  # aka ctl12
            "config",  # aka ctl13
            "mpubase",  # aka ctl14
            "mpuacc",  # aka ctl15
            "ctl16",
            "ctl17",
            "ctl18",
            "ctl19",
            "ctl20",
            "ctl21",
            "ctl22",
            "ctl23",
            "ctl24",
            "ctl25",
            "ctl26",
            "ctl27",
            "ctl28",
            "ctl29",
            "ctl30",
            "ctl31",
            # Fake segment registers
            "CS",
            "DS",
        ]

        # Create the ireg_XXXX constants
        for i in range(len(self.reg_names)):
            setattr(self, "ireg_" + self.reg_names[i], i)

        # Segment register information (use virtual CS and DS registers if your
        # processor doesn't have segment registers):
        self.reg_first_sreg = self.ireg_CS
        self.reg_last_sreg = self.ireg_DS

        # You should define 2 virtual segment registers for CS and DS.

        # number of CS register
        self.reg_code_sreg = self.ireg_CS
        # number of DS register
        self.reg_data_sreg = self.ireg_DS

    def __init__(self):
        idaapi.processor_t.__init__(self)
        self.init_instructions()
        self.init_registers()


# ----------------------------------------------------------------------
# Every processor module script must provide this function.
# It should return a new instance of a class derived from idaapi.processor_t
def PROCESSOR_ENTRY():
    return nios2_processor_t()
