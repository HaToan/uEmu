from __future__ import print_function
from unicorn import *
from unicorn.arm_const import *
from unicorn.arm64_const import *
from unicorn.mips_const import *
from unicorn.x86_const import *
from sys import exit
import keystone
import capstone
import os
import threading
import datetime
import pickle

# === Configuration

class UEMU_CONFIG:
    
    IDAViewColor_PC     = 0x00B3CBFF
    IDAViewColor_Reset  = 0xFFFFFFFF

    UnicornPageSize     = 0x1000

# === Helpers

class UEMU_HELPERS:
    @staticmethod
    def ALIGN_PAGE_DOWN(x):
        return x & ~(UEMU_CONFIG.UnicornPageSize - 1)
        
    @staticmethod
    def ALIGN_PAGE_UP(x):
        return (x + UEMU_CONFIG.UnicornPageSize - 1) & ~(UEMU_CONFIG.UnicornPageSize-1)

    @staticmethod
    def get_register_map(arch):
        if arch.startswith("arm64"):
            arch = "arm64"
        elif arch.startswith("arm"):
            arch = "arm"
        elif arch.startswith("mips"):
            arch = "mips"

        registers = {
            "x64" : [
                [ "rax",    UC_X86_REG_RAX  ],
                [ "rbx",    UC_X86_REG_RBX  ],
                [ "rcx",    UC_X86_REG_RCX  ],
                [ "rdx",    UC_X86_REG_RDX  ],
                [ "rsi",    UC_X86_REG_RSI  ],
                [ "rdi",    UC_X86_REG_RDI  ],
                [ "rbp",    UC_X86_REG_RBP  ],
                [ "rsp",    UC_X86_REG_RSP  ],
                [ "r8",     UC_X86_REG_R8   ],
                [ "r9",     UC_X86_REG_R9   ],
                [ "r10",    UC_X86_REG_R10  ],
                [ "r11",    UC_X86_REG_R11  ],
                [ "r12",    UC_X86_REG_R12  ],
                [ "r13",    UC_X86_REG_R13  ],
                [ "r14",    UC_X86_REG_R14  ],
                [ "r15",    UC_X86_REG_R15  ],
                [ "rip",    UC_X86_REG_RIP  ],
                [ "sp",     UC_X86_REG_SP   ],
            ],
            "x86" : [
                [ "eax",    UC_X86_REG_EAX  ],
                [ "ebx",    UC_X86_REG_EBX  ],
                [ "ecx",    UC_X86_REG_ECX  ],
                [ "edx",    UC_X86_REG_EDX  ],
                [ "esi",    UC_X86_REG_ESI  ],
                [ "edi",    UC_X86_REG_EDI  ],
                [ "ebp",    UC_X86_REG_EBP  ],
                [ "esp",    UC_X86_REG_ESP  ],
                [ "eip",    UC_X86_REG_EIP  ],
                [ "sp",     UC_X86_REG_SP   ],
            ],        
            "arm" : [
                [ "R0",     UC_ARM_REG_R0  ],
                [ "R1",     UC_ARM_REG_R1  ],
                [ "R2",     UC_ARM_REG_R2  ],
                [ "R3",     UC_ARM_REG_R3  ],
                [ "R4",     UC_ARM_REG_R4  ],
                [ "R5",     UC_ARM_REG_R5  ],
                [ "R6",     UC_ARM_REG_R6  ],
                [ "R7",     UC_ARM_REG_R7  ],
                [ "R8",     UC_ARM_REG_R8  ],
                [ "R9",     UC_ARM_REG_R9  ],
                [ "R10",    UC_ARM_REG_R10 ],
                [ "R11",    UC_ARM_REG_R11 ],
                [ "R12",    UC_ARM_REG_R12 ],
                [ "PC",     UC_ARM_REG_PC  ],
                [ "SP",     UC_ARM_REG_SP  ],
                [ "LR",     UC_ARM_REG_LR  ],
                [ "CPSR",   UC_ARM_REG_CPSR ]
            ],
            "arm64" : [
                [ "X0",     UC_ARM64_REG_X0  ],
                [ "X1",     UC_ARM64_REG_X1  ],
                [ "X2",     UC_ARM64_REG_X2  ],
                [ "X3",     UC_ARM64_REG_X3  ],
                [ "X4",     UC_ARM64_REG_X4  ],
                [ "X5",     UC_ARM64_REG_X5  ],
                [ "X6",     UC_ARM64_REG_X6  ],
                [ "X7",     UC_ARM64_REG_X7  ],
                [ "X8",     UC_ARM64_REG_X8  ],
                [ "X9",     UC_ARM64_REG_X9  ],
                [ "X10",    UC_ARM64_REG_X10 ],
                [ "X11",    UC_ARM64_REG_X11 ],
                [ "X12",    UC_ARM64_REG_X12 ],
                [ "X13",    UC_ARM64_REG_X13 ],
                [ "X14",    UC_ARM64_REG_X14 ],
                [ "X15",    UC_ARM64_REG_X15 ],
                [ "X16",    UC_ARM64_REG_X16 ],
                [ "X17",    UC_ARM64_REG_X17 ],
                [ "X18",    UC_ARM64_REG_X18 ],
                [ "X19",    UC_ARM64_REG_X19 ],
                [ "X20",    UC_ARM64_REG_X20 ],
                [ "X21",    UC_ARM64_REG_X21 ],
                [ "X22",    UC_ARM64_REG_X22 ],
                [ "X23",    UC_ARM64_REG_X23 ],
                [ "X24",    UC_ARM64_REG_X24 ],
                [ "X25",    UC_ARM64_REG_X25 ],
                [ "X26",    UC_ARM64_REG_X26 ],
                [ "X27",    UC_ARM64_REG_X27 ],
                [ "X28",    UC_ARM64_REG_X28 ],
                [ "PC",     UC_ARM64_REG_PC  ],
                [ "SP",     UC_ARM64_REG_SP  ],
                [ "FP",     UC_ARM64_REG_FP  ],
                [ "LR",     UC_ARM64_REG_LR  ],
                [ "NZCV",   UC_ARM64_REG_NZCV ]
            ],
            "mips" : [
                [ "zero",   UC_MIPS_REG_0   ],
                [ "at",     UC_MIPS_REG_1   ],
                [ "v0",     UC_MIPS_REG_2   ],
                [ "v1",     UC_MIPS_REG_3   ],
                [ "a0",     UC_MIPS_REG_4   ],
                [ "a1",     UC_MIPS_REG_5   ],
                [ "a2",     UC_MIPS_REG_6   ],
                [ "a3",     UC_MIPS_REG_7   ],
                [ "t0",     UC_MIPS_REG_8   ],
                [ "t1",     UC_MIPS_REG_9   ],
                [ "t2",     UC_MIPS_REG_10  ],
                [ "t3",     UC_MIPS_REG_11  ],
                [ "t4",     UC_MIPS_REG_12  ],
                [ "t5",     UC_MIPS_REG_13  ],
                [ "t6",     UC_MIPS_REG_14  ],
                [ "t7",     UC_MIPS_REG_15  ],
                [ "s0",     UC_MIPS_REG_16  ],
                [ "s1",     UC_MIPS_REG_17  ],
                [ "s2",     UC_MIPS_REG_18  ],
                [ "s3",     UC_MIPS_REG_19  ],
                [ "s4",     UC_MIPS_REG_20  ],
                [ "s5",     UC_MIPS_REG_21  ],
                [ "s6",     UC_MIPS_REG_22  ],
                [ "s7",     UC_MIPS_REG_23  ],
                [ "t8",     UC_MIPS_REG_24  ],
                [ "t9",     UC_MIPS_REG_25  ],
                [ "k0",     UC_MIPS_REG_26  ],
                [ "k1",     UC_MIPS_REG_27  ],
                [ "gp",     UC_MIPS_REG_28  ],
                [ "sp",     UC_MIPS_REG_29  ],
                [ "fp",     UC_MIPS_REG_30  ],
                [ "ra",     UC_MIPS_REG_31  ],
                [ "pc",     UC_MIPS_REG_PC  ],
            ]
        }
        return registers[arch]

    @staticmethod
    def get_register_bits(arch):
        if arch.startswith("arm64"):
            arch = "arm64"
        elif arch.startswith("arm"):
            arch = "arm"
        elif arch.startswith("mips"):
            arch = "mips"

        registers_bits = {
            "x64"   : 64,
            "x86"   : 32,        
            "arm"   : 32,
            "arm64" : 64,
            "mips"  : 32
        }
        return registers_bits[arch]

    @staticmethod
    def get_register_ext_map(arch):
        if arch.startswith("arm64"):
            arch = "arm64"
        elif arch.startswith("arm"):
            arch = "arm"
        elif arch.startswith("mips"):
            arch = "mips"

        registers_ext = {
            "x64" : [
            ],
            "x86" : [
            ],        
            "arm" : [
            ],
            "arm64" : [
                [ "Q0",     UC_ARM64_REG_Q0  ],
                [ "Q1",     UC_ARM64_REG_Q1  ],
                [ "Q2",     UC_ARM64_REG_Q2  ],
                [ "Q3",     UC_ARM64_REG_Q3  ],
                [ "Q4",     UC_ARM64_REG_Q4  ],
                [ "Q5",     UC_ARM64_REG_Q5  ],
                [ "Q6",     UC_ARM64_REG_Q6  ],
                [ "Q7",     UC_ARM64_REG_Q7  ],
                [ "Q8",     UC_ARM64_REG_Q8  ],
                [ "Q9",     UC_ARM64_REG_Q9  ],
                [ "Q10",    UC_ARM64_REG_Q10 ],
                [ "Q11",    UC_ARM64_REG_Q11 ],
                [ "Q12",    UC_ARM64_REG_Q12 ],
                [ "Q13",    UC_ARM64_REG_Q13 ],
                [ "Q14",    UC_ARM64_REG_Q14 ],
                [ "Q15",    UC_ARM64_REG_Q15 ],
                [ "Q16",    UC_ARM64_REG_Q16 ],
                [ "Q17",    UC_ARM64_REG_Q17 ],
                [ "Q18",    UC_ARM64_REG_Q18 ],
                [ "Q19",    UC_ARM64_REG_Q19 ],
                [ "Q20",    UC_ARM64_REG_Q20 ],
                [ "Q21",    UC_ARM64_REG_Q21 ],
                [ "Q22",    UC_ARM64_REG_Q22 ],
                [ "Q23",    UC_ARM64_REG_Q23 ],
                [ "Q24",    UC_ARM64_REG_Q24 ],
                [ "Q25",    UC_ARM64_REG_Q25 ],
                [ "Q26",    UC_ARM64_REG_Q26 ],
                [ "Q27",    UC_ARM64_REG_Q27 ],
                [ "Q28",    UC_ARM64_REG_Q28 ],
                [ "Q29",    UC_ARM64_REG_Q29 ],
                [ "Q30",    UC_ARM64_REG_Q30 ],
                [ "Q31",    UC_ARM64_REG_Q31 ],
            ],
            "mips" : [
            ]            
        }
        return registers_ext[arch]

    @staticmethod
    def get_register_ext_bits(arch):
        if arch.startswith("arm64"):
            arch = "arm64"
        elif arch.startswith("arm"):
            arch = "arm"
        elif arch.startswith("mips"):
            arch = "mips"

        registers_ext_bits = {
            "x64"   : 0,
            "x86"   : 0,        
            "arm"   : 0,
            "arm64" : 128,
            "mips"  : 0
        }
        return registers_ext_bits[arch] 

    @staticmethod
    def trim_spaces(string):
        return ' '.join(str(string).split())

def uemu_log(entry):
    print("[Emulator]: " + entry + "\n")

class Emulator(object):
    mu = None
    pc = 0xffffffff #BADADDR

    emuActive       = False
    emuRunning      = False
    emuThread       = None

    kStepCount_Run  = 0
    emuStepCount    = 1

    fix_context     = None
    extended        = False

    settings = {
        "follow_pc"     : True,
        "force_code"    : True,
        "trace_inst"    : False,
        "lazy_mapping"  : False,
    }

    def __init__(self, owner = None, arch='armle'):
        super(Emulator, self).__init__()
        self.owner = owner
        self.pc = None
        self.arch_mode = arch
        self.context = None

        uc_setup = {
            "x64"       : [ UC_X86_REG_RIP,     UC_ARCH_X86,    UC_MODE_64                              ],
            "x86"       : [ UC_X86_REG_EIP,     UC_ARCH_X86,    UC_MODE_32                              ],
            "arm64be"   : [ UC_ARM64_REG_PC,    UC_ARCH_ARM64,  UC_MODE_ARM     | UC_MODE_BIG_ENDIAN    ],
            "arm64le"   : [ UC_ARM64_REG_PC,    UC_ARCH_ARM64,  UC_MODE_ARM     | UC_MODE_LITTLE_ENDIAN ],
            "armbe"     : [ UC_ARM_REG_PC,      UC_ARCH_ARM,    UC_MODE_ARM     | UC_MODE_BIG_ENDIAN    ],
            "armle"     : [ UC_ARM_REG_PC,      UC_ARCH_ARM,    UC_MODE_ARM     | UC_MODE_LITTLE_ENDIAN ],
            "mips64be"  : [ UC_MIPS_REG_PC,     UC_ARCH_MIPS,   UC_MODE_MIPS64  | UC_MODE_BIG_ENDIAN    ],
            "mips64le"  : [ UC_MIPS_REG_PC,     UC_ARCH_MIPS,   UC_MODE_MIPS64  | UC_MODE_LITTLE_ENDIAN ],
            "mipsbe"    : [ UC_MIPS_REG_PC,     UC_ARCH_MIPS,   UC_MODE_MIPS32  | UC_MODE_BIG_ENDIAN    ],
            "mipsle"    : [ UC_MIPS_REG_PC,     UC_ARCH_MIPS,   UC_MODE_MIPS32  | UC_MODE_LITTLE_ENDIAN ],
        }

        self.uc_reg_pc = uc_setup[arch][0]
        self.uc_arch   = uc_setup[arch][1]
        self.uc_mode   = uc_setup[arch][2]

        uemu_log("Unicorn version [ %s ]" % (unicorn.__version__))
        uemu_log("CPU arch set to [ %s ]" % (arch))


    def is_active(self):
        return self.emuActive

    def is_running(self):
        return self.emuRunning

    def get_context(self):
        # Looks like unicorn context is not serializable in python
        # return self.mu.context_save()

        uc_context = {}
        reg_map = UEMU_HELPERS.get_register_map(self.arch_mode)
        reg_ext_map = UEMU_HELPERS.get_register_ext_map(self.arch_mode)
        uc_context["cpu"] = [ [ row[1], self.emu.reg_read(row[1]) ] for row in reg_map ]
        uc_context["cpu_ext"] = [ [ row[1], self.emu.reg_read(row[1]) ] for row in reg_ext_map ]
        uc_context["mem"] = [ [ memStart, memEnd, memPerm, self.emu.mem_read(memStart, memEnd - memStart + 1) ] for (memStart, memEnd, memPerm) in self.emu.mem_regions() ]

        return uc_context

    def set_context(self, context):
        # Looks like unicorn context is not serializable in python
        # self.mu.context_restore(context)

        for reg in context["cpu"]:
            self.emu.reg_write(reg[0], reg[1])

        for reg in context["cpu_ext"]:
            self.emu.reg_write(reg[0], reg[1])

        for mem in context["mem"]:
            try:
                memStart = mem[0]
                memEnd = mem[1]
                memPerm = mem[2]
                memData = mem[3]
                uemu_log("  map [%X:%X]" % (memStart, memEnd))
                #self.emu.mem_map(memStart, memEnd - memStart + 1, memPerm)
                self.emu.mem_write(memStart, str(memData))
            except UcError as e:
                uemu_log("! <U> %s" % e)

        self.pc = self.emu.reg_read(self.uc_reg_pc)
        self.emuActive = True

    def is_memory_mapped(self, address):
        try:
            self.mu.mem_read(address, 1)
            return True
        except UcError as e:
            return False

    def map_memory(self, address, size):
        # - size is unsigned and must be != 0
        # - starting address must be aligned to 4KB
        # - map size must be multiple of the page size (4KB)
        # - permissions can only contain READ or WRITE perms
        try:
            memStart = address
            memEnd = address + size
            memStartAligned = UEMU_HELPERS.ALIGN_PAGE_DOWN(memStart)
            memEndAligned = UEMU_HELPERS.ALIGN_PAGE_UP(memEnd)
            uemu_log("  map [%X:%X] -> [%X:%X]" % (memStart, memEnd - 1, memStartAligned, memEndAligned - 1))
            self.emu.mem_map(memStartAligned, memEndAligned - memStartAligned)
        except UcError as e:
            uemu_log("! <U> %s" % e)

    def map_empty(self, address, size):
        self.map_memory(address, size)
        self.emu.mem_write(UEMU_HELPERS.ALIGN_PAGE_DOWN(address), "\x00" * UEMU_CONFIG.UnicornPageSize)

    def map_binary(self, bin_name, address):
        with open(bin_name, 'rb') as file:
            file.seek(0, 2)
            file_size = file.tell()

            # read data from file
            file.seek(0, 0)
            data = file.read(file_size)
            file.close()

            try:
                self.map_memory(UEMU_HELPERS.ALIGN_PAGE_DOWN(address), file_size)
                self.emu.mem_write(address, data)
            except UcError as e:
                return False

            return True

        return False
    def get_mapped_segments(self):
        return [ memStart for (memStart, memEnd, memPerm) in self.emu.mem_regions() ]

    def get_mapped_memory(self):
        return [ [ memStart, memEnd, memPerm ] for (memStart, memEnd, memPerm) in self.emu.mem_regions() ]

    def get_mapped_bytes(self, address, size):
        return self.emu.mem_read(address, size)


    def init_cpu_context(self, regs):
        reg_map = UEMU_HELPERS.get_register_map(self.arch_mode)
        i = 0
        for row in reg_map:
            self.emu.reg_write(row[1], regs[i])
            i = i + 1

        return True
        
    def run_form(self, bin_name, mem_map, regs, segments):
        '''
            ARCH and ARCH_MODE:
            https://github.com/unicorn-engine/unicorn/blob/master/bindings/python/unicorn/unicorn_const.py
        '''
        '''
        https://github.com/unicorn-engine/unicorn/blob/master/bindings/python/unicorn/arm_const.py
        '''
        '''
        ARM, THUMB, ARM926, ARM946, ARM1176, ..
        '''
        # initalize emulator in ARM mode
        self.emu = Uc(self.uc_arch, self.uc_mode)
        # hook
        self.emu.hook_add(UC_HOOK_CODE, self.hook_code)
        self.emu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, self.hook_mem_invalid)
        '''init keytone, captone'''
        #ks = keystone.Ks(keystone.KS_ARCH_ARM, keystone.KS_MODE_ARM)
        self.md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)

        try:
            # init regs
            if self.init_cpu_context(regs) == False:
                return

            uemu_log("Mapping segments...")
            # load binary 
            # map memory and write machine code to be emulated to memory
            if self.map_binary(bin_name, mem_map) == False:
                return

            # get segments
            for seg in segments:
                self.map_memory(seg['addr'], seg['size'])
                self.emu.mem_write(seg['addr'], '\x00' * seg['size'])

            segmented = self.get_mapped_segments()

            files = os.listdir('./segments')
            for segment in files:
                with open('./segments/' + segment, 'rb') as file:
                    addr_segment = int(segment[0:-1].strip(), 16)
                    if self.checkMem(addr_segment):
                        print(hex(addr_segment))
                        self.emu.mem_write(addr_segment, file.read())
                    else:
                        print(hex(addr_segment))
                        file.seek(0, 2)
                        self.map_memory(addr_segment, file.tell())
                        file.seek(0, 0)
                        self.emu.mem_write(addr_segment, file.read())
                file.close()

            self.emuActive = True    
        except IOError:
            print('[x]ERROR: Cannot open', filename)
            raise
        except Exception as e:
            print("[x]ERROR Init:\t", e)
            raise

    def checkMem(self, add_mem):
        try:
            self.emu.mem_read(add_mem, 1)
            return 1
        except Exception as e:
            return 0

    def interrupt(self):
        self.emu.emu_stop()

        self.emuStepCount = 1
        self.emuRunning = False

    def reset(self):
        self.interrupt()
        # unmap all regions
        for (start, end, perm) in self.emu.mem_regions():
            uemu_log("  unmap [%X:%X]" % (start, end))
            self.emu.mem_unmap(start, end - start + 1)

        self.pc = 0xFFFFFFFF
        self.mu = None
        self.emuActive = False


    #callback for tracing instructions
    def hook_code(self, uc, address, size, user_data):
        reg_map = UEMU_HELPERS.get_register_map(self.arch_mode)
        self.context = [ [ row[0], hex(self.emu.reg_read(row[1])) ] for row in reg_map ]
        self.pc = address
        # if address == 0x4B88:
        #     for reg in Emu.get_cpu():
        #         print(reg)


    def hook_mem_invalid(self, uc, access, address, size, value, user_data):
        try:
            print("! <M> Missing memory at 0x%x, data size = %u, data value = 0x%x" %(address, size, value))
            size = raw_input("[>]Size of segment: ")
            if size == '\n' or size == '':
                self.map_empty(address, 0x1000)
            else:
                self.map_empty(address, size)
            return True
        except Exception as e:
            print(e)
            print("! <M> Missing memory at 0x%x, data size = %u, data value = 0x%x" %(address, size, value))
            size = raw_input("[>]Size of segment: ")
            if size == '\n' or size == '':
                self.map_empty(address, 0x1000)
            else:
                self.map_empty(address, size)
            return True

    def getDisasm(self, pc):
        
        byteb = self.emu.mem_read(pc, 4)
        str_opcode = b''
        for i in byteb:
            str_opcode += chr(i)
        for i in self.md.disasm(str_opcode, 0x1000):
            return(i.mnemonic + " " + i.op_str)

    def step_thread_main(self):
        try:
            self.emu.emu_start(self.pc, -1, count = 1)
            
            if self.fix_context is not None:
                self.emu.context_restore(self.fix_context)
                self.fix_context = None

            self.pc = self.emu.reg_read(self.uc_reg_pc)
            if self.emuStepCount != 1:
                if self.emuStepCount == self.kStepCount_Run:
                    self.step(self.kStepCount_Run)
                else:
                    self.step(self.emuStepCount - 1)
                return

            self.emuStepCount = 1
            self.emuRunning = False
            return True
        except UcError as e:
            if self.emuRunning:
                uemu_log("Emulation interrupted at 0x%X : %s" % (self.pc, UEMU_HELPERS.trim_spaces(self.getDisasm(self.pc))))

            self.emuStepCount = 1
            self.emuRunning = False
            return True

    def step(self, count=1):
        self.emuStepCount = count
        self.emuThread = threading.Thread(target=self.step_thread_main)

        self.emuRunning = True
        self.emuThread.start()

    def run(self, start, end):
        try:
            # if self.context != None:
            #     for reg in self.context:
            #         self.emu.reg_write(reg[0], reg[1])
            self.emu.emu_start(start, end)
        except UcError as e:
            uemu_log("Emulation interrupted at 0x%X : %s" % (self.pc, UEMU_HELPERS.trim_spaces(self.getDisasm(self.pc))))
            print(e)
        except Exception as e:
            print(e)


    def thread_run(self, start, end):
        #start = datetime.datetime.now()
        self.emuThread = threading.Thread(target=self.run, args=(start, end,))
        self.emuThread.start()
        # self.emuThread.join()
        # delta = datetime.datetime.now()- start
        # uemu_log("End threading: " +  str(delta.total_seconds()))

    def checkThread(self):
        if self.emuThread == None:
            return "emuThread is None"
        
        return self.emuThread.is_alive()

    def segment_save_file(self, segment, segment_end):
        # segment_end = None
        # for (start, end, perm) in self.emu.mem_regions():
        #     if segment == start:
        #         segment_end = end
        #         uemu_log("  Dump M [%X:%X]" % (start, end))
        #         break
        try:
            data = ""
            seg_end = segment_end - segment
            fp = open('./segments/' + hex(segment), 'wb')
            isize = segment
            while isize < segment_end:
                if seg_end < 0x1000:
                    data = self.emu.mem_read(isize, seg_end)
                    isize = isize + seg_end
                else:
                    data = self.emu.mem_read(isize, 0x1000)
                    isize = isize + 0x1000
                    seg_end = seg_end - 0x1000
                fp.write(data)

            fp.close()
            print("[.] Dump %s save to file" % "./segments/" + hex(segment))
        except Exception as e:
            fp.close()
            print(e)

    def get_cpu(self):
        pc = None
        print("Context: ")
        for reg in self.context:
            print("\t", reg)
            if reg[0] == "PC":
                pc = reg[1]

        print("\t" + pc + ": " + self.getDisasm(int(pc.split('L')[0], 16)))

    def hexdump(self, addr, size=0x100):
        data = self.emu.mem_read(addr, size)
        iline = 0
        while iline < size / 16:
            stri = "\t"
            for i in range(iline * 16, iline * 16 + 4):
                stri += "%02x " % int(data[i])
            
            stri += " "
            
            for i in range(iline * 16 + 4, iline * 16 + 8):
                stri += "%02x " % int(data[i])
            
            stri += "  " 

            for i in range(iline * 16 + 8, iline * 16 + 12):
                stri += "%02x " % int(data[i])
            
            stri += " "
            
            for i in range(iline * 16 + 12, iline * 16 + 16):
                stri += "%02x " % int(data[i])

            stri += " | "    
            for i in range(iline * 16, iline * 16 + 16):
                if data[i] < 32 or data[i] > 126:
                    stri += '.'
                else:
                    stri += chr(data[i])
            print(stri)

            iline = iline + 1

    def get_pc(self):
        return self.pc

    def write_mem(self, addr, value):
        try:
            self.emu.mem_write(addr, value)
        except Exception as e:
            print(e)

    def read_mem(self, addr, value):
        try:
            return self.emu.mem_read(addr, value)
        except Exception as e:
            print(e)        

    def load_project(self, file):
        try:
            filePath =  "./saveproject/" + file + ".emu"
            if filePath is None:
                return
            with open(filePath, 'rb') as file:
                settings = pickle.load(file)
                self.set_context(pickle.load(file))
                file.close()

                uemu_log("Project loaded from %s" % filePath)
            reg_map = UEMU_HELPERS.get_register_map(self.arch_mode)
            self.context = [ [ row[0], hex(self.emu.reg_read(row[1])) ] for row in reg_map ]
            self.pc = self.emu.reg_read(self.uc_reg_pc)
        except Exception as e:
            print(e)


    def save_project(self):
        filePath = "./saveproject/" + hex(self.pc) + ".emu"
        if filePath is None:
            return
        with open(filePath, 'wb') as file:
            pickle.dump(self.settings, file, pickle.HIGHEST_PROTOCOL)
            pickle.dump(self.get_context(), file, pickle.HIGHEST_PROTOCOL)
            file.close()
            uemu_log("Project saved to %s" % filePath)

if __name__ == '__main__':

    filename = './binary/file.bin'
    regs = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

    # 
    segmentlist = [{'addr': 0x4000000, 'size': 0x10000, 'name': 'BOOTROM'}, 
    {'addr': 0x4010000, 'size': 0x10000, 'name': 'BOOTRAM'},
    {'addr': 0x4020000, 'size': 0x10000, 'name': 'on-chip RAM'}, 
    {'addr': 0x82000000, 'size': 0x4000000, 'name': 'firmware'},
    {'addr': 0x88000000, 'size': 0x400000, 'name': 'DDR'},
    {'addr': 0x88400000, 'size': 0xc00000, 'name': 'uncompress'}]

    Emu = Emulator(arch = 'armle')
    Emu.run_form(bin_name = filename, mem_map = 0x00, regs = regs, segments=segmentlist)
 
    while True:
        option = raw_input("#UC: ")
        if "checkthread" in option:
            print("[+] Thread status: ", Emu.checkThread())

        elif "write" in option:
            try:
                arg1 = int(option.split(" ")[1], 16)
                arg2 = option.split(" ")[2]
                arg2 = arg2.split(",")
                arg2.reverse()
                print(arg2)
                i = 0
                for c in arg2:
                    Emu.write_mem(arg1 + i, chr(int(c, 16)))
                    i = i + 1
                data = Emu.read_mem(arg1, 4)
                uemu_log("check value write: " + hex(data[0]) + " " + hex(data[1]) + " " + hex(data[2]) + " " + hex(data[3]))
            except Exception as e:
                print(e)
        elif "read" in option:
            try:
                arg1 = int(option.split(" ")[1], 16)
                data = Emu.read_mem(arg1, 4)
                uemu_log(hex(arg1)  + ": " + hex(data[0]) + " " + hex(data[1]) + " " + hex(data[2]) + " " + hex(data[3]))
            except Exception as e:
                print(e)
        elif "step" in option:
            if not Emu.is_active():
                uemu_log("Emulator is not active")
                continue
            if Emu.checkThread():
                uemu_log("Emulator is runing")
                continue

            pc = Emu.get_pc()
            Emu.step()
            print(Emu.get_cpu())
        elif "run" in option:
            if not Emu.is_active():
                    uemu_log("Emulator is not active")
                    continue
            if  Emu.is_running():
                uemu_log("Emulator is runing")
                continue

            try:
                arg1 = int(option.split(" ")[1], 16)
                arg2 = int(option.split(" ")[2], 16)
                Emu.thread_run(arg1, arg2)
            except Exception as e:
                print(e)

            print("[+] Thread status: ", Emu.checkThread())    
        elif "stop" in option:
            if not Emu.is_active():
                uemu_log("Emulator is not active")
                continue
            if not Emu.is_running():
                uemu_log("Emulator is not runing")
                continue

            Emu.interrupt()
        elif "context" in option:
            try:
                Emu.get_cpu()
            except Exception as e:
                print(e)
        elif "hexdump" in option:
            try:
                arg1 = int(option.split(" ")[1], 16)
                Emu.hexdump(arg1)
            except Exception as e:
                print(e)
        elif "dumpsegment" in option:
            try:
                arg1 = int(option.split(" ")[1], 16)
                arg2 = int(option.split(" ")[2], 16)
                Emu.segment_save_file(arg1, arg2)
            except Exception as e:
                print(e)
        elif "reset" in option:
            Emu.reset()
        elif "saveproject" in option:
            if Emu.checkThread() == 1:
                uemu_log("Emulator is runing")
                continue

            Emu.save_project()
        elif "loadproject" in option:
            if Emu.checkThread() == 1:
                uemu_log("Emulator is runing")
                continue

            Emu.load_project(option.split(" ")[1])
        elif "q" == option:
            Emu.reset()
            exit(0)
        else:
            pass