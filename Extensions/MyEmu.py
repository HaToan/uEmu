# uEmu
from unicorn.arm_const import *
from uEmu import *

MYEMU_USE_AS_SCRIPT = True    # Set to `False` if you want to load MyEmu automatically as IDA Plugin

def myemu_log(entry):
    uemu_log(entry, name = "MyEmu")
    
class MyEmuPlugin(uEmuPlugin):

    ### uEmuPlugin methods override

    def __init__(self):
        hooks = uEmuExtensionHooks()
        hooks.init_context = self.hook_init_context
        hooks.trace_log = self.hook_trace_log
        hooks.emu_step = self.hook_emu_step
        hooks.instruction_exception = self.hook_instruction_exception

        super(MyEmuPlugin, self).__init__("MyEmu", hooks)

    def add_custom_menu(self):
        self.MENU_ITEMS.append(UEMU_HELPERS.MenuItem(self.plugin_name + ":myemu_test", self.myemu_test,  "MyEmu",  "MyEmu",  None,  True  ))
        self.MENU_ITEMS.append(UEMU_HELPERS.MenuItem("-",                              self.do_nothing,  "",       None,     None,  True  ))

    def update_context(self, address, context):
        super(MyEmuPlugin, self).update_context(address, context)
        myemu_log("MyEmu update context")

    def close_windows(self):
        super(MyEmuPlugin, self).close_windows()
        myemu_log("MyEmu close windows")

    ### uEmuUnicornEngine hooks 

    def hook_init_context(self):
        myemu_log("MyEmu context init")

        # return False to let uEmu init context, True otherwise
        return False

    def hook_trace_log(self, pc):
        bytes = IDAAPI_GetBytes(pc, IDAAPI_NextHead(pc) - pc)
        bytes_hex = UEMU_HELPERS.bytes_to_str(bytes)
        myemu_log("* MYTRACE<I> 0x%X | %-16s | %s" % (pc, bytes_hex, IDAAPI_GetDisasm(pc, 0)))

        # return False to let uEmu output its own trace log, True otherwise
        return True

    def hook_emu_step(self, pc):
        myemu_log("MyEmu emulation step")
        
        # return False to let uEmu execute next instruction, True otherwise
        return False
    
    def hook_instruction_exception(self, pc):
        # addr syscall or addr instruction
        myemu_log("Emulator  at addr 0x%X" % pc)
        addr_emu = 0x4C

        if( pc == addr_emu):
            myemu_log("Emulator  function, instruction, syscall")
            R0 = self.unicornEngine.mu.reg_read(UC_ARM_REG_R0)
            R1 = self.unicornEngine.mu.reg_read(UC_ARM_REG_R1)
            myemu_log("Get Param R0: " + hex(R0))
            myemu_log("Get Param R0: " + hex(R1))
            
            # read memory
            R0_value = self.unicornEngine.mu.mem_read(R0, 4)
            myemu_log("Read Memory 4byte: 0x%X" % int.from_bytes(R0_value, 'little'))

            # write memory
            myemu_log("Write Memory : 0x%X - 0x%X" % (R1, 0x1234))
            self.unicornEngine.mu.mem_write(R1, b'\x34\x12')
            
            # return True
            self.unicornEngine.mu.reg_write(UC_ARM_REG_R0, 1)
            
        return True

    ### MyEmuPlugin methods

    def myemu_test(self):
        myemu_log("MyEmu menu click")

def PLUGIN_ENTRY():
    return MyEmuPlugin()

if MYEMU_USE_AS_SCRIPT:
    if __name__ == '__main__':
        MyEmu = MyEmuPlugin()
        MyEmu.init()
        MyEmu.run()

