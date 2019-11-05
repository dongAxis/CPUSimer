#include "UnicornWrapper.h"
#include "InstConstant.h"
#include "assert.h"
#include "utils.h"
#include "Stub.h"
#include "Common.h"
#include <mutex>
#include <iostream>

namespace faker {

Disassemble *UnicornWrapper::_armMode = nullptr;
Disassemble *UnicornWrapper::_thumbMode = nullptr;
uc_engine *UnicornWrapper::_uc = nullptr;
static std::once_flag flag;

static void hook_code(uc_engine *uc, uint64_t address, uint32_t size,
                      void *user_data) {
  uint32_t tmp;
  uc_mem_read(uc, address, &tmp, sizeof(tmp));
  cs_insn *insn;

  if (size == 4) { // arm mode
      assert(UnicornWrapper::_armMode != nullptr);
      UnicornWrapper::_armMode->disassemble(address, size);
  } else if (size == 2) {
      assert(UnicornWrapper::_thumbMode != nullptr);
      UnicornWrapper::_thumbMode->disassemble(address, size);
  }
}

static void hookPrintf(uc_engine *uc, uint64_t address, uint32_t size,
                       void *user_data)
{
    // 0. dump regs
    Status status = Status::OK();
    #if 0
    status = dumpRegsInfo(uc);
    if (!status.isOK()) {
        std::cout << status.errorMsg() << std::endl;
        return;
    }
    #endif
    // 1. call stub function
    status = StubFunc::PrtinfStub(uc);
    if (!status.isOK()) {
      std::cout << status.errorMsg() << std::endl;
      return;
    }

    // 2. set pc
    // 2.1 read lr
    uint32_t lr = 0;
    uc_reg_read(uc, UC_ARM_REG_LR, &lr);
    // 2.2 write lr to pc
    uc_reg_write(uc, UC_ARM_REG_PC, &lr);
}

Status UnicornWrapper::patchPrintf(uint64_t targetFakeAddr) {
    uint64_t targetAbsAddr = ADDRESS + 0x1FFC;
    // 1. patch got 
    uc_mem_write(_uc, targetAbsAddr, (void*)&targetFakeAddr, 4);

    // 2. patch nop to fake target address
    uint32_t nopInst = ARMV7_NOP;
    uc_mem_write(_uc, targetFakeAddr, (void*)&nopInst, 4);

    return Status::OK();
}

Status UnicornWrapper::patchCode() {
    // 1. alloc fake function def memory
    uc_mem_map(UnicornWrapper::_uc, FAKE_GOT_ADDRESS, FAKE_GOT_TOTAL_SIZE, UC_PROT_ALL);

    uint32_t targetFakeAddress = FAKE_GOT_ADDRESS;
    // 2. patch printf
    patchPrintf(targetFakeAddress);
    func2Addrs["printf"] = targetFakeAddress;

    return Status::OK();
}

Status UnicornWrapper::prepareResource() {
    // 1. patch code (got table)
    patchCode();

    // 2. preapre jump memory

    // 3. hook code
    hookCode();

    // 4. hook basic block

    return Status::OK();
}

Status UnicornWrapper::hookCode() {
  uc_hook trace;
  uc_hook_add(_uc, &trace, UC_HOOK_CODE, (void *)hook_code, NULL,
              ENTRY_CODE_START, ENTRY_CODE_END);

  // 1. handle stub
  // 1.1 printf
  uint32_t printfAddr = func2Addrs["printf"];
  uc_hook_add(_uc, &trace, UC_HOOK_CODE, (void *)hookPrintf, NULL, printfAddr,
              printfAddr);

  return Status::OK();
}

Status UnicornWrapper::init() {
  Status status = Status::OK();
  std::call_once(flag, [&]() {
    uc_err err;
    err = uc_open(UC_ARCH_ARM, UC_MODE_ARM, &UnicornWrapper::_uc);
    if (err) {
      std::string errorMessage =
          "Failed on uc_open() with error returned: " + std::to_string(err) +
          " (" + uc_strerror(err) + ")";
      status = Status(FAKER_FAIL_TO_INIT_UNICORN, errorMessage);
      return;
    }

    // 1. alloc memory of emuator
    uc_mem_map(UnicornWrapper::_uc, ADDRESS, 8 * 1024 * 1024, UC_PROT_ALL);
    uc_mem_map(UnicornWrapper::_uc, STACK_ADDRESS, 1 * 1024 * 1024, UC_PROT_ALL);

    // 2. map elf to qmeu memory
    uint32_t len = 0;
    unsigned char *code = readFile("./target_libs/arm_renter_shared", &len);
    uc_mem_write(UnicornWrapper::_uc, ADDRESS, code, len);
    free(code);

    // 3. map stack address to qemu memory
    int32_t sp = STACK_ADDRESS + 8 * 1024 * 1024;
    uc_reg_write(_uc, UC_ARM_REG_SP, &sp);

    // 3. init disassemble
    UnicornWrapper::_armMode = new Disassemble(UnicornWrapper::_uc);
    assert(UnicornWrapper::_armMode != nullptr);
    UnicornWrapper::_armMode->init();

    UnicornWrapper::_thumbMode = new Disassemble(UnicornWrapper::_uc, true);
    UnicornWrapper::_thumbMode->init();

    status = Status::OK();
  });

  return status;
}

Status UnicornWrapper::start(uint64_t codeStart, uint64_t codeEnd) {
  uc_err err = uc_emu_start(UnicornWrapper::_uc, codeStart, codeEnd, 0, 0);
  if (err) {
    printf("%s", uc_strerror(err));
    return Status(FAKER_FAIL_TO_RUN_EMU, "Failed on uc_emu_start() with error");
  }
  return Status::OK();
}

Status UnicornWrapper::finish() {
    uc_close(_uc);
    if (_armMode) {
        delete _armMode;
        _armMode = nullptr;
    }

    if (_thumbMode) {
        delete _thumbMode;
        _thumbMode = nullptr;
    }

    return Status::OK();
}

}
/*
void UnicornWrapper::monitorBlock(uc_engine *uc, uint64_t address,
                                  uint32_t size, void *user_data) {
  uint32_t r0, r1, r2, r3, r4, r5, r6, r7;
  uc_reg_read(uc, UC_ARM_REG_R0, &r0);
  uc_reg_read(uc, UC_ARM_REG_R1, &r1);
  uc_reg_read(uc, UC_ARM_REG_R2, &r2);
  uc_reg_read(uc, UC_ARM_REG_R3, &r3);
  uc_reg_read(uc, UC_ARM_REG_R4, &r4);
  uc_reg_read(uc, UC_ARM_REG_R5, &r5);
  uc_reg_read(uc, UC_ARM_REG_R6, &r6);
  uc_reg_read(uc, UC_ARM_REG_R7, &r7);
  printf(">>> R0 = 0x%x\n", r0);
  printf(">>> R1 = 0x%x\n", r1);
  printf(">>> R2 = 0x%x\n", r2);
  printf(">>> R3 = 0x%x\n", r3);
  printf(">>> R4 = 0x%x\n", r4);
  printf(">>> R5 = 0x%x\n", r5);
  printf(">>> R6 = 0x%x\n", r6);
  printf(">>> R7 = 0x%x\n", r7);
  uint32_t sp;
  uc_reg_read(uc, UC_ARM_REG_SP, &sp);
  printf(">>> SP = 0x%x\n", sp);
}

void UnicornWrapper::monitorCode(uc_engine *uc, uint64_t address, uint32_t size,
                                 void *user_data)
{
  return;
  }*/
