#include <capstone/capstone.h>
#include <capstone/platform.h>

namespace faker {

class Disassemble {
public:
    Disassemble(uc_engine *uc, bool isThumb = false)
      : isThumb(isThumb)
      , uc(uc)
    {
    }

  Status init() {
    cs_mode mode = CS_MODE_ARM;
    if (isThumb) {
      mode = CS_MODE_THUMB;
    }
    cs_err cerr = cs_open(CS_ARCH_ARM, mode, &handle);
    if (cerr) {
        std::string log = "Failed on cs_open() with error returned: " + std::to_string(cerr);
      return Status(FAKER_INIT_DISASSEMBLE_FAILED, log);
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    return Status::OK();
  }

  Status disassemble(uint64_t address, uint32_t size) {
    cs_insn *insn;
    if (size == 2 && !isThumb) {
      return Status(FAKER_WRONG_EXEC_MODE, "failed");
    } else if (size == 4 && isThumb) {
      return Status(FAKER_WRONG_EXEC_MODE, "failed");
    }

    uint32_t code;
    uc_mem_read(uc, address, &code, sizeof(code));

    size_t count =
        cs_disasm(handle, (const uint8_t *)&code, size, address, 0, &insn);
    if (count) {
      for (int j = 0; j < count; j++) {
        printf("0x%" PRIx64 ":\t%s\t%s\n", insn[j].address, insn[j].mnemonic,
               insn[j].op_str);
      }
    } else {
      return Status(FAKER_FAIL_TO_DISASSEMBLE, "failed to disassemble");
    }
    return Status::OK();
  }

private:
  csh handle;
  bool isThumb;
  uc_engine *uc;
};

} // namespace faker
