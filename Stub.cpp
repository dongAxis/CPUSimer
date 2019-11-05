#include "Stub.h"

namespace faker {

Status StubFunc::PrtinfStub(uc_engine *uc) {
    assert(uc != nullptr);

    // 1. read r0
    uint32_t r0;
    uc_reg_read(uc, UC_ARM_REG_R0, &r0);

    // 2. copy the format args to the host memory
    std::string fmtStr = "";
    uint32_t addr = r0;
    while(1) {
        char ch;
        uc_mem_read(uc, addr, &ch, sizeof(ch));

        if (ch > 127) {
            return Status(FAKER_READ_INVALID_CHAR, "read invalid char in printf");
        }

        if (ch == '\0') {
            break;
        }
        fmtStr += ch;
        addr++;
    }

    const char* ptr = (const char*)fmtStr.c_str();
    int ret = printf(ptr);

    // 3. write return value to r0
    uc_reg_write(uc, UC_ARM_REG_R0, &ret);

    return Status::OK();
}

} // namespace faker
