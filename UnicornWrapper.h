#pragma once

#include <string.h>
#include <unicorn/unicorn.h>
#include <capstone/capstone.h>
#include <capstone/platform.h>
#include <map>
#include "Status.h"
#include "Disassemble.h"

namespace faker {

class UnicornWrapper {
public:
  UnicornWrapper() {}
  ~UnicornWrapper() { finish(); }

  Status init();
  Status prepareResource();
  Status start(uint64_t codeStart, uint64_t codeEnd);
private:
    Status finish();
    Status hookCode();
    Status patchCode();
    Status patchPrintf(uint64_t targetFakeAddr);
public:
    static uc_engine *_uc;
    static Disassemble *_armMode;
    static Disassemble *_thumbMode;
private:
    std::map<std::string, uint32_t> func2Addrs;
};

}
