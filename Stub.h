#pragma once

#include "Status.h"
#include <unicorn/unicorn.h>
#include <capstone/capstone.h>
#include <capstone/platform.h>

namespace faker {

class StubFunc {
public:
    static Status PrtinfStub(uc_engine *uc);
};

}
