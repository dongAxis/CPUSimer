#include <string.h>
#include <unicorn/unicorn.h>
#include <capstone/capstone.h>
#include <capstone/platform.h>
#include "InstConstant.h"
#include "UnicornWrapper.h"
#include "Common.h"
#include <iostream>

using namespace faker;

Status runArm() {
    UnicornWrapper unicorn;
    FAKER_ENSURE(unicorn.init());
    FAKER_ENSURE(unicorn.prepareResource());
    FAKER_ENSURE(unicorn.start(ENTRY_CODE_START, ENTRY_CODE_END));
    return Status::OK();
}

int main(int argc, char **argv, char **envp) {
  Status status = runArm();
  std::cout << status.errorMsg() << std::endl;
  assert(status.isOK());
  return 0;
}
