#pragma once

#include <string>

#define FAKER_SUCCESS 0
#define FAKER_INIT_DISASSEMBLE_FAILED -1
#define FAKER_UC_IS_NULL -2
#define FAKER_WRONG_EXEC_MODE -3
#define FAKER_FAIL_TO_DISASSEMBLE -4
#define FAKER_FAIL_TO_INIT_UNICORN -5
#define FAKER_FAIL_TO_RUN_EMU -6
#define FAKER_READ_INVALID_CHAR -7

class Status {
public:
    Status(int ec, const std::string &em)
        : errorCode(ec)
        , errorMessage(em)
    {
    }

    // Status(const Status &right) = delete;
    // void operator=(const Status &right) = delete;
    
    const std::string &errorMsg() {
        return errorMessage;
    }

    int code() {
        return errorCode;
    }
    
    static const Status &OK() {
        static Status status = Status(0, "");
        return status;
    }
    
    bool isOK() {
        return errorCode == 0;
    }
    
private:
    int errorCode;
    std::string errorMessage;
};
