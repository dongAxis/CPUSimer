#pragma once

// memory address where emulation starts
#define ADDRESS 0x40000
#define STACK_ADDRESS 0x10000
//#define GOT_ADDRESS 0x10000
#define ENTRY_CODE_START 0x40000 + 0x3F4
#define ENTRY_CODE_END 0x40000 + 0x43C
#define GOT_PRINTF_ADDR
#define FAKE_GOT_ADDRESS 0x900000
#define FAKE_GOT_TOTAL_SIZE 1 * 1024 * 1024

// machine code
#define ARMV7_NOP 0x0000A0E1
