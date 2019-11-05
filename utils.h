#pragma once

#include <unicorn/unicorn.h>
#include <capstone/capstone.h>
#include <capstone/platform.h>
#include "Status.h"

namespace faker {

Status dumpRegsInfo(uc_engine *uc) {
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

  return Status::OK();
}

unsigned char *readFile(const char *path, uint32_t *len) {
  FILE *fp = fopen(path, "rb");
  if (fp == NULL)
    return NULL;
  fseek(fp, 0, SEEK_END);
  *len = ftell(fp);
  fseek(fp, 0, SEEK_SET);
  unsigned char *code = (unsigned char *)malloc(*len);
  memset(code, 0, *len);
  fread(code, 1, *len, fp);
  fclose(fp);
  return code;
}

}
