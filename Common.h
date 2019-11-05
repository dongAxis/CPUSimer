#pragma once

#include "Status.h"

#define FAKER_ENSURE(x)                                                        \
  {                                                                            \
    Status retStatus = x;                                                      \
    if (!retStatus.isOK()) {                                                   \
      return retStatus;                                                        \
    }                                                                          \
  }
