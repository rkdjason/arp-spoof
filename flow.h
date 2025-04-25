#pragma once

#include <stdint.h>
#include <map>
#include "ip.h"
#include "mac.h"

#define MAX_FLOWS 64

typedef struct {
    Mac s_mac;
    Ip s_ip;
    Mac t_mac;
    Ip t_ip;
} Flow;
