/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>

#include "lwip/netdb.h"
#include "lwip/sockets.h"

/* libssh calls getnameinfo(NI_NUMERICHOST | NI_NUMERICSERV) before connect(), with lwIP's NI_*
 * values. sock_utils' getnameinfo() checks the flags against its own, different NI_* values and
 * returns EAI_BADFLAGS, so libssh fails with "getnameinfo failed: Success". There is no reverse
 * lookup on ESP-IDF anyway: always return the numeric host and port. */
int __wrap_getnameinfo(const struct sockaddr *addr, socklen_t addrlen,
                       char *host, socklen_t hostlen,
                       char *serv, socklen_t servlen, int flags)
{
    const void *ip;
    unsigned port;

    if (!addr) {
        return EAI_FAIL;
    }
    if (addr->sa_family == AF_INET && addrlen >= sizeof(struct sockaddr_in)) {
        ip = &((const struct sockaddr_in *)addr)->sin_addr;
        port = ntohs(((const struct sockaddr_in *)addr)->sin_port);
    } else if (addr->sa_family == AF_INET6 && addrlen >= sizeof(struct sockaddr_in6)) {
        ip = &((const struct sockaddr_in6 *)addr)->sin6_addr;
        port = ntohs(((const struct sockaddr_in6 *)addr)->sin6_port);
    } else {
        return EAI_FAMILY;
    }
    if (host && hostlen > 0 && !inet_ntop(addr->sa_family, ip, host, hostlen)) {
        return EAI_FAIL;
    }
    if (serv && servlen > 0) {
        snprintf(serv, servlen, "%u", port);
    }
    return 0;
}
