/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>

#include "esp_log.h"
#include "lwip/netdb.h"
#include "lwip/sockets.h"

static const char *TAG = "cap_ssh";

int __real_getnameinfo(const struct sockaddr *addr, socklen_t addrlen,
                       char *host, socklen_t hostlen,
                       char *serv, socklen_t servlen, int flags);

/* libssh calls getnameinfo(NI_NUMERICHOST | NI_NUMERICSERV) before connect(); the sock_utils
 * implementation only handles AF_INET, so AF_INET6 results from getaddrinfo() are handled here. */
int __wrap_getnameinfo(const struct sockaddr *addr, socklen_t addrlen,
                       char *host, socklen_t hostlen,
                       char *serv, socklen_t servlen, int flags)
{
    const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;
    int rc;

    if (!addr || addr->sa_family != AF_INET6) {
        rc = __real_getnameinfo(addr, addrlen, host, hostlen, serv, servlen, flags);
        if (rc != 0) {
            ESP_LOGW(TAG, "getnameinfo failed: rc=%d family=%d addrlen=%u flags=0x%x",
                     rc, addr ? addr->sa_family : -1, (unsigned)addrlen, flags);
        }
        return rc;
    }
    if ((flags & NI_NUMERICHOST) && host && hostlen > 0 &&
            !inet_ntop(AF_INET6, &sin6->sin6_addr, host, hostlen)) {
        return EAI_FAIL;
    }
    if ((flags & NI_NUMERICSERV) && serv && servlen > 0) {
        snprintf(serv, servlen, "%u", (unsigned)ntohs(sin6->sin6_port));
    }
    return 0;
}
