/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/*
 * ping: ICMP echo from the device.
 *   ping_host  ping a host name or IP address 1-10 times (default 4)
 * Waiting for replies is host time and does not count against the call budget.
 */
#define CLAW_ARENA_SIZE 1024
#include "claw.h"
#include "claw_util.h"

CLAW_DEFINE_ARENA()

static int32_t s_host = -1;

CLAW_EXPORT("app_init") void app_init(void)
{
    s_host = CLAW_REGISTER("host", "Ping a host name or IP address from the device (ICMP echo) and report "
                           "replies and round-trip times. Useful to check whether a LAN device or server is up.",
                           "{\"type\":\"object\",\"properties\":{\"host\":{\"type\":\"string\","
                           "\"description\":\"Host name, IPv4 or IPv6 address\"},"
                           "\"count\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":10,"
                           "\"description\":\"Echo requests to send (default 4)\"}},\"required\":[\"host\"]}");
}

static void tool_host(const char *args, const char *end)
{
    char host[254];
    char out[256];
    int32_t host_len = cj_string(cj_member(args, end, "host"), end, host, sizeof(host));
    int64_t count = cj_uint(cj_member(args, end, "count"), end);
    int32_t rc;

    if (host_len <= 0) {
        CLAW_RESULT("{\"error\":\"host is required\"}");
        return;
    }
    rc = claw_ping(host, (uint32_t)host_len, count < 1 || count > 10 ? 4 : (int32_t)count, out, sizeof(out));
    if (rc == -CLAW_ENOENT) {
        CLAW_RESULT("{\"error\":\"unknown host\"}");
    } else if (rc == -CLAW_EINVAL) {
        CLAW_RESULT("{\"error\":\"host must be a host name or IP address\"}");
    } else if (rc < 0) {
        CLAW_RESULT("{\"error\":\"ping failed\"}");
    } else {
        claw_tool_result(out, (uint32_t)rc);
    }
}

CLAW_EXPORT("tool_call") int32_t tool_call(int32_t tool, const char *args, uint32_t len)
{
    if (tool != s_host) {
        return -1;
    }
    tool_host(args, args + len);
    return 0;
}
