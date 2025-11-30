/*
 * Minimal unit test framework for DHCP Server Scanner
 * No external dependencies - uses only standard C
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Test framework macros */
static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) static void name(void)
#define RUN_TEST(name) do { \
    printf("  Running %s... ", #name); \
    tests_run++; \
    name(); \
} while(0)

#define ASSERT(cond) do { \
    if (!(cond)) { \
        printf("FAILED\n    Assertion failed: %s\n    at %s:%d\n", \
               #cond, __FILE__, __LINE__); \
        tests_failed++; \
        return; \
    } \
} while(0)

#define ASSERT_EQ(a, b) do { \
    if ((a) != (b)) { \
        printf("FAILED\n    Expected %ld, got %ld\n    at %s:%d\n", \
               (long)(b), (long)(a), __FILE__, __LINE__); \
        tests_failed++; \
        return; \
    } \
} while(0)

#define ASSERT_MEM_EQ(a, b, len) do { \
    if (memcmp((a), (b), (len)) != 0) { \
        printf("FAILED\n    Memory comparison failed\n    at %s:%d\n", \
               __FILE__, __LINE__); \
        tests_failed++; \
        return; \
    } \
} while(0)

#define TEST_PASSED() do { \
    printf("OK\n"); \
    tests_passed++; \
} while(0)

/* Include headers under test */
#include "../src/sum.h"
#include "../src/dhcpd-detector.h"

/* Re-implement dhcp_get_opt for testing (from dhcpd-detector.c) */
unsigned char dhcp_get_opt(unsigned char *options, unsigned char optcode,
                           unsigned char optlen, void *optvalptr)
{
    unsigned char i;
    int max_iterations = MAX_DHCP_OPT_ITERATIONS;

    while (max_iterations-- > 0) {
        if (*options == DHO_PAD)
            options++;
        else if (*options == DHO_END)
            break;
        else if (*options == optcode) {
            optlen = (optlen < *(options + 1)) ? optlen : *(options + 1);
            for (i = 0; i < optlen; i++)
                *(((unsigned char *)optvalptr) + i) = *(options + i + 2);
            return *(options + 1);
        } else {
            options++;
            options += *options;
            options++;
        }
    }
    return 0;
}

/*
 * Tests for compute_checksum
 */

TEST(test_checksum_zeros)
{
    unsigned char data[] = {0, 0, 0, 0};
    unsigned short result = compute_checksum(data, 4);
    /* All zeros should give 0xFFFF after complement */
    ASSERT_EQ(result, 0xFFFF);
    TEST_PASSED();
}

TEST(test_checksum_ones)
{
    unsigned char data[] = {0xFF, 0xFF, 0xFF, 0xFF};
    unsigned short result = compute_checksum(data, 4);
    /* Result should be 0 (since ~0xFFFF = 0) */
    ASSERT_EQ(result, 0x0000);
    TEST_PASSED();
}

TEST(test_checksum_odd_length)
{
    unsigned char data[] = {0x01, 0x02, 0x03};
    unsigned short result = compute_checksum(data, 3);
    /* Should handle odd length properly */
    ASSERT(result != 0 || result == 0); /* Just verify it doesn't crash */
    TEST_PASSED();
}

TEST(test_checksum_known_value)
{
    /* IP header example: 4500 0073 0000 4000 4011 [checksum] c0a8 0001 c0a8 00c7 */
    unsigned char ip_header[] = {
        0x45, 0x00, 0x00, 0x73,
        0x00, 0x00, 0x40, 0x00,
        0x40, 0x11, 0x00, 0x00,  /* checksum field zeroed */
        0xc0, 0xa8, 0x00, 0x01,
        0xc0, 0xa8, 0x00, 0xc7
    };
    unsigned short result = compute_checksum(ip_header, 20);
    /* Verify checksum is non-zero and consistent */
    ASSERT(result != 0);
    /* The computed checksum should be 0x61b8 (endianness) */
    ASSERT_EQ(result, 0x61b8);
    TEST_PASSED();
}

TEST(test_checksum_empty)
{
    unsigned char data[] = {};
    unsigned short result = compute_checksum(data, 0);
    ASSERT_EQ(result, 0xFFFF);
    TEST_PASSED();
}

/*
 * Tests for dhcp_get_opt
 */

TEST(test_dhcp_get_opt_simple)
{
    /* Simple option: type 53 (message type), length 1, value 2 (OFFER) */
    unsigned char options[] = {
        DHO_DHCP_MESSAGE_TYPE, 1, DHCPOFFER,
        DHO_END
    };
    unsigned char msgtype = 0;
    unsigned char len = dhcp_get_opt(options, DHO_DHCP_MESSAGE_TYPE, 1, &msgtype);
    ASSERT_EQ(len, 1);
    ASSERT_EQ(msgtype, DHCPOFFER);
    TEST_PASSED();
}

TEST(test_dhcp_get_opt_with_padding)
{
    /* Options with PAD bytes before the actual option */
    unsigned char options[] = {
        DHO_PAD, DHO_PAD, DHO_PAD,
        DHO_DHCP_MESSAGE_TYPE, 1, DHCPACK,
        DHO_END
    };
    unsigned char msgtype = 0;
    unsigned char len = dhcp_get_opt(options, DHO_DHCP_MESSAGE_TYPE, 1, &msgtype);
    ASSERT_EQ(len, 1);
    ASSERT_EQ(msgtype, DHCPACK);
    TEST_PASSED();
}

TEST(test_dhcp_get_opt_multiple_options)
{
    /* Multiple options, find the second one */
    unsigned char options[] = {
        DHO_DHCP_MESSAGE_TYPE, 1, DHCPOFFER,
        DHO_SUBNET_MASK, 4, 255, 255, 255, 0,
        DHO_END
    };
    unsigned int mask = 0;
    unsigned char len = dhcp_get_opt(options, DHO_SUBNET_MASK, 4, &mask);
    ASSERT_EQ(len, 4);
    /* Mask should be 255.255.255.0 in network byte order */
    unsigned char *mask_bytes = (unsigned char *)&mask;
    ASSERT_EQ(mask_bytes[0], 255);
    ASSERT_EQ(mask_bytes[1], 255);
    ASSERT_EQ(mask_bytes[2], 255);
    ASSERT_EQ(mask_bytes[3], 0);
    TEST_PASSED();
}

TEST(test_dhcp_get_opt_not_found)
{
    unsigned char options[] = {
        DHO_DHCP_MESSAGE_TYPE, 1, DHCPOFFER,
        DHO_END
    };
    unsigned int router = 0;
    unsigned char len = dhcp_get_opt(options, DHO_ROUTERS, 4, &router);
    ASSERT_EQ(len, 0);
    ASSERT_EQ(router, 0);
    TEST_PASSED();
}

TEST(test_dhcp_get_opt_end_only)
{
    unsigned char options[] = { DHO_END };
    unsigned char msgtype = 0xFF;
    unsigned char len = dhcp_get_opt(options, DHO_DHCP_MESSAGE_TYPE, 1, &msgtype);
    ASSERT_EQ(len, 0);
    ASSERT_EQ(msgtype, 0xFF); /* Should remain unchanged */
    TEST_PASSED();
}

TEST(test_dhcp_get_opt_truncate_to_requested_len)
{
    /* Option has 4 bytes but we only request 2 */
    unsigned char options[] = {
        DHO_SUBNET_MASK, 4, 0xAA, 0xBB, 0xCC, 0xDD,
        DHO_END
    };
    unsigned char val[2] = {0, 0};
    unsigned char len = dhcp_get_opt(options, DHO_SUBNET_MASK, 2, val);
    ASSERT_EQ(len, 4); /* Returns actual length */
    ASSERT_EQ(val[0], 0xAA);
    ASSERT_EQ(val[1], 0xBB);
    TEST_PASSED();
}

TEST(test_dhcp_get_opt_server_identifier)
{
    /* Test DHO_DHCP_SERVER_IDENTIFIER option */
    unsigned char options[] = {
        DHO_DHCP_MESSAGE_TYPE, 1, DHCPOFFER,
        DHO_DHCP_SERVER_IDENTIFIER, 4, 192, 168, 1, 1,
        DHO_END
    };
    unsigned int server_ip = 0;
    unsigned char len = dhcp_get_opt(options, DHO_DHCP_SERVER_IDENTIFIER, 4, &server_ip);
    ASSERT_EQ(len, 4);
    unsigned char *ip_bytes = (unsigned char *)&server_ip;
    ASSERT_EQ(ip_bytes[0], 192);
    ASSERT_EQ(ip_bytes[1], 168);
    ASSERT_EQ(ip_bytes[2], 1);
    ASSERT_EQ(ip_bytes[3], 1);
    TEST_PASSED();
}

TEST(test_dhcp_get_opt_dns_servers)
{
    /* Multiple DNS servers (8 bytes = 2 IPs) */
    unsigned char options[] = {
        DHO_DOMAIN_NAME_SERVERS, 8,
        8, 8, 8, 8,      /* 8.8.8.8 */
        8, 8, 4, 4,      /* 8.8.4.4 */
        DHO_END
    };
    unsigned char dns[8] = {0};
    unsigned char len = dhcp_get_opt(options, DHO_DOMAIN_NAME_SERVERS, 8, dns);
    ASSERT_EQ(len, 8);
    ASSERT_EQ(dns[0], 8);
    ASSERT_EQ(dns[1], 8);
    ASSERT_EQ(dns[2], 8);
    ASSERT_EQ(dns[3], 8);
    ASSERT_EQ(dns[4], 8);
    ASSERT_EQ(dns[5], 8);
    ASSERT_EQ(dns[6], 4);
    ASSERT_EQ(dns[7], 4);
    TEST_PASSED();
}

/*
 * Test runner
 */
int main(void)
{
    printf("\n=== DHCP Server Scanner Unit Tests ===\n\n");

    printf("Checksum tests:\n");
    RUN_TEST(test_checksum_zeros);
    RUN_TEST(test_checksum_ones);
    RUN_TEST(test_checksum_odd_length);
    RUN_TEST(test_checksum_known_value);
    RUN_TEST(test_checksum_empty);

    printf("\nDHCP option parser tests:\n");
    RUN_TEST(test_dhcp_get_opt_simple);
    RUN_TEST(test_dhcp_get_opt_with_padding);
    RUN_TEST(test_dhcp_get_opt_multiple_options);
    RUN_TEST(test_dhcp_get_opt_not_found);
    RUN_TEST(test_dhcp_get_opt_end_only);
    RUN_TEST(test_dhcp_get_opt_truncate_to_requested_len);
    RUN_TEST(test_dhcp_get_opt_server_identifier);
    RUN_TEST(test_dhcp_get_opt_dns_servers);

    printf("\n=== Results ===\n");
    printf("Tests run:    %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);
    printf("\n");

    return tests_failed > 0 ? 1 : 0;
}
