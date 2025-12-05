/**
 * @file test_vlan_lacp.c
 * @brief Test and simulation for VLAN and LACP interface fetchers
 */

#include "interface.h"
#include "vlan.h"
#include "lacp.h"
#include "packet.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#ifdef HAVE_DPDK
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#endif

#define TEST_PASS() printf("  [PASS] %s\n", __func__)
#define TEST_FAIL() do { printf("  [FAIL] %s at line %d\n", __func__, __LINE__); exit(1); } while(0)

/* Test counters */
static int tests_passed = 0;
static int tests_total = 0;

#define TEST_START(name) \
    do { \
        printf("\n=== %s ===\n", name); \
        tests_total++; \
    } while(0)

#define TEST_END() \
    do { \
        tests_passed++; \
        printf("  [PASS] Test completed\n"); \
    } while(0)

/**
 * Test 1: VLAN Interface Creation
 */
void test_vlan_interface_creation(void)
{
    TEST_START("Test 1: VLAN Interface Creation");

    /* Create parent physical interface */
    struct interface *parent = interface_create("eth0", IF_TYPE_PHYSICAL);
    assert(parent != NULL);
    printf("  Created parent interface: %s\n", parent->name);

    /* Create VLAN sub-interface */
    struct interface *vlan = interface_create("eth0.100", IF_TYPE_VLAN);
    assert(vlan != NULL);
    assert(vlan->type == IF_TYPE_VLAN);
    printf("  Created VLAN interface: %s (type: %s)\n",
           vlan->name, interface_type_to_str(vlan->type));

    /* Configure VLAN */
    struct interface_config_data config = vlan->config;
    config.vlan_id = 100;
    config.parent_ifindex = parent->ifindex;

    int ret = interface_configure(vlan, &config);
    assert(ret == 0);
    (void)ret;  /* Suppress warning */
    printf("  Configured VLAN ID: %u, Parent: %s\n",
           config.vlan_id, parent->name);

    /* Cleanup */
    interface_delete(vlan);
    interface_delete(parent);

    TEST_END();
}

/**
 * Test 2: VLAN ID Validation
 */
void test_vlan_id_validation(void)
{
    TEST_START("Test 2: VLAN ID Validation");

    /* Test valid VLAN IDs */
    assert(vlan_id_is_valid(1) == true);
    assert(vlan_id_is_valid(100) == true);
    assert(vlan_id_is_valid(4094) == true);
    printf("  Valid VLAN IDs: 1, 100, 4094 - OK\n");

    /* Test invalid VLAN IDs */
    assert(vlan_id_is_valid(0) == false);
    assert(vlan_id_is_valid(4095) == false);
    assert(vlan_id_is_valid(5000) == false);
    printf("  Invalid VLAN IDs: 0, 4095, 5000 - OK\n");

    TEST_END();
}

/**
 * Test 3: LACP Bond Creation
 */
void test_lacp_bond_creation(void)
{
    TEST_START("Test 3: LACP Bond Creation");

    /* Initialize LACP subsystem */
    int ret = lacp_init();
    assert(ret == 0);
    (void)ret;  /* Suppress warning */
    printf("  LACP subsystem initialized\n");

    /* Create bond interface */
    struct bond_interface *bond = bond_create("bond0", BOND_MODE_BALANCE_XOR);
    assert(bond != NULL);
    assert(bond->mode == BOND_MODE_BALANCE_XOR);
    assert(bond->num_ports == 0);
    (void)bond;  /* Suppress warning */
    printf("  Created bond interface: bond0 (mode: BALANCE_XOR)\n");

    /* Cleanup */
    lacp_cleanup();

    TEST_END();
}

/**
 * Test 4: LACP Bond Member Management
 */
void test_lacp_bond_members(void)
{
    TEST_START("Test 4: LACP Bond Member Management");

    /* Initialize LACP */
    lacp_init();

    /* Create bond interface */
    struct bond_interface *bond = bond_create("bond1", BOND_MODE_802_3AD);
    assert(bond != NULL);
    printf("  Created bond interface: bond1 (mode: 802.3AD)\n");

    /* Create member interfaces */
    struct interface *eth1 = interface_create("eth1", IF_TYPE_PHYSICAL);
    struct interface *eth2 = interface_create("eth2", IF_TYPE_PHYSICAL);
    assert(eth1 != NULL && eth2 != NULL);
    printf("  Created member interfaces: eth1, eth2\n");

    /* Add members to bond */
    int ret = bond_add_member(bond, eth1);
    assert(ret == 0);
    assert(bond->num_ports == 1);
    printf("  Added eth1 to bond (members: %u)\n", bond->num_ports);

    ret = bond_add_member(bond, eth2);
    assert(ret == 0);
    assert(bond->num_ports == 2);
    printf("  Added eth2 to bond (members: %u)\n", bond->num_ports);

    /* Remove member */
    ret = bond_remove_member(bond, eth1);
    assert(ret == 0);
    (void)ret;  /* Suppress warning */
    assert(bond->num_ports == 1);
    printf("  Removed eth1 from bond (members: %u)\n", bond->num_ports);

    /* Cleanup */
    interface_delete(eth1);
    interface_delete(eth2);
    lacp_cleanup();

    TEST_END();
}

/**
 * Test 5: LACP Bonding Modes
 */
void test_lacp_bonding_modes(void)
{
    TEST_START("Test 5: LACP Bonding Modes");

    lacp_init();

    /* Test all bonding modes */
    const char *mode_names[] = {
        "Active-Backup",
        "Balance Round-Robin",
        "Balance XOR",
        "802.3ad LACP",
        "Balance TLB",
        "Balance ALB"
    };

    for (int i = 0; i < 6; i++) {
        struct bond_interface *bond = bond_create("test_bond", i);
        assert(bond != NULL);
        assert(bond->mode == i);
        (void)bond;  /* Suppress warning */
        printf("  Mode %d (%s): OK\n", i, mode_names[i]);
    }

    lacp_cleanup();

    TEST_END();
}

/**
 * Test 6: LACP Load Balancing Hash
 */
void test_lacp_load_balancing(void)
{
    TEST_START("Test 6: LACP Load Balancing Hash");

    lacp_init();

    /* Create a simple packet buffer */
    struct pkt_buf pkt;
    memset(&pkt, 0, sizeof(pkt));

    /* Simulate packet metadata */
    pkt.meta.l2_offset = 0;
    pkt.meta.l3_offset = 14;
    pkt.meta.l3_type = PKT_L3_IPV4;
    pkt.meta.src_ip = 0xC0A80101;  /* 192.168.1.1 */
    pkt.meta.dst_ip = 0xC0A80102;  /* 192.168.1.2 */
    pkt.meta.flow_hash = 0x12345678;

    /* Test Layer 2 hash */
    uint32_t hash_l2 = bond_hash_packet(&pkt, BOND_XMIT_POLICY_LAYER2);
    printf("  Layer 2 hash: 0x%08x\n", hash_l2);

    /* Test Layer 3+4 hash (uses flow_hash) */
    uint32_t hash_l34 = bond_hash_packet(&pkt, BOND_XMIT_POLICY_LAYER34);
    printf("  Layer 3+4 hash: 0x%08x\n", hash_l34);
    assert(hash_l34 == pkt.meta.flow_hash);  /* Should use cached flow hash */

    lacp_cleanup();

    TEST_END();
}

/**
 * Test 7: LACP Member Selection
 */
void test_lacp_member_selection(void)
{
    TEST_START("Test 7: LACP Member Selection");

    lacp_init();

    /* Create bond with 3 members */
    struct bond_interface *bond = bond_create("bond_select", BOND_MODE_BALANCE_XOR);

    struct interface *eth1 = interface_create("eth1", IF_TYPE_PHYSICAL);
    struct interface *eth2 = interface_create("eth2", IF_TYPE_PHYSICAL);
    struct interface *eth3 = interface_create("eth3", IF_TYPE_PHYSICAL);

    /* Bring interfaces UP */
    interface_up(eth1);
    interface_up(eth2);
    interface_up(eth3);

    bond_add_member(bond, eth1);
    bond_add_member(bond, eth2);
    bond_add_member(bond, eth3);

    printf("  Created bond with 3 UP members\n");

    /* Create packet with different flow hashes */
    struct pkt_buf pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.meta.flow_hash = 100;

    /* Select member based on hash */
    struct interface *selected = bond_select_tx_member(bond, &pkt);
    assert(selected != NULL);
    assert(selected->state == IF_STATE_UP);
    printf("  Selected member for hash 100: %s\n", selected->name);

    /* Test with different hash */
    pkt.meta.flow_hash = 250;
    selected = bond_select_tx_member(bond, &pkt);
    assert(selected != NULL);
    printf("  Selected member for hash 250: %s\n", selected->name);

    /* Cleanup */
    interface_delete(eth1);
    interface_delete(eth2);
    interface_delete(eth3);
    lacp_cleanup();

    TEST_END();
}

/**
 * Test 8: Dummy Interface Creation
 */
void test_dummy_interface(void)
{
    TEST_START("Test 8: Dummy Interface Creation");

    /* Create dummy interface */
    struct interface *dummy = interface_create("dummy0", IF_TYPE_DUMMY);
    assert(dummy != NULL);
    assert(dummy->type == IF_TYPE_DUMMY);
    printf("  Created dummy interface: %s (type: %s)\n",
           dummy->name, interface_type_to_str(dummy->type));

    /* Dummy should start UP */
    assert(dummy->state == IF_STATE_UP);
    printf("  Dummy interface state: %s\n",
           interface_state_to_str(dummy->state));

    /* Link should be UP */
    enum link_state link = interface_get_link_state(dummy);
    assert(link == LINK_STATE_UP);
    printf("  Dummy interface link: %s\n", link_state_to_str(link));

    /* Create multiple dummy interfaces */
    struct interface *dummy1 = interface_create("dummy1", IF_TYPE_DUMMY);
    struct interface *dummy2 = interface_create("dummy2", IF_TYPE_DUMMY);
    assert(dummy1 != NULL && dummy2 != NULL);
    printf("  Created multiple dummy interfaces: dummy1, dummy2\n");

    /* Cleanup */
    interface_delete(dummy);
    interface_delete(dummy1);
    interface_delete(dummy2);

    TEST_END();
}

/**
 * Main test runner
 */
int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    printf("========================================\n");
    printf("VLAN and LACP Interface Fetcher Tests\n");
    printf("========================================\n");

    /* Initialize interface subsystem */
    interface_init();

    /* Run all tests */
    test_vlan_interface_creation();
    test_vlan_id_validation();
    test_lacp_bond_creation();
    test_lacp_bond_members();
    test_lacp_bonding_modes();
    test_lacp_load_balancing();
    test_lacp_member_selection();
    test_dummy_interface();

    /* Cleanup */
    interface_cleanup();

    /* Print summary */
    printf("\n========================================\n");
    printf("Test Summary:\n");
    printf("  Total:  %d\n", tests_total);
    printf("  Passed: %d\n", tests_passed);
    printf("  Failed: %d\n", tests_total - tests_passed);
    printf("========================================\n");

    if (tests_passed == tests_total) {
        printf("\n✅ ALL TESTS PASSED!\n\n");
        return 0;
    } else {
        printf("\n❌ SOME TESTS FAILED!\n\n");
        return 1;
    }
}
