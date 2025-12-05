/**
 * @file routing_table.c
 * @brief Routing Table Implementation with Radix Tree LPM
 */

#define _GNU_SOURCE
#include "routing_table.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <errno.h>

/* Helper macros */
#define PREFIX_MASK(len) ((len) == 0 ? 0 : htonl(0xFFFFFFFF << (32 - (len))))
#define IP_BIT(ip_nbo, bit_pos) (((ntohl(ip_nbo)) >> (31 - (bit_pos))) & 1)

/* Internal function declarations */
static struct radix_node *radix_node_create(const struct in_addr *prefix,
                                             uint8_t prefix_len);
static void radix_node_free(struct radix_node *node);
static int radix_tree_insert_rib(struct routing_table *table,
                                  struct route_entry *route);
static int radix_tree_delete_rib(struct routing_table *table,
                                  const struct in_addr *prefix,
                                  uint8_t prefix_len,
                                  enum route_source source);
static struct route_entry *radix_tree_lookup(struct radix_node *root,
                                              const struct in_addr *ip);
static void update_fib(struct routing_table *table);
/* static struct route_entry *find_best_route_rib(struct routing_table *table,
                                                const struct in_addr *prefix,
                                                uint8_t prefix_len); */
static void notify_route_update(struct routing_table *table,
                                struct route_entry *route,
                                bool added);

/* Global notification list */
static struct route_notification *g_notifications = NULL;
static pthread_mutex_t g_notification_lock = PTHREAD_MUTEX_INITIALIZER;

static struct routing_table *g_routing_table = NULL;

struct routing_table *routing_table_get_instance(void)
{
    return g_routing_table;
}

struct routing_table *routing_table_init(void)
{
    struct routing_table *table;
    pthread_rwlock_t *lock;

    if (g_routing_table) {
        return g_routing_table;
    }

    table = calloc(1, sizeof(*table));
    if (!table) {
        return NULL;
    }

    /* Initialize RIB and FIB roots */
    table->rib_root = NULL;
    table->fib_root = NULL;
    table->rib_count = 0;
    table->fib_count = 0;

    /* Initialize statistics */
    table->lookups = 0;
    table->hits = 0;
    table->misses = 0;
    table->inserts = 0;
    table->deletes = 0;

    /* Initialize read-write lock */
    lock = calloc(1, sizeof(pthread_rwlock_t));
    if (!lock) {
        free(table);
        return NULL;
    }

    if (pthread_rwlock_init(lock, NULL) != 0) {
        free(lock);
        free(table);
        return NULL;
    }

    table->lock = lock;
    g_routing_table = table;

    return table;
}

void routing_table_cleanup(struct routing_table *table)
{
    if (!table) {
        return;
    }

    /* Free RIB tree */
    if (table->rib_root) {
        radix_node_free(table->rib_root);
    }

    /* Free FIB tree */
    if (table->fib_root) {
        radix_node_free(table->fib_root);
    }

    /* Destroy lock */
    if (table->lock) {
        pthread_rwlock_destroy((pthread_rwlock_t *)table->lock);
        free(table->lock);
    }

    free(table);
}

static struct radix_node *radix_node_create(const struct in_addr *prefix,
                                             uint8_t prefix_len)
{
    struct radix_node *node;

    node = calloc(1, sizeof(*node));
    if (!node) {
        return NULL;
    }

    if (prefix) {
        node->prefix = *prefix;
    }
    node->prefix_len = prefix_len;
    node->left = NULL;
    node->right = NULL;
    node->route = NULL;
    node->refcnt = 1;

    return node;
}

static void radix_node_free(struct radix_node *node)
{
    if (!node) {
        return;
    }

    /* Recursively free children */
    if (node->left) {
        radix_node_free(node->left);
    }
    if (node->right) {
        radix_node_free(node->right);
    }

    /* Free route entry if present */
    if (node->route) {
        free(node->route);
    }

    free(node);
}

static int radix_tree_insert_rib(struct routing_table *table,
                                  struct route_entry *route)
{
    struct radix_node *node, *parent, *new_node;
    struct in_addr prefix = route->prefix;
    uint8_t prefix_len = route->prefix_len;
    int bit_pos = 0;

    /* If tree is empty, create root */
    if (!table->rib_root) {
        printf("DEBUG: Tree empty, creating root for %08x/%d\n", prefix.s_addr, prefix_len);
        table->rib_root = radix_node_create(&prefix, prefix_len);
        if (!table->rib_root) {
            return -1;
        }
        table->rib_root->route = route;
        table->rib_count++;
        return 0;
    }

    printf("DEBUG: Inserting %08x/%d. Root is %08x/%d\n",
           prefix.s_addr, prefix_len,
           table->rib_root->prefix.s_addr, table->rib_root->prefix_len);

    /* Check if new prefix is a supernet of the root */
    if (prefix_len < table->rib_root->prefix_len) {
        /* Check if root is within new prefix */
        uint32_t mask_val = PREFIX_MASK(prefix_len);
        if ((table->rib_root->prefix.s_addr & mask_val) == (prefix.s_addr & mask_val)) {
            /* New node becomes new root */
            new_node = radix_node_create(&prefix, prefix_len);
            if (!new_node) return -1;
            new_node->route = route;

            /* Old root becomes child */
            int bit = IP_BIT(table->rib_root->prefix.s_addr, prefix_len);
            if (bit == 0) {
                new_node->left = table->rib_root;
            } else {
                new_node->right = table->rib_root;
            }
            table->rib_root = new_node;
            table->rib_count++;
            return 0;
        }
    }

    /* Check for disjoint prefixes (divergence before root's prefix length) */
    /* Find first differing bit */
    int diff_bit = -1;
    int min_len = (prefix_len < table->rib_root->prefix_len) ? prefix_len : table->rib_root->prefix_len;
    for (int i = 0; i < min_len; i++) {
        if (IP_BIT(prefix.s_addr, i) != IP_BIT(table->rib_root->prefix.s_addr, i)) {
            diff_bit = i;
            break;
        }
    }

    /* If they diverge, or if new prefix is shorter but not a supernet (diverges) */
    if (diff_bit != -1 || (prefix_len < table->rib_root->prefix_len)) {
        /* They diverge at diff_bit. Create a glue node at this level. */
        /* If diff_bit is -1 here, it means they matched up to min_len, but prefix_len < root_len,
           which means it should have been handled by the supernet check above.
           So if we are here and prefix_len < root_len, they MUST have diverged.
           If diff_bit is -1, it implies they are equal up to min_len. */

        int glue_len = (diff_bit != -1) ? diff_bit : min_len;

        /* Create glue node (no route, just internal node) */
        /* Prefix of glue node is common prefix */
        struct in_addr glue_prefix = prefix;
        /* Zero out bits after glue_len to be clean */
        uint32_t glue_mask = PREFIX_MASK(glue_len);
        glue_prefix.s_addr &= glue_mask;

        struct radix_node *glue = radix_node_create(&glue_prefix, glue_len);
        if (!glue) return -1;

        /* Create new node for the new route */
        new_node = radix_node_create(&prefix, prefix_len);
        if (!new_node) {
            free(glue);
            return -1;
        }
        new_node->route = route;

        /* Attach old root and new node to glue */
        int old_root_bit = IP_BIT(table->rib_root->prefix.s_addr, glue_len);
        int new_node_bit = IP_BIT(prefix.s_addr, glue_len);

        if (old_root_bit == 0) glue->left = table->rib_root;
        else glue->right = table->rib_root;

        if (new_node_bit == 0) glue->left = new_node;
        else glue->right = new_node;

        table->rib_root = glue;
        table->rib_count++;
        return 0;
    }

    /* Traverse tree to find insertion point */
    node = table->rib_root;
    parent = NULL;

    while (bit_pos < prefix_len && node) {
        /* Check if current node has a route with same prefix */
        if (node->route && node->route->prefix_len == prefix_len) {
            struct in_addr mask = {.s_addr = PREFIX_MASK(prefix_len)};
            if ((node->route->prefix.s_addr & mask.s_addr) ==
                (prefix.s_addr & mask.s_addr)) {
                /* Exact match - replace route */
                free(node->route);
                node->route = route;
                return 0;
            }
        }

        /* Navigate based on current bit */
        int bit = IP_BIT(prefix.s_addr, bit_pos);
        parent = node;
        node = (bit == 0) ? node->left : node->right;
        bit_pos++;
    }

    /* If we exhausted the prefix, insert at current position */
    if (bit_pos >= prefix_len) {
        if (node && !node->route) {
            /* Node exists but has no route - add route */
            node->route = route;
            table->rib_count++;
            return 0;
        } else if (!node && parent) {
            /* Create new leaf node */
            new_node = radix_node_create(&prefix, prefix_len);
            if (!new_node) {
                return -1;
            }
            new_node->route = route;
            if (IP_BIT(prefix.s_addr, bit_pos - 1) == 0) {
                parent->left = new_node;
            } else {
                parent->right = new_node;
            }
            table->rib_count++;
            return 0;
        }
    }

    /* Need to create intermediate nodes */
    if (!node && parent) {
        /* Create path from parent to new node */
        new_node = radix_node_create(&prefix, prefix_len);
        if (!new_node) {
            return -1;
        }
        new_node->route = route;

        /* Link to parent */
        int bit = IP_BIT(prefix.s_addr, bit_pos - 1);
        if (bit == 0) {
            parent->left = new_node;
        } else {
            parent->right = new_node;
        }
        table->rib_count++;
        return 0;
    }

    /* Should not reach here */
    return -1;
}

static struct route_entry *radix_tree_lookup(struct radix_node *root,
                                              const struct in_addr *ip)
{
    struct radix_node *node;
    struct route_entry *best_match = NULL;
    int best_prefix_len = -1;  /* Use -1 to allow 0-length prefix match */
    int bit_pos;

    if (!root) {
        return NULL;
    }

    node = root;
    bit_pos = 0;

    /* Traverse tree following IP address bits */
    while (node && bit_pos < 32) {
        /* Update best match if current node has a route (LPM) */
        if (node->route) {
            /* Check if this route matches the IP */
            struct in_addr mask = {.s_addr = PREFIX_MASK(node->route->prefix_len)};
            if ((ip->s_addr & mask.s_addr) ==
                (node->route->prefix.s_addr & mask.s_addr)) {
                /* Accept if better match (longer prefix wins) */
                if ((int)node->route->prefix_len > best_prefix_len) {
                    best_match = node->route;
                    best_prefix_len = node->route->prefix_len;
                }
            }
        }

        /* Navigate to next level */
        int bit = IP_BIT(ip->s_addr, bit_pos);
        node = (bit == 0) ? node->left : node->right;
        bit_pos++;
    }

    return best_match;
}

int routing_table_add(struct routing_table *table,
                      const struct in_addr *prefix,
                      uint8_t prefix_len,
                      const struct in_addr *next_hop,
                      uint32_t egress_ifindex,
                      uint8_t admin_distance,
                      enum route_source source,
                      const char *source_name)
{
    if (!table || !prefix || prefix_len > 32) {
        return -1;
    }

    struct route_entry *route;
    int ret;

    /* Acquire write lock */
    pthread_rwlock_wrlock((pthread_rwlock_t *)table->lock);

    /* Create route entry */
    route = calloc(1, sizeof(*route));
    if (!route) {
        pthread_rwlock_unlock((pthread_rwlock_t *)table->lock);
        return -1;
    }

    route->prefix = *prefix;
    route->prefix_len = prefix_len;
    route->next_hop = *next_hop;
    route->egress_ifindex = egress_ifindex;
    route->admin_distance = admin_distance;
    route->source = source;
    if (source_name) {
        strncpy(route->source_name, source_name, sizeof(route->source_name) - 1);
    }
    route->num_paths = 1;
    route->paths[0].next_hop = *next_hop;
    route->paths[0].egress_ifindex = egress_ifindex;
    route->paths[0].weight = 1;
    route->created_time = time(NULL);
    route->last_used = 0;
    route->in_fib = false;

    /* Insert into RIB */
    ret = radix_tree_insert_rib(table, route);
    if (ret < 0) {
        free(route);
        pthread_rwlock_unlock((pthread_rwlock_t *)table->lock);
        return -1;
    }

    table->inserts++;

    /* Update FIB if this is the best route */
    update_fib(table);

    /* Notify listeners */
    notify_route_update(table, route, true);

    pthread_rwlock_unlock((pthread_rwlock_t *)table->lock);

    return 0;
}

static int radix_tree_delete_rib(struct routing_table *table,
                                  const struct in_addr *prefix,
                                  uint8_t prefix_len,
                                  enum route_source source)
{
    struct radix_node *node, *parent;
    int bit_pos = 0;
    int bit;

    if (!table->rib_root) {
        return -1;
    }

    node = table->rib_root;
    parent = NULL;

    /* Find the node containing the route */
    while (node && bit_pos < prefix_len) {
        /* Check if current node matches */
        if (node->route && node->route->prefix_len == prefix_len) {
            struct in_addr mask = {.s_addr = PREFIX_MASK(prefix_len)};
            if ((node->route->prefix.s_addr & mask.s_addr) ==
                (prefix->s_addr & mask.s_addr) &&
                node->route->source == source) {
                /* Found matching route */
                struct route_entry *route = node->route;
                node->route = NULL;

                /* If node has no children and is not root, remove it */
                if (!node->left && !node->right && parent) {
                    if (parent->left == node) {
                        parent->left = NULL;
                    } else if (parent->right == node) {
                        parent->right = NULL;
                    }
                    free(node);
                } else if (!node->left && !node->right && !parent) {
                    /* This is the root node - just clear it */
                    table->rib_root = NULL;
                    free(node);
                }

                table->rib_count--;
                table->deletes++;
                free(route);
                return 0;
            }
        }

        bit = IP_BIT(prefix->s_addr, bit_pos);
        parent = node;
        node = (bit == 0) ? node->left : node->right;
        bit_pos++;
    }

    return -1;
}

int routing_table_delete(struct routing_table *table,
                         const struct in_addr *prefix,
                         uint8_t prefix_len,
                         enum route_source source)
{
    int ret;

    if (!table || !prefix || prefix_len > 32) {
        return -1;
    }

    pthread_rwlock_wrlock((pthread_rwlock_t *)table->lock);

    ret = radix_tree_delete_rib(table, prefix, prefix_len, source);

    if (ret == 0) {
        /* Update FIB after deletion */
        update_fib(table);
    }

    pthread_rwlock_unlock((pthread_rwlock_t *)table->lock);

    return ret;
}

struct route_entry *routing_table_lookup(struct routing_table *table,
                                         const struct in_addr *ip)
{
    struct route_entry *route;

    if (!table || !ip) {
        return NULL;
    }

    pthread_rwlock_rdlock((pthread_rwlock_t *)table->lock);

    table->lookups++;

    /* Lookup in FIB (best routes only) */
    route = radix_tree_lookup(table->fib_root, ip);

    if (route) {
        table->hits++;
        route->last_used = time(NULL);
        route->packets++;
    } else {
        table->misses++;
    }

    pthread_rwlock_unlock((pthread_rwlock_t *)table->lock);

    return route;
}

/* static struct route_entry *find_best_route_rib(struct routing_table *table,
                                                const struct in_addr *prefix,
                                                uint8_t prefix_len)
{
    (void)prefix_len;

    return radix_tree_lookup(table->rib_root, prefix);
} */

/* Helper to copy a radix tree node and its children */
static struct radix_node *radix_node_copy(struct radix_node *src)
{
    if (!src) return NULL;

    struct radix_node *dst = calloc(1, sizeof(*dst));
    if (!dst) return NULL;

    dst->prefix = src->prefix;
    dst->prefix_len = src->prefix_len;
    dst->refcnt = 1;

    /* Copy route entry if present */
    if (src->route) {
        dst->route = calloc(1, sizeof(*dst->route));
        if (dst->route) {
            memcpy(dst->route, src->route, sizeof(*dst->route));
            dst->route->in_fib = true;
        }
    }

    /* Recursively copy children */
    dst->left = radix_node_copy(src->left);
    dst->right = radix_node_copy(src->right);

    return dst;
}

static void update_fib(struct routing_table *table)
{
    /* Free existing FIB */
    if (table->fib_root) {
        radix_node_free(table->fib_root);
        table->fib_root = NULL;
    }

    /* Copy RIB to FIB (simplified - full impl would select best routes) */
    table->fib_root = radix_node_copy(table->rib_root);
    table->fib_count = table->rib_count;
}

int routing_table_add_ecmp_path(struct routing_table *table,
                                const struct in_addr *prefix,
                                uint8_t prefix_len,
                                const struct in_addr *next_hop,
                                uint32_t egress_ifindex,
                                uint32_t weight)
{
    struct route_entry *route;

    if (!table || !prefix || !next_hop) {
        return -1;
    }

    (void)prefix_len; /* Unused for now */

    pthread_rwlock_wrlock((pthread_rwlock_t *)table->lock);

    /* Find existing route */
    route = radix_tree_lookup(table->rib_root, prefix);
    if (!route) {
        pthread_rwlock_unlock((pthread_rwlock_t *)table->lock);
        return -1;
    }

    /* Check if we have space for another ECMP path */
    if (route->num_paths >= ROUTE_MAX_ECMP_PATHS) {
        pthread_rwlock_unlock((pthread_rwlock_t *)table->lock);
        return -1;
    }

    /* Add new path */
    route->paths[route->num_paths].next_hop = *next_hop;
    route->paths[route->num_paths].egress_ifindex = egress_ifindex;
    route->paths[route->num_paths].weight = weight ? weight : 1;
    route->paths[route->num_paths].packets = 0;
    route->paths[route->num_paths].bytes = 0;
    route->num_paths++;

    pthread_rwlock_unlock((pthread_rwlock_t *)table->lock);

    return 0;
}

struct ecmp_path *routing_table_select_ecmp_path(struct route_entry *route,
                                                  uint32_t flow_hash)
{
    if (!route || route->num_paths == 0) {
        return NULL;
    }

    if (route->num_paths == 1) {
        return &route->paths[0];
    }

    /* Simple hash-based selection */
    uint32_t index = flow_hash % route->num_paths;
    return &route->paths[index];
}

int routing_table_register_notification(struct routing_table *table,
                                        route_update_callback_t callback,
                                        void *user_data)
{
    struct route_notification *notif;

    if (!table || !callback) {
        return -1;
    }

    notif = calloc(1, sizeof(*notif));
    if (!notif) {
        return -1;
    }

    notif->callback = callback;
    notif->user_data = user_data;

    pthread_mutex_lock(&g_notification_lock);
    notif->next = g_notifications;
    g_notifications = notif;
    pthread_mutex_unlock(&g_notification_lock);

    return 0;
}

static void notify_route_update(struct routing_table *table,
                                struct route_entry *route,
                                bool added)
{
    struct route_notification *notif;

    (void)table; /* Unused for now */

    pthread_mutex_lock(&g_notification_lock);

    for (notif = g_notifications; notif; notif = notif->next) {
        if (notif->callback) {
            notif->callback(route, added, notif->user_data);
        }
    }

    pthread_mutex_unlock(&g_notification_lock);
}

void routing_table_get_stats(struct routing_table *table,
                             uint64_t *lookups,
                             uint64_t *hits,
                             uint64_t *misses,
                             uint64_t *rib_count,
                             uint64_t *fib_count)
{
    if (!table) {
        return;
    }

    pthread_rwlock_rdlock((pthread_rwlock_t *)table->lock);

    if (lookups) *lookups = table->lookups;
    if (hits) *hits = table->hits;
    if (misses) *misses = table->misses;
    if (rib_count) *rib_count = table->rib_count;
    if (fib_count) *fib_count = table->fib_count;

    pthread_rwlock_unlock((pthread_rwlock_t *)table->lock);
}

const char *routing_table_source_to_str(enum route_source source)
{
    switch (source) {
        case ROUTE_SOURCE_CONNECTED: return "connected";
        case ROUTE_SOURCE_STATIC: return "static";
        case ROUTE_SOURCE_BGP: return "bgp";
        case ROUTE_SOURCE_OSPF: return "ospf";
        case ROUTE_SOURCE_ISIS: return "isis";
        case ROUTE_SOURCE_RIP: return "rip";
        default: return "unknown";
    }
}

void routing_table_print_route(struct route_entry *route)
{
    char prefix_str[INET_ADDRSTRLEN];
    char next_hop_str[INET_ADDRSTRLEN];

    if (!route) {
        return;
    }

    inet_ntop(AF_INET, &route->prefix, prefix_str, sizeof(prefix_str));
    inet_ntop(AF_INET, &route->next_hop, next_hop_str, sizeof(next_hop_str));

    printf("  %s/%u via %s", prefix_str, route->prefix_len, next_hop_str);
    printf(" [%s/%u]", routing_table_source_to_str(route->source),
           route->admin_distance);

    if (route->num_paths > 1) {
        printf(" (ECMP: %u paths)", route->num_paths);
    }

    printf(" - %lu packets, %lu bytes\n", route->packets, route->bytes);
}

static void radix_tree_print_node(struct radix_node *node)
{
    if (!node) return;

    if (node->route) {
        char dest_str[INET_ADDRSTRLEN];
        char gw_str[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &node->route->prefix, dest_str, sizeof(dest_str));
        inet_ntop(AF_INET, &node->route->next_hop, gw_str, sizeof(gw_str));

        printf("  %s/%d via %s dev %u (src: %s)\n",
               dest_str, node->route->prefix_len,
               node->route->next_hop.s_addr ? gw_str : "connected",
               node->route->egress_ifindex,
               routing_table_source_to_str(node->route->source));
    }

    radix_tree_print_node(node->left);
    radix_tree_print_node(node->right);
}

void routing_table_print(struct routing_table *table)
{
    if (!table) return;

    pthread_rwlock_rdlock((pthread_rwlock_t *)table->lock);

    printf("\nRouting Table:\n");
    printf("  RIB entries: %u\n", table->rib_count);
    printf("  FIB entries: %u\n", table->fib_count);
    printf("  Lookups: %lu (hits: %lu, misses: %lu)\n",
           table->lookups, table->hits, table->misses);
    printf("\nRoutes:\n");

    if (table->rib_root) {
        radix_tree_print_node(table->rib_root);
    } else {
        printf("  (empty)\n");
    }
    printf("\n");

    pthread_rwlock_unlock((pthread_rwlock_t *)table->lock);
}
