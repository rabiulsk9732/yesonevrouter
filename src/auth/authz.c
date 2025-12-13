/**
 * @file authz.c
 * @brief Authorization Implementation
 */

#include "authz.h"
#include "auth.h"
#include "user_db.h"
#include "log.h"
#include <string.h>
#include <strings.h>

/**
 * Check if user has required privilege level
 */
bool authz_check_privilege(struct user *user, uint8_t required_level)
{
    if (!user) {
        user = auth_get_current_user();
    }

    if (!user) {
        return false;  /* No user authenticated */
    }

    /* Lower number = higher privilege */
    return user->privilege_level <= required_level;
}

/**
 * Get required privilege level for a command
 */
uint8_t authz_get_required_level(const char *command, int argc, char **argv)
{
    if (!command) return 255;

    /* Level 0 (Admin) only commands */
    if (strcmp(command, "username") == 0) return USER_PRIV_LEVEL_ADMIN;
    if (strcmp(command, "reload") == 0) return USER_PRIV_LEVEL_ADMIN;
    if (strcmp(command, "shutdown") == 0) return USER_PRIV_LEVEL_ADMIN;
    if (strcmp(command, "write") == 0 && argc >= 2 && strcmp(argv[1], "memory") == 0) {
        return USER_PRIV_LEVEL_ADMIN;
    }

    /* Level 1 (Operator) commands - configuration */
    if (strcmp(command, "configure") == 0) return USER_PRIV_LEVEL_OPERATOR;
    if (strcmp(command, "interface") == 0) return USER_PRIV_LEVEL_OPERATOR;
    if (strcmp(command, "ip") == 0) {
        if (argc >= 2) {
            if (strcmp(argv[1], "address") == 0) return USER_PRIV_LEVEL_OPERATOR;
            if (strcmp(argv[1], "route") == 0) return USER_PRIV_LEVEL_OPERATOR;
        }
        return USER_PRIV_LEVEL_OPERATOR;
    }
    if (strcmp(command, "no") == 0) return USER_PRIV_LEVEL_OPERATOR;
    if (strcmp(command, "shutdown") == 0) return USER_PRIV_LEVEL_OPERATOR;  /* Interface shutdown */
    if (strcmp(command, "clear") == 0) return USER_PRIV_LEVEL_OPERATOR;

    /* Level 2 (Viewer) commands - read-only */
    if (strcmp(command, "show") == 0) return USER_PRIV_LEVEL_VIEWER;
    if (strcmp(command, "ping") == 0) return USER_PRIV_LEVEL_VIEWER;
    if (strcmp(command, "traceroute") == 0) return USER_PRIV_LEVEL_VIEWER;
    if (strcmp(command, "nslookup") == 0) return USER_PRIV_LEVEL_VIEWER;
    if (strcmp(command, "help") == 0) return USER_PRIV_LEVEL_VIEWER;
    if (strcmp(command, "?") == 0) return USER_PRIV_LEVEL_VIEWER;

    /* Exit/end are allowed for all authenticated users */
    if (strcmp(command, "exit") == 0) return USER_PRIV_LEVEL_VIEWER;
    if (strcmp(command, "end") == 0) return USER_PRIV_LEVEL_VIEWER;
    if (strcmp(command, "logout") == 0) return USER_PRIV_LEVEL_VIEWER;
    if (strcmp(command, "quit") == 0) return USER_PRIV_LEVEL_VIEWER;

    /* Default: require operator level for unknown commands */
    return USER_PRIV_LEVEL_OPERATOR;
}

/**
 * Check if user has permission to execute command
 */
bool authz_check_command(struct user *user, const char *command, int argc, char **argv)
{
    if (!user) {
        user = auth_get_current_user();
    }

    if (!user) {
        YLOG_WARNING("Authorization check failed: no user authenticated");
        return false;
    }

    uint8_t required_level = authz_get_required_level(command, argc, argv);
    bool authorized = authz_check_privilege(user, required_level);

    if (!authorized) {
        YLOG_WARNING("User %s (level %u) attempted unauthorized command: %s (requires level %u)",
                    user->username, user->privilege_level, command, required_level);
    }

    return authorized;
}
