/**
 * @file cli_auth.c
 * @brief User Management CLI Commands
 */

#include "cli.h"
#include "user_db.h"
#include "auth.h"
#include "authz.h"
#include "session.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Command: username (Cisco-style) */
int cmd_username(int argc, char **argv)
{
    struct user *current_user = auth_get_current_user();
    if (!current_user || current_user->privilege_level != USER_PRIV_LEVEL_ADMIN) {
        printf("%% Permission denied: Administrator access required\n");
        return -1;
    }

    if (argc < 2) {
        printf("Usage: username <name> privilege <0|1|2> password <password>\n");
        printf("       username <name> secret <encrypted>\n");
        printf("       username <name> secret 0 <password>  (enable password)\n");
        printf("       no username <name>\n");
        return -1;
    }

    if (strcmp(argv[1], "no") == 0 && argc >= 3) {
        /* Delete user */
        if (user_db_delete(argv[2]) == 0) {
            printf("%% User %s deleted\n", argv[2]);
            return 0;
        } else {
            printf("%% Failed to delete user %s\n", argv[2]);
            return -1;
        }
    }

    const char *username = argv[1];
    int i = 2;

    uint8_t privilege_level = USER_PRIV_LEVEL_VIEWER;
    const char *password = NULL;
    const char *enable_password = NULL;
    bool is_enable_secret = false;

    while (i < argc) {
        if (strcmp(argv[i], "privilege") == 0 && i + 1 < argc) {
            privilege_level = (uint8_t)atoi(argv[i + 1]);
            if (privilege_level > USER_PRIV_LEVEL_VIEWER) {
                printf("%% Invalid privilege level: %u (must be 0-2)\n", privilege_level);
                return -1;
            }
            i += 2;
        } else if (strcmp(argv[i], "password") == 0 && i + 1 < argc) {
            password = argv[i + 1];
            i += 2;
        } else if (strcmp(argv[i], "secret") == 0) {
            if (i + 1 < argc && strcmp(argv[i + 1], "0") == 0 && i + 2 < argc) {
                /* Enable secret: username <name> secret 0 <password> */
                enable_password = argv[i + 2];
                is_enable_secret = true;
                i += 3;
            } else if (i + 1 < argc) {
                printf("%% Encrypted secrets not yet supported. Use 'secret 0 <password>' for enable password.\n");
                return -1;
            } else {
                i++;
            }
        } else {
            i++;
        }
    }

    /* Check if user exists */
    struct user *existing = user_db_find(username);
    if (existing) {
        /* Update existing user */
        bool updated = true;
        if (password) {
            updated = (user_db_update_password(username, password) == 0) && updated;
        }
        if (is_enable_secret && enable_password) {
            updated = (user_db_set_enable_password(username, enable_password) == 0) && updated;
        }
        updated = (user_db_update_privilege(username, privilege_level) == 0) && updated;

        if (updated) {
            printf("%% User %s updated\n", username);
            return 0;
        } else {
            printf("%% Failed to update user %s\n", username);
            return -1;
        }
    } else {
        /* Create new user */
        if (!password) {
            printf("%% Password required for new user\n");
            return -1;
        }

        if (user_db_add(username, password, privilege_level) == 0) {
            if (is_enable_secret && enable_password) {
                user_db_set_enable_password(username, enable_password);
            }
            printf("%% User %s created with privilege level %u\n", username, privilege_level);
            return 0;
        } else {
            printf("%% Failed to create user %s\n", username);
            return -1;
        }
    }
}

/* Command: show users */
int cmd_show_users(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    user_db_print_all();
    return 0;
}

/* Command: show user */
int cmd_show_user(int argc, char **argv)
{
    if (argc < 3) {
        printf("Usage: show user <username>\n");
        return -1;
    }

    user_db_print_user(argv[2]);
    return 0;
}

/* Command: show sessions */
int cmd_show_sessions(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    session_print_all();
    return 0;
}

/* Command: enable secret (set global enable password) */
int cmd_enable_secret(int argc, char **argv)
{
    struct user *current_user = auth_get_current_user();
    if (!current_user || current_user->privilege_level != USER_PRIV_LEVEL_ADMIN) {
        printf("%% Permission denied: Administrator access required\n");
        return -1;
    }

    if (argc < 3) {
        printf("Usage: enable secret <password>\n");
        printf("       enable secret 0 <password>\n");
        return -1;
    }

    const char *password = argv[2];
    if (user_db_set_global_enable_password(password) == 0) {
        printf("%% Enable secret set\n");
        return 0;
    } else {
        printf("%% Failed to set enable secret\n");
        return -1;
    }
}

/* Command: clear line (disconnect session) */
int cmd_clear_line(int argc, char **argv)
{
    struct user *current_user = auth_get_current_user();
    if (!current_user || current_user->privilege_level != USER_PRIV_LEVEL_ADMIN) {
        printf("%% Permission denied: Administrator access required\n");
        return -1;
    }

    if (argc < 3) {
        printf("Usage: clear line <session-id>\n");
        return -1;
    }

    uint32_t session_id = (uint32_t)atoi(argv[2]);
    if (session_destroy(session_id) == 0) {
        printf("%% Session %u disconnected\n", session_id);
        return 0;
    } else {
        printf("%% Session %u not found\n", session_id);
        return -1;
    }
}

/* Register user management commands */
void cli_register_auth_commands(void)
{
    cli_register_command("username", "Manage users", cmd_username);
}
