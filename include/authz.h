/**
 * @file authz.h
 * @brief Authorization Interface
 */

#ifndef AUTHZ_H
#define AUTHZ_H

#include <stdbool.h>
#include "user_db.h"

/**
 * Check if user has permission to execute command
 * @param user User structure (NULL for current user)
 * @param command Command name
 * @param argc Argument count
 * @param argv Arguments
 * @return true if authorized, false otherwise
 */
bool authz_check_command(struct user *user, const char *command, int argc, char **argv);

/**
 * Check if user has required privilege level
 * @param user User structure (NULL for current user)
 * @param required_level Required privilege level
 * @return true if user has sufficient privileges, false otherwise
 */
bool authz_check_privilege(struct user *user, uint8_t required_level);

/**
 * Get required privilege level for a command
 * @param command Command name
 * @param argc Argument count
 * @param argv Arguments
 * @return Required privilege level, or 255 if unknown
 */
uint8_t authz_get_required_level(const char *command, int argc, char **argv);

#endif /* AUTHZ_H */
