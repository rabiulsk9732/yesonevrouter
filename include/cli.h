/**
 * @file cli.h
 * @brief YESRouter Command Line Interface
 */

#ifndef CLI_H
#define CLI_H

#include <stdbool.h>
#include <stdint.h>

/* CLI command handler function type */
typedef int (*cli_cmd_handler_t)(int argc, char **argv);

/* CLI command structure */
struct cli_command {
    const char *name;
    const char *help;
    cli_cmd_handler_t handler;
};

/**
 * @brief Initialize CLI subsystem
 * @return 0 on success, -1 on error
 */
int cli_init(void);

/**
 * @brief Cleanup CLI subsystem
 */
void cli_cleanup(void);

/**
 * @brief Execute a CLI command
 * @param cmdline Command line string
 * @return 0 on success, -1 on error
 */
int cli_execute(const char *cmdline);

/**
 * @brief Execute CLI commands from a file
 * @param filename Path to file containing CLI commands
 * @return 0 on success, -1 on error
 */
int cli_execute_file(const char *filename);

/**
 * @brief Start interactive CLI mode
 * @return 0 on success, -1 on error
 */
int cli_interactive(void);

/**
 * @brief Register a CLI command
 * @param name Command name
 * @param help Help text
 * @param handler Command handler function
 * @return 0 on success, -1 on error
 */
int cli_register_command(const char *name, const char *help, cli_cmd_handler_t handler);

/* Module registration functions */
void cli_register_interface_commands(void);
void cli_register_route_commands(void);
void cli_register_arp_commands(void);
void cli_register_system_commands(void);
void cli_register_auth_commands(void);
void cli_vlan_register_commands(void);
void cli_register_config_commands(void);
void cli_register_debug_commands(void);
void cli_register_nat_commands(void);
void cli_register_log_commands(void);  // Added new module registration
void cli_register_user_commands(void); // Added new module registration

/* Built-in command handlers */
int cmd_show(int argc, char **argv);
int cmd_interface(int argc, char **argv);
int cmd_route(int argc, char **argv);
int cmd_arp(int argc, char **argv);
int cmd_ping(int argc, char **argv);
int cmd_system(int argc, char **argv);
int cmd_daemon(int argc, char **argv);
int cmd_help(int argc, char **argv);
int cmd_quit(int argc, char **argv);

/* Show command handlers */
int cmd_show_interfaces(int argc, char **argv);
int cmd_show_interfaces_brief(int argc, char **argv);
int cmd_show_routes(int argc, char **argv);
int cmd_show_arp(int argc, char **argv);
int cmd_show_users(int argc, char **argv);
int cmd_show_user(int argc, char **argv);
int cmd_show_sessions(int argc, char **argv);
int cmd_username(int argc, char **argv);

/* Cisco-style interface config mode commands (from cli_interface.c) */
struct interface *cli_get_config_interface(void);
int cli_cmd_config_interface(int argc, char **argv);
int cli_cmd_if_ip_address(int argc, char **argv);
int cli_cmd_if_no_shutdown(void);
int cli_cmd_if_shutdown(void);
void cli_exit_interface_config(void);

void show_context_help(const char *partial);

#endif /* CLI_H */
