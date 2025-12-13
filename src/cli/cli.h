/**
 * @file cli.h
 * @brief CLI Public Interface
 */

#ifndef _CLI_H
#define _CLI_H

#include "vty.h"
#include "command.h"

/* Module initialization functions */
void cli_pppoe_init(void);
void cli_interface_init(void);
void cli_system_init(void);
void cli_radius_init(void);
void cli_ippool_init(void);
void cli_route_init(void);

/* Main CLI functions (compatibility with main.c) */
int cli_init(void);
int cli_execute(const char *cmdline);
int cli_execute_file(const char *filename);
void cli_interactive(void);

/* Socket server functions */
int cli_socket_server_init(const char *path);
int cli_socket_server_start(void);
void cli_socket_server_stop(void);

#endif /* _CLI_H */
