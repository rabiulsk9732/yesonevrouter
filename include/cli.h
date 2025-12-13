/**
 * @file cli.h
 * @brief YESRouter CLI Public Interface
 *
 * Cisco IOS / FRR Style CLI
 */

#ifndef _CLI_H
#define _CLI_H

#include <stdint.h>
#include <stdbool.h>

/* Initialize CLI subsystem */
int cli_init(void);

/* Cleanup CLI subsystem */
void cli_cleanup(void);

/* Execute a single command */
int cli_execute(const char *cmdline);

/* Execute commands from file */
int cli_execute_file(const char *filename);

/* Start interactive CLI */
void cli_interactive(void);

#endif /* _CLI_H */
