/**
 * @file cli_socket.h
 * @brief CLI Unix Socket Server Interface
 */

#ifndef _CLI_SOCKET_H
#define _CLI_SOCKET_H

/* Initialize CLI socket server */
int cli_socket_server_init(const char *path);

/* Start CLI socket server */
int cli_socket_server_start(void);

/* Stop CLI socket server */
void cli_socket_server_stop(void);

#endif /* _CLI_SOCKET_H */
