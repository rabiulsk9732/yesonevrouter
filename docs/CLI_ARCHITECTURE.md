# YESRouter CLI Architecture

## Design Principles (RFC/Cisco IOS Compliant)

### 1. Command Modes (Cisco IOS Style)
```
User EXEC Mode        (Router>)      - Read-only, basic show commands
Privileged EXEC Mode  (Router#)      - All show, clear, debug commands
Global Config Mode    (Router(config)#) - System-wide configuration
Interface Config Mode (Router(config-if)#) - Per-interface config
PPPoE Config Mode     (Router(config-pppoe)#) - PPPoE specific
```

### 2. Command Structure
```
<verb> <object> [<modifier>] [<value>]

Examples:
  show pppoe sessions
  show pppoe statistics
  show interfaces brief
  clear pppoe session 1234
  configure terminal
  interface GigabitEthernet0/1
  pppoe enable
```

### 3. Privilege Levels (0-15)
- Level 0: Disable, enable, exit, help, logout
- Level 1: User EXEC (show basic)
- Level 15: Privileged EXEC (full access)

## File Structure (New Clean CLI)
```
src/cli/
├── vty.c              # Virtual terminal (core I/O)
├── vty.h
├── command.c          # Command registration & dispatch
├── command.h
├── cli_node.c         # Command tree nodes
├── cli_node.h
├── cli_show.c         # All 'show' commands
├── cli_config.c       # Configuration commands
├── cli_pppoe.c        # PPPoE specific commands
├── cli_interface.c    # Interface commands
├── cli_radius.c       # RADIUS commands
├── cli_system.c       # System commands (hostname, etc)
└── CMakeLists.txt
```

## Core Data Structures

### Command Node
```c
enum node_type {
    VIEW_NODE,           /* User EXEC mode (>) */
    ENABLE_NODE,         /* Privileged EXEC mode (#) */
    CONFIG_NODE,         /* Global config mode */
    INTERFACE_NODE,      /* Interface config mode */
    PPPOE_NODE,          /* PPPoE config mode */
};

struct cmd_element {
    const char *string;      /* Command string with tokens */
    const char *doc;         /* Help documentation */
    int (*func)(struct vty *, int, const char **);
    uint8_t privilege;       /* Required privilege level */
};

struct cmd_node {
    enum node_type node;
    const char *prompt;
    struct cmd_element **cmd_vector;
    int cmd_count;
};
```

### VTY Structure
```c
struct vty {
    int fd;                  /* File descriptor */
    enum node_type node;     /* Current command mode */
    uint8_t privilege;       /* Current privilege level */
    char *buf;               /* Input buffer */
    size_t length;           /* Buffer length */
    char hostname[64];       /* Router hostname */

    /* Output */
    int (*output)(struct vty *, const char *, ...);
};
```

## Command Macros (FRR Style)
```c
/* Define a command */
DEFUN(show_pppoe_sessions,
      show_pppoe_sessions_cmd,
      "show pppoe sessions",
      SHOW_STR
      "PPPoE information\n"
      "Display active sessions\n")
{
    pppoe_show_sessions(vty);
    return CMD_SUCCESS;
}

/* Install command to node */
install_element(VIEW_NODE, &show_pppoe_sessions_cmd);
install_element(ENABLE_NODE, &show_pppoe_sessions_cmd);
```

## Command Flow
```
1. User input -> vty_read()
2. Tokenize -> cmd_tokenize()
3. Match command -> cmd_match()
4. Check privilege -> cmd_check_privilege()
5. Execute handler -> cmd->func(vty, argc, argv)
6. Output result -> vty_out()
```

## Essential Commands

### View Mode (Router>)
```
enable                    - Enter privileged mode
show version             - Display version
show pppoe sessions      - Display PPPoE sessions
show pppoe statistics    - Display PPPoE stats
show interfaces          - Display interfaces
show interfaces brief    - Brief interface summary
exit                     - Disconnect
help                     - Show help
?                        - Context help
```

### Enable Mode (Router#)
```
configure terminal       - Enter config mode
show running-config      - Display running config
show startup-config      - Display startup config
clear pppoe session <id> - Clear specific session
clear pppoe sessions     - Clear all sessions
write memory             - Save config
reload                   - Restart router
debug pppoe              - Enable PPPoE debug
no debug pppoe           - Disable PPPoE debug
```

### Config Mode (Router(config)#)
```
hostname <name>          - Set hostname
interface <name>         - Enter interface config
pppoe                    - Enter PPPoE config
radius-server host <ip>  - Configure RADIUS
ip local pool <name> <start> <end>
end                      - Exit to enable mode
exit                     - Exit one level
```

### Interface Mode (Router(config-if)#)
```
description <text>       - Set description
ip address <ip> <mask>   - Set IP address
no shutdown              - Enable interface
shutdown                 - Disable interface
pppoe enable             - Enable PPPoE on interface
exit                     - Exit to config mode
```

### PPPoE Mode (Router(config-pppoe)#)
```
ac-name <name>           - Set AC name
service-name <name>      - Set service name
max-sessions <num>       - Set max sessions
interface <name>         - Bind to interface
exit                     - Exit to config mode
```

## Implementation Priority

### Phase 1: Core Framework
1. vty.c - VTY I/O handling
2. command.c - Command registration
3. cli_node.c - Node management

### Phase 2: Basic Commands
1. cli_show.c - show commands
2. cli_system.c - system commands

### Phase 3: Feature Commands
1. cli_pppoe.c - PPPoE commands
2. cli_interface.c - Interface commands
3. cli_radius.c - RADIUS commands

### Phase 4: Config Management
1. cli_config.c - Config save/load
2. JSON config integration
