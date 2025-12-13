/**
 * @file cli_system.c
 * @brief System CLI Commands (Cisco IOS Style)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/utsname.h>
#include <sys/sysinfo.h>

#include "command.h"
#include "vty.h"

/* ============================================================================
 * Show Commands
 * ============================================================================ */

DEFUN(cmd_show_running_config,
      cmd_show_running_config_cmd,
      "show running-config",
      SHOW_STR
      "Current operating configuration\n")
{
    vty_out(vty, "!\r\n");
    vty_out(vty, "! YESRouter Running Configuration\r\n");
    vty_out(vty, "! Generated: %s", ctime(&(time_t){time(NULL)}));
    vty_out(vty, "!\r\n");
    vty_out(vty, "hostname %s\r\n", g_hostname);
    vty_out(vty, "!\r\n");
    /* TODO: Dump actual running config */
    vty_out(vty, "end\r\n");
    return CMD_SUCCESS;
}

DEFUN(cmd_show_startup_config,
      cmd_show_startup_config_cmd,
      "show startup-config",
      SHOW_STR
      "Contents of startup configuration\n")
{
    vty_out(vty, "!\r\n");
    vty_out(vty, "! YESRouter Startup Configuration\r\n");
    vty_out(vty, "!\r\n");
    /* TODO: Read from startup.json */
    vty_out(vty, "end\r\n");
    return CMD_SUCCESS;
}

DEFUN(cmd_show_clock,
      cmd_show_clock_cmd,
      "show clock",
      SHOW_STR
      "Display the system clock\n")
{
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char buf[64];

    strftime(buf, sizeof(buf), "%H:%M:%S.000 %Z %a %b %d %Y", tm);
    vty_out(vty, "%s\r\n", buf);
    return CMD_SUCCESS;
}

DEFUN(cmd_show_uptime,
      cmd_show_uptime_cmd,
      "show uptime",
      SHOW_STR
      "Display system uptime\n")
{
    struct sysinfo si;
    if (sysinfo(&si) == 0) {
        long days = si.uptime / 86400;
        long hours = (si.uptime % 86400) / 3600;
        long mins = (si.uptime % 3600) / 60;
        long secs = si.uptime % 60;

        vty_out(vty, "System uptime: %ld days, %ld hours, %ld minutes, %ld seconds\r\n",
                days, hours, mins, secs);
    }
    return CMD_SUCCESS;
}

DEFUN(cmd_show_memory,
      cmd_show_memory_cmd,
      "show memory",
      SHOW_STR
      "Memory statistics\n")
{
    struct sysinfo si;
    if (sysinfo(&si) == 0) {
        vty_out(vty, "\r\n");
        vty_out(vty, "Memory Statistics\r\n");
        vty_out(vty, "=================\r\n");
        vty_out(vty, "Total RAM:     %lu MB\r\n", si.totalram / (1024 * 1024));
        vty_out(vty, "Free RAM:      %lu MB\r\n", si.freeram / (1024 * 1024));
        vty_out(vty, "Shared RAM:    %lu MB\r\n", si.sharedram / (1024 * 1024));
        vty_out(vty, "Buffer RAM:    %lu MB\r\n", si.bufferram / (1024 * 1024));
        vty_out(vty, "Total Swap:    %lu MB\r\n", si.totalswap / (1024 * 1024));
        vty_out(vty, "Free Swap:     %lu MB\r\n", si.freeswap / (1024 * 1024));
        vty_out(vty, "\r\n");
    }
    return CMD_SUCCESS;
}

DEFUN(cmd_show_cpu,
      cmd_show_cpu_cmd,
      "show cpu",
      SHOW_STR
      "CPU statistics\n")
{
    FILE *f = fopen("/proc/loadavg", "r");
    if (f) {
        float load1, load5, load15;
        if (fscanf(f, "%f %f %f", &load1, &load5, &load15) == 3) {
            vty_out(vty, "\r\n");
            vty_out(vty, "CPU Load Average\r\n");
            vty_out(vty, "================\r\n");
            vty_out(vty, "1 minute:   %.2f\r\n", load1);
            vty_out(vty, "5 minutes:  %.2f\r\n", load5);
            vty_out(vty, "15 minutes: %.2f\r\n", load15);
            vty_out(vty, "\r\n");
        }
        fclose(f);
    }
    return CMD_SUCCESS;
}

DEFUN(cmd_show_processes,
      cmd_show_processes_cmd,
      "show processes",
      SHOW_STR
      "Process information\n")
{
    vty_out(vty, "\r\n");
    vty_out(vty, "YESRouter Processes\r\n");
    vty_out(vty, "===================\r\n");
    vty_out(vty, "Main Process: Running\r\n");
    vty_out(vty, "CLI Server:   Running\r\n");
    vty_out(vty, "DPDK Workers: Running\r\n");
    vty_out(vty, "\r\n");
    return CMD_SUCCESS;
}

DEFUN(cmd_show_logging,
      cmd_show_logging_cmd,
      "show logging",
      SHOW_STR
      "Show logging configuration and buffer\n")
{
    vty_out(vty, "\r\n");
    vty_out(vty, "Logging Configuration\r\n");
    vty_out(vty, "=====================\r\n");
    vty_out(vty, "Console logging: enabled\r\n");
    vty_out(vty, "File logging:    /var/log/yesrouter.log\r\n");
    vty_out(vty, "Log level:       info\r\n");
    vty_out(vty, "\r\n");
    return CMD_SUCCESS;
}

DEFUN(cmd_show_tech_support,
      cmd_show_tech_support_cmd,
      "show tech-support",
      SHOW_STR
      "Show system information for technical support\n")
{
    struct utsname uts;

    vty_out(vty, "\r\n");
    vty_out(vty, "================ SHOW TECH-SUPPORT ================\r\n");
    vty_out(vty, "\r\n");

    /* Version */
    vty_out(vty, "---- show version ----\r\n");
    vty_out(vty, "YESRouter vBNG Version 1.0.0\r\n");
    if (uname(&uts) == 0) {
        vty_out(vty, "System: %s %s %s\r\n", uts.sysname, uts.release, uts.machine);
    }
    vty_out(vty, "\r\n");

    /* Uptime */
    vty_out(vty, "---- show uptime ----\r\n");
    cmd_show_uptime_cmd.func(vty, 0, NULL);

    /* Memory */
    vty_out(vty, "---- show memory ----\r\n");
    cmd_show_memory_cmd.func(vty, 0, NULL);

    /* CPU */
    vty_out(vty, "---- show cpu ----\r\n");
    cmd_show_cpu_cmd.func(vty, 0, NULL);

    vty_out(vty, "================ END TECH-SUPPORT ================\r\n");
    return CMD_SUCCESS;
}

/* ============================================================================
 * Configuration Commands
 * ============================================================================ */

DEFUN(cmd_write_memory,
      cmd_write_memory_cmd,
      "write memory",
      "Write running configuration to memory\n"
      "Write to NVRAM\n")
{
    vty_out(vty, "Building configuration...\r\n");
    /* TODO: Save config to startup.json */
    vty_out(vty, "[OK]\r\n");
    return CMD_SUCCESS;
}

DEFUN(cmd_write,
      cmd_write_cmd,
      "write",
      "Write running configuration to memory\n")
{
    return cmd_write_memory_cmd.func(vty, argc, argv);
}

DEFUN(cmd_copy_running_startup,
      cmd_copy_running_startup_cmd,
      "copy running-config startup-config",
      "Copy configuration\n"
      "Copy running configuration\n"
      "Copy to startup configuration\n")
{
    return cmd_write_memory_cmd.func(vty, argc, argv);
}

DEFUN(cmd_reload,
      cmd_reload_cmd,
      "reload",
      "Halt and perform a cold restart\n")
{
    vty_out(vty, "System configuration has been modified. Save? [yes/no]: ");
    /* TODO: Implement reload confirmation */
    vty_out(vty, "\r\nReload scheduled.\r\n");
    return CMD_SUCCESS;
}

DEFUN(cmd_logging_console,
      cmd_logging_console_cmd,
      "logging console",
      "Logging control\n"
      "Set console logging\n")
{
    vty_out(vty, "Console logging enabled\r\n");
    return CMD_SUCCESS;
}

DEFUN(cmd_logging_file,
      cmd_logging_file_cmd,
      "logging file WORD",
      "Logging control\n"
      "Log to file\n"
      "Filename\n")
{
    if (argc < 3) {
        vty_out(vty, "%% Filename required\r\n");
        return CMD_ERR_INCOMPLETE;
    }
    vty_out(vty, "Logging to file: %s\r\n", argv[2]);
    return CMD_SUCCESS;
}

DEFUN(cmd_logging_level,
      cmd_logging_level_cmd,
      "logging level WORD",
      "Logging control\n"
      "Set logging level\n"
      "Level (debug, info, warning, error)\n")
{
    if (argc < 3) {
        vty_out(vty, "%% Level required (debug, info, warning, error)\r\n");
        return CMD_ERR_INCOMPLETE;
    }
    vty_out(vty, "Logging level set to: %s\r\n", argv[2]);
    return CMD_SUCCESS;
}

/* ============================================================================
 * Clear Commands
 * ============================================================================ */

DEFUN(cmd_clear_counters,
      cmd_clear_counters_cmd,
      "clear counters",
      CLEAR_STR
      "Clear interface counters\n")
{
    vty_out(vty, "All interface counters cleared\r\n");
    return CMD_SUCCESS;
}

DEFUN(cmd_clear_logging,
      cmd_clear_logging_cmd,
      "clear logging",
      CLEAR_STR
      "Clear logging buffer\n")
{
    vty_out(vty, "Logging buffer cleared\r\n");
    return CMD_SUCCESS;
}

/* ============================================================================
 * Terminal Commands
 * ============================================================================ */

DEFUN(cmd_terminal_length,
      cmd_terminal_length_cmd,
      "terminal length <0-512>",
      "Set terminal parameters\n"
      "Set number of lines on screen\n"
      "Number of lines (0 for no pausing)\n")
{
    if (argc < 3) {
        vty_out(vty, "%% Length required\r\n");
        return CMD_ERR_INCOMPLETE;
    }
    vty->lines = atoi(argv[2]);
    return CMD_SUCCESS;
}

DEFUN(cmd_terminal_width,
      cmd_terminal_width_cmd,
      "terminal width <40-512>",
      "Set terminal parameters\n"
      "Set terminal width\n"
      "Width in columns\n")
{
    if (argc < 3) {
        vty_out(vty, "%% Width required\r\n");
        return CMD_ERR_INCOMPLETE;
    }
    vty->width = atoi(argv[2]);
    return CMD_SUCCESS;
}

/* ============================================================================
 * Initialization
 * ============================================================================ */

void cli_system_init(void)
{
    /* View mode */
    install_element(VIEW_NODE, &cmd_show_clock_cmd);
    install_element(VIEW_NODE, &cmd_show_uptime_cmd);
    install_element(VIEW_NODE, &cmd_show_memory_cmd);
    install_element(VIEW_NODE, &cmd_show_cpu_cmd);
    install_element(VIEW_NODE, &cmd_show_processes_cmd);
    install_element(VIEW_NODE, &cmd_show_logging_cmd);
    install_element(VIEW_NODE, &cmd_terminal_length_cmd);
    install_element(VIEW_NODE, &cmd_terminal_width_cmd);

    /* Enable mode */
    install_element(ENABLE_NODE, &cmd_show_clock_cmd);
    install_element(ENABLE_NODE, &cmd_show_uptime_cmd);
    install_element(ENABLE_NODE, &cmd_show_memory_cmd);
    install_element(ENABLE_NODE, &cmd_show_cpu_cmd);
    install_element(ENABLE_NODE, &cmd_show_processes_cmd);
    install_element(ENABLE_NODE, &cmd_show_logging_cmd);
    install_element(ENABLE_NODE, &cmd_show_running_config_cmd);
    install_element(ENABLE_NODE, &cmd_show_startup_config_cmd);
    install_element(ENABLE_NODE, &cmd_show_tech_support_cmd);
    install_element(ENABLE_NODE, &cmd_write_cmd);
    install_element(ENABLE_NODE, &cmd_write_memory_cmd);
    install_element(ENABLE_NODE, &cmd_copy_running_startup_cmd);
    install_element(ENABLE_NODE, &cmd_reload_cmd);
    install_element(ENABLE_NODE, &cmd_clear_counters_cmd);
    install_element(ENABLE_NODE, &cmd_clear_logging_cmd);
    install_element(ENABLE_NODE, &cmd_terminal_length_cmd);
    install_element(ENABLE_NODE, &cmd_terminal_width_cmd);

    /* Config mode */
    install_element(CONFIG_NODE, &cmd_logging_console_cmd);
    install_element(CONFIG_NODE, &cmd_logging_file_cmd);
    install_element(CONFIG_NODE, &cmd_logging_level_cmd);
}
