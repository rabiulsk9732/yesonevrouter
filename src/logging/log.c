/**
 * @file log.c
 * @brief Logging Framework Implementation
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <syslog.h>

/* Include log.h after syslog.h to avoid macro conflicts */
#include "log.h"

/* Global logging state */
static struct log_config g_log_config;
static FILE *g_log_file = NULL;
static bool g_log_initialized = false;
static pthread_mutex_t g_log_mutex;  /* Initialized in log_init() */

/* ANSI color codes for terminal output */
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_WHITE   "\033[37m"

/* Log level names */
static const char *log_level_names[] = {
    "EMERGENCY",
    "ALERT",
    "CRITICAL",
    "ERROR",
    "WARNING",
    "NOTICE",
    "INFO",
    "DEBUG"
};

/* Log level colors */
static const char *log_level_colors[] = {
    COLOR_RED,      /* EMERGENCY */
    COLOR_RED,      /* ALERT */
    COLOR_RED,      /* CRITICAL */
    COLOR_RED,      /* ERROR */
    COLOR_YELLOW,   /* WARNING */
    COLOR_CYAN,     /* NOTICE */
    COLOR_GREEN,    /* INFO */
    COLOR_BLUE      /* DEBUG */
};

/* Syslog priority mapping - use integer values to avoid macro conflicts */
static int log_level_to_syslog[] = {
    0,  /* LOG_EMERG - EMERGENCY */
    1,  /* LOG_ALERT - ALERT */
    2,  /* LOG_CRIT - CRITICAL */
    3,  /* LOG_ERR - ERROR */
    4,  /* LOG_WARNING - WARNING */
    5,  /* LOG_NOTICE - NOTICE */
    6,  /* LOG_INFO - INFO */
    7   /* LOG_DEBUG - DEBUG */
};

static void log_set_defaults(struct log_config *config)
{
    memset(config, 0, sizeof(*config));
    config->level = LOG_LEVEL_INFO;
    config->destinations = LOG_DEST_STDOUT | LOG_DEST_STDERR;
    config->use_syslog = false;
    config->syslog_facility = LOG_DAEMON;
    config->structured = false;
    config->color_output = true;
    config->timestamp = true;
    config->thread_id = false;
    config->max_file_size = 10 * 1024 * 1024;  /* 10 MB */
    config->max_files = 5;
}

int log_init(struct log_config *config)
{
    if (g_log_initialized) {
        return 0;
    }

    if (config) {
        memcpy(&g_log_config, config, sizeof(g_log_config));
    } else {
        log_set_defaults(&g_log_config);
    }

    /* Explicitly initialize mutex */
    pthread_mutex_init(&g_log_mutex, NULL);

    /* Initialize syslog if enabled */
    if (g_log_config.use_syslog) {
        openlog("yesrouter", LOG_PID | LOG_CONS, g_log_config.syslog_facility);
    }

    /* Open log file if file destination is enabled */
    if (g_log_config.destinations & LOG_DEST_FILE) {
        if (g_log_config.log_file[0] != '\0') {
            g_log_file = fopen(g_log_config.log_file, "a");
            if (!g_log_file) {
                fprintf(stderr, "Failed to open log file: %s (%s)\n",
                        g_log_config.log_file, strerror(errno));
                g_log_config.destinations &= ~LOG_DEST_FILE;
            }
        } else {
            fprintf(stderr, "Log file path not specified\n");
            g_log_config.destinations &= ~LOG_DEST_FILE;
        }
    }

    g_log_initialized = true;
    /* YLOG_INFO removed to prevent hang during init */

    return 0;
}

void log_set_level(enum log_level level)
{
    if (level <= LOG_LEVEL_DEBUG) {
        g_log_config.level = level;
    }
}

enum log_level log_get_level(void)
{
    return g_log_config.level;
}

static void format_timestamp(char *buf, size_t buf_size)
{
    struct timespec ts;
    struct tm tm_info;
    char time_buf[32];  /* "YYYY-MM-DD HH:MM:SS" = 19 bytes */
    long msec;
    int ret;

    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tm_info);
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm_info);
    msec = ts.tv_nsec / 1000000;
    if (msec < 0) msec = 0;
    if (msec > 999) msec = 999;
    ret = snprintf(buf, buf_size, "%s.%03ld", time_buf, msec);
    if (ret < 0 || (size_t)ret >= buf_size) {
        buf[0] = '\0';  /* Ensure null termination on error */
    }
}

static void format_message(char *buf, size_t buf_size, enum log_level level,
                           const char *file, int line, const char *function,
                           const char *fmt, va_list ap)
{
    char timestamp[64] = {0};
    char thread_id_str[16] = {0};
    char message[1024];
    int pos = 0;

    /* Format the actual message */
    vsnprintf(message, sizeof(message), fmt, ap);

    /* Add timestamp if enabled */
    if (g_log_config.timestamp) {
        format_timestamp(timestamp, sizeof(timestamp));
    }

    /* Add thread ID if enabled */
    if (g_log_config.thread_id) {
        snprintf(thread_id_str, sizeof(thread_id_str), "[%lu]",
                 (unsigned long)pthread_self());
    }

    /* Build the log line */
    if (g_log_config.structured) {
        /* JSON structured format */
        if (g_log_config.thread_id) {
            pos = snprintf(buf, buf_size,
                "{"
                "\"timestamp\":\"%s\","
                "\"level\":\"%s\","
                "\"file\":\"%s\","
                "\"line\":%d,"
                "\"function\":\"%s\","
                "\"thread_id\":\"%s\","
                "\"message\":\"%s\""
                "}\n",
                timestamp,
                log_level_names[level],
                file ? file : "unknown",
                line,
                function ? function : "unknown",
                thread_id_str,
                message);
        } else {
            pos = snprintf(buf, buf_size,
                "{"
                "\"timestamp\":\"%s\","
                "\"level\":\"%s\","
                "\"file\":\"%s\","
                "\"line\":%d,"
                "\"function\":\"%s\","
                "\"message\":\"%s\""
                "}\n",
                timestamp,
                log_level_names[level],
                file ? file : "unknown",
                line,
                function ? function : "unknown",
                message);
        }
    } else {
        /* Human-readable format */
        if (g_log_config.timestamp) {
            pos = snprintf(buf, buf_size, "[%s] ", timestamp);
        }
        pos += snprintf(buf + pos, buf_size - pos, "[%s] ",
                       log_level_names[level]);
        if (g_log_config.thread_id) {
            pos += snprintf(buf + pos, buf_size - pos, "%s ", thread_id_str);
        }
        pos += snprintf(buf + pos, buf_size - pos, "%s:%d:%s() ",
                       file ? file : "unknown", line,
                       function ? function : "unknown");
        pos += snprintf(buf + pos, buf_size - pos, "%s\n", message);
    }
}

void log_msg(enum log_level level, const char *file, int line,
             const char *function, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    log_vmsg(level, file, line, function, fmt, ap);
    va_end(ap);
}

void log_vmsg(enum log_level level, const char *file, int line,
              const char *function, const char *fmt, va_list ap)
{
    char buf[2048];
    char color_buf[2560];
    const char *output = buf;
    bool use_color = false;

    if (!g_log_initialized) {
        /* Fallback to stderr if not initialized */
        vfprintf(stderr, fmt, ap);
        fprintf(stderr, "\n");
        return;
    }

    /* Check if message should be logged */
    if (level > g_log_config.level) {
        return;
    }

    pthread_mutex_lock(&g_log_mutex);

    /* Format the message */
    format_message(buf, sizeof(buf), level, file, line, function, fmt, ap);

    /* Add color for console output if enabled */
    if (g_log_config.color_output && isatty(fileno(stdout))) {
        if (level <= LOG_LEVEL_ERROR) {
            snprintf(color_buf, sizeof(color_buf), "%s%s%s",
                    log_level_colors[level], buf, COLOR_RESET);
            output = color_buf;
            use_color = true;
        }
    }

    /* Output to stdout */
    if (g_log_config.destinations & LOG_DEST_STDOUT) {
        if (level <= LOG_LEVEL_INFO) {
            fprintf(stdout, "%s", use_color ? output : buf);
            fflush(stdout);
        }
    }

    /* Output to stderr */
    if (g_log_config.destinations & LOG_DEST_STDERR) {
        if (level <= LOG_LEVEL_WARNING) {
            fprintf(stderr, "%s", use_color ? output : buf);
            fflush(stderr);
        }
    }

    /* Output to syslog */
    if (g_log_config.use_syslog && (g_log_config.destinations & LOG_DEST_SYSLOG)) {
        vsyslog(log_level_to_syslog[level], fmt, ap);
    }

    /* Output to file */
    if (g_log_file && (g_log_config.destinations & LOG_DEST_FILE)) {
        fprintf(g_log_file, "%s", buf);
        fflush(g_log_file);

        /* Check if rotation is needed */
        if (ftell(g_log_file) > (long)g_log_config.max_file_size) {
            log_rotate();
        }
    }

    pthread_mutex_unlock(&g_log_mutex);
}

void log_structured(enum log_level level, const char *file, int line,
                    const char *function, const char **fields)
{
    char buf[2048];
    char timestamp[64] = {0};
    int pos = 0;
    int i;

    if (!g_log_initialized || level > g_log_config.level) {
        return;
    }

    pthread_mutex_lock(&g_log_mutex);

    if (g_log_config.timestamp) {
        format_timestamp(timestamp, sizeof(timestamp));
    }

    pos = snprintf(buf, sizeof(buf),
        "{"
        "\"timestamp\":\"%s\","
        "\"level\":\"%s\","
        "\"file\":\"%s\","
        "\"line\":%d,"
        "\"function\":\"%s\"",
        timestamp,
        log_level_names[level],
        file ? file : "unknown",
        line,
        function ? function : "unknown");

    /* Add custom fields */
    if (fields) {
        for (i = 0; fields[i] && fields[i + 1]; i += 2) {
            pos += snprintf(buf + pos, sizeof(buf) - pos, ",\"%s\":\"%s\"",
                           fields[i], fields[i + 1]);
        }
    }

    pos += snprintf(buf + pos, sizeof(buf) - pos, "}\n");

    /* Output to destinations */
    if (g_log_config.destinations & LOG_DEST_STDOUT) {
        fprintf(stdout, "%s", buf);
        fflush(stdout);
    }
    if (g_log_config.destinations & LOG_DEST_STDERR) {
        fprintf(stderr, "%s", buf);
        fflush(stderr);
    }
    if (g_log_file && (g_log_config.destinations & LOG_DEST_FILE)) {
        fprintf(g_log_file, "%s", buf);
        fflush(g_log_file);
    }
    if (g_log_config.use_syslog) {
        syslog(log_level_to_syslog[level], "%s", buf);
    }

    pthread_mutex_unlock(&g_log_mutex);
}

int log_rotate(void)
{
    char old_file[512];
    char new_file[512];
    int i;

    if (!g_log_file || g_log_config.log_file[0] == '\0') {
        return -1;
    }

    pthread_mutex_lock(&g_log_mutex);

    /* Close current log file */
    fclose(g_log_file);
    g_log_file = NULL;

    /* Rotate existing files */
    for (i = g_log_config.max_files - 1; i > 0; i--) {
        if (i == 1) {
            snprintf(old_file, sizeof(old_file), "%s", g_log_config.log_file);
        } else {
            snprintf(old_file, sizeof(old_file), "%s.%d",
                    g_log_config.log_file, i - 1);
        }
        snprintf(new_file, sizeof(new_file), "%s.%d",
                g_log_config.log_file, i);

        /* Remove old file if it exists */
        unlink(new_file);
        /* Rename old file to new number */
        rename(old_file, new_file);
    }

    /* Open new log file */
    g_log_file = fopen(g_log_config.log_file, "a");
    if (!g_log_file) {
        fprintf(stderr, "Failed to reopen log file after rotation: %s\n",
                strerror(errno));
        pthread_mutex_unlock(&g_log_mutex);
        return -1;
    }

    YLOG_INFO("Log file rotated");

    pthread_mutex_unlock(&g_log_mutex);
    return 0;
}

void log_cleanup(void)
{
    if (!g_log_initialized) {
        return;
    }

    pthread_mutex_lock(&g_log_mutex);

    if (g_log_file) {
        fclose(g_log_file);
        g_log_file = NULL;
    }

    if (g_log_config.use_syslog) {
        closelog();
    }

    g_log_initialized = false;

    pthread_mutex_unlock(&g_log_mutex);
}
