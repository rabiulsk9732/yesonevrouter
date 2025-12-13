/**
 * @file log.h
 * @brief Logging Framework
 *
 * Provides comprehensive logging with multiple levels, structured logging,
 * syslog integration, and log rotation.
 */

#ifndef LOG_H
#define LOG_H

#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>

/* Log levels matching syslog priorities */
enum log_level {
    LOG_LEVEL_EMERGENCY = 0,  /* System is unusable */
    LOG_LEVEL_ALERT = 1,      /* Action must be taken immediately */
    LOG_LEVEL_CRITICAL = 2,   /* Critical conditions */
    LOG_LEVEL_ERROR = 3,      /* Error conditions */
    LOG_LEVEL_WARNING = 4,    /* Warning conditions */
    LOG_LEVEL_NOTICE = 5,     /* Normal but significant condition */
    LOG_LEVEL_INFO = 6,       /* Informational messages */
    LOG_LEVEL_DEBUG = 7       /* Debug-level messages */
};

/* Log output destinations */
enum log_destination {
    LOG_DEST_STDOUT = (1 << 0),
    LOG_DEST_STDERR = (1 << 1),
    LOG_DEST_SYSLOG = (1 << 2),
    LOG_DEST_FILE = (1 << 3)
};

/* Logging configuration */
struct log_config {
    enum log_level level;         /* Minimum log level to output */
    uint32_t destinations;        /* Bitmask of log_destination */
    char log_file[256];           /* Log file path (if LOG_DEST_FILE) */
    bool use_syslog;              /* Enable syslog integration */
    int syslog_facility;          /* Syslog facility */
    bool structured;              /* Enable structured logging (JSON) */
    bool color_output;            /* Enable colored output for console */
    bool timestamp;               /* Include timestamp in logs */
    bool thread_id;               /* Include thread ID in logs */
    uint32_t max_file_size;       /* Max log file size in bytes */
    uint32_t max_files;           /* Maximum number of rotated log files */
};

/**
 * Initialize logging subsystem
 * @param config Logging configuration (NULL for defaults)
 * @return 0 on success, -1 on failure
 */
int log_init(struct log_config *config);

/**
 * Set log level
 * @param level Minimum log level to output
 */
void log_set_level(enum log_level level);

/**
 * Get current log level
 * @return Current log level
 */
enum log_level log_get_level(void);

/**
 * Log a message
 * @param level Log level
 * @param file Source file name
 * @param line Source line number
 * @param function Function name
 * @param fmt Format string
 * @param ... Variable arguments
 */
void log_msg(enum log_level level, const char *file, int line,
             const char *function, const char *fmt, ...)
    __attribute__((format(printf, 5, 6)));

/**
 * Log a message with va_list
 * @param level Log level
 * @param file Source file name
 * @param line Source line number
 * @param function Function name
 * @param fmt Format string
 * @param ap Variable argument list
 */
void log_vmsg(enum log_level level, const char *file, int line,
              const char *function, const char *fmt, va_list ap);

/**
 * Log structured message (JSON format)
 * @param level Log level
 * @param file Source file name
 * @param line Source line number
 * @param function Function name
 * @param fields JSON fields as key-value pairs (NULL-terminated)
 */
void log_structured(enum log_level level, const char *file, int line,
                    const char *function, const char **fields);

/**
 * Rotate log file (if file logging enabled)
 * @return 0 on success, -1 on failure
 */
int log_rotate(void);

/**
 * Cleanup logging subsystem
 */
void log_cleanup(void);

/* Simple logging macros - direct to stderr for reliability */
#define YLOG_EMERGENCY(fmt, ...) fprintf(stderr, "[EMERG] " fmt "\n", ##__VA_ARGS__)
#define YLOG_ALERT(fmt, ...)     fprintf(stderr, "[ALERT] " fmt "\n", ##__VA_ARGS__)
#define YLOG_CRITICAL(fmt, ...)  fprintf(stderr, "[CRIT] " fmt "\n", ##__VA_ARGS__)
#define YLOG_ERROR(fmt, ...)     fprintf(stderr, "[ERROR] " fmt "\n", ##__VA_ARGS__)
#define YLOG_WARNING(fmt, ...)   fprintf(stderr, "[WARN] " fmt "\n", ##__VA_ARGS__)
#define YLOG_NOTICE(fmt, ...)    fprintf(stderr, "[NOTICE] " fmt "\n", ##__VA_ARGS__)
#define YLOG_INFO(fmt, ...)      fprintf(stderr, "[INFO] " fmt "\n", ##__VA_ARGS__)
#define YLOG_DEBUG(fmt, ...)     fprintf(stderr, "[DEBUG] " fmt "\n", ##__VA_ARGS__)

/* Short aliases - only define if not already defined by syslog.h */
#ifndef LOG_EMERG
#define LOG_EMERGENCY YLOG_EMERGENCY
#endif
#ifndef LOG_ALERT
#define LOG_ALERT     YLOG_ALERT
#endif
#ifndef LOG_CRIT
#define LOG_CRITICAL  YLOG_CRITICAL
#endif
#ifndef LOG_ERR
#define LOG_ERROR     YLOG_ERROR
#endif
#ifndef LOG_WARNING
#define LOG_WARNING   YLOG_WARNING
#endif
#ifndef LOG_NOTICE
#define LOG_NOTICE    YLOG_NOTICE
#endif
#ifndef LOG_INFO
#define LOG_INFO      YLOG_INFO
#endif
#ifndef LOG_DEBUG
#define LOG_DEBUG     YLOG_DEBUG
#endif

/* Legacy macros for compatibility */
#define LOG_TRACE(fmt, ...) YLOG_DEBUG(fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...) YLOG_WARNING(fmt, ##__VA_ARGS__)

#endif /* LOG_H */
