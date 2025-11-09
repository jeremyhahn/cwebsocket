/**
 *  Production-Grade Configurable Logging System
 *
 *  Copyright 2014 Jeremy Hahn
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef CWEBSOCKET_LOGGING_H
#define CWEBSOCKET_LOGGING_H

#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <syslog.h>

#ifdef __cplusplus
extern "C" {
#endif

// =============================================================================
// Log Level Definitions
// =============================================================================

typedef enum {
    CWEBSOCKET_LOG_LEVEL_NONE  = 0,   // Logging disabled
    CWEBSOCKET_LOG_LEVEL_ERROR = 1,   // Errors only
    CWEBSOCKET_LOG_LEVEL_WARN  = 2,   // Warnings and errors
    CWEBSOCKET_LOG_LEVEL_INFO  = 3,   // Informational messages
    CWEBSOCKET_LOG_LEVEL_DEBUG = 4,   // Debug messages
    CWEBSOCKET_LOG_LEVEL_TRACE = 5    // Trace messages (very verbose)
} cwebsocket_log_level;

// =============================================================================
// Log Backend Definitions
// =============================================================================

typedef enum {
    CWEBSOCKET_LOG_BACKEND_SYSLOG  = (1 << 0),   // Use syslog (default)
    CWEBSOCKET_LOG_BACKEND_FILE    = (1 << 1),   // Write to file
    CWEBSOCKET_LOG_BACKEND_STDERR  = (1 << 2),   // Write to stderr
    CWEBSOCKET_LOG_BACKEND_CALLBACK = (1 << 3)   // Use custom callback
} cwebsocket_log_backend;

// =============================================================================
// Custom Logging Callback
// =============================================================================

/**
 * Custom logging callback function signature
 *
 * @param level     Log level of the message
 * @param function  Function name where log was generated
 * @param file      Source file name
 * @param line      Line number in source file
 * @param format    Printf-style format string
 * @param args      Variable arguments for format string
 */
typedef void (*cwebsocket_log_callback)(
    cwebsocket_log_level level,
    const char *function,
    const char *file,
    int line,
    const char *format,
    va_list args
);

// =============================================================================
// Configuration Structure
// =============================================================================

typedef struct {
    cwebsocket_log_level level;           // Current log level
    uint32_t backends;                    // Bitmask of enabled backends
    const char *log_file_path;            // Path for file backend (if enabled)
    FILE *log_file;                       // Open file handle (internal use)
    cwebsocket_log_callback callback;    // Custom callback (if enabled)
    void *user_data;                      // User data passed to callback

    // File rotation settings
    uint64_t max_file_size;               // Max size before rotation (0 = no rotation)
    int max_rotations;                    // Number of rotated files to keep
    uint64_t current_file_size;           // Current file size (internal)

    // Format options
    int include_timestamp;                // Include timestamp in messages
    int include_level;                    // Include log level in messages
    int include_location;                 // Include file:line in messages

    // Thread safety
    int thread_safe;                      // Enable thread-safe logging
    void *mutex;                          // Internal mutex (when thread_safe)
} cwebsocket_log_config;

// =============================================================================
// Core Logging API
// =============================================================================

/**
 * Initialize the logging system with default configuration
 * Default: ERROR level, syslog backend, backward compatible
 */
void cwebsocket_log_init(void);

/**
 * Shutdown the logging system and release resources
 */
void cwebsocket_log_shutdown(void);

/**
 * Get the current log configuration
 * @return Pointer to current configuration (read-only)
 */
const cwebsocket_log_config* cwebsocket_log_get_config(void);

/**
 * Set the log level
 * @param level New log level
 */
void cwebsocket_log_set_level(cwebsocket_log_level level);

/**
 * Get the current log level
 * @return Current log level
 */
cwebsocket_log_level cwebsocket_log_get_level(void);

/**
 * Enable or disable a log backend
 * @param backend Backend to enable/disable
 * @param enable  1 to enable, 0 to disable
 */
void cwebsocket_log_set_backend(cwebsocket_log_backend backend, int enable);

/**
 * Check if a backend is enabled
 * @param backend Backend to check
 * @return 1 if enabled, 0 if disabled
 */
int cwebsocket_log_is_backend_enabled(cwebsocket_log_backend backend);

/**
 * Set the file path for file backend
 * @param path Path to log file (NULL to disable file backend)
 * @return 0 on success, -1 on error
 */
int cwebsocket_log_set_file(const char *path);

/**
 * Set file rotation parameters
 * @param max_size Maximum file size in bytes (0 = no rotation)
 * @param max_rotations Number of rotated files to keep
 */
void cwebsocket_log_set_rotation(uint64_t max_size, int max_rotations);

/**
 * Set a custom logging callback
 * @param callback Callback function (NULL to disable)
 * @param user_data User data passed to callback
 */
void cwebsocket_log_set_callback(cwebsocket_log_callback callback, void *user_data);

/**
 * Set format options
 * @param include_timestamp Include timestamp in messages
 * @param include_level Include log level in messages
 * @param include_location Include file:line in messages
 */
void cwebsocket_log_set_format(int include_timestamp, int include_level, int include_location);

/**
 * Enable or disable thread-safe logging
 * @param enable 1 to enable, 0 to disable
 * @return 0 on success, -1 on error
 */
int cwebsocket_log_set_thread_safe(int enable);

// =============================================================================
// Internal Logging Function (DO NOT CALL DIRECTLY)
// =============================================================================

void cwebsocket_log_write(
    cwebsocket_log_level level,
    const char *function,
    const char *file,
    int line,
    const char *format,
    ...
) __attribute__((format(printf, 5, 6)));

// =============================================================================
// Convenience Macros (Primary API for logging)
// =============================================================================

/**
 * Log an error message
 * Usage: CWEBSOCKET_LOG_ERROR("Failed to connect: %s", error_msg);
 */
#define CWEBSOCKET_LOG_ERROR(fmt, ...) \
    cwebsocket_log_write(CWEBSOCKET_LOG_LEVEL_ERROR, __func__, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

/**
 * Log a warning message
 * Usage: CWEBSOCKET_LOG_WARN("Connection unstable: retry %d", retry_count);
 */
#define CWEBSOCKET_LOG_WARN(fmt, ...) \
    cwebsocket_log_write(CWEBSOCKET_LOG_LEVEL_WARN, __func__, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

/**
 * Log an informational message
 * Usage: CWEBSOCKET_LOG_INFO("Connection established to %s", host);
 */
#define CWEBSOCKET_LOG_INFO(fmt, ...) \
    cwebsocket_log_write(CWEBSOCKET_LOG_LEVEL_INFO, __func__, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

/**
 * Log a debug message
 * Usage: CWEBSOCKET_LOG_DEBUG("Processing packet id=%u", packet_id);
 */
#define CWEBSOCKET_LOG_DEBUG(fmt, ...) \
    cwebsocket_log_write(CWEBSOCKET_LOG_LEVEL_DEBUG, __func__, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

/**
 * Log a trace message
 * Usage: CWEBSOCKET_LOG_TRACE("Entering function with param=%d", param);
 */
#define CWEBSOCKET_LOG_TRACE(fmt, ...) \
    cwebsocket_log_write(CWEBSOCKET_LOG_LEVEL_TRACE, __func__, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

// =============================================================================
// MQTT-Specific Logging Macros (for compatibility with existing code)
// =============================================================================

#define MQTT_LOG_ERROR   CWEBSOCKET_LOG_ERROR
#define MQTT_LOG_WARN    CWEBSOCKET_LOG_WARN
#define MQTT_LOG_INFO    CWEBSOCKET_LOG_INFO
#define MQTT_LOG_DEBUG   CWEBSOCKET_LOG_DEBUG
#define MQTT_LOG_TRACE   CWEBSOCKET_LOG_TRACE

// =============================================================================
// Utility Functions
// =============================================================================

/**
 * Convert log level to string
 * @param level Log level
 * @return String representation of log level
 */
const char* cwebsocket_log_level_to_string(cwebsocket_log_level level);

/**
 * Convert string to log level
 * @param str String representation of log level
 * @return Log level, or CWEBSOCKET_LOG_LEVEL_NONE if invalid
 */
cwebsocket_log_level cwebsocket_log_string_to_level(const char *str);

/**
 * Convert log level to syslog priority
 * @param level Log level
 * @return Corresponding syslog priority
 */
int cwebsocket_log_level_to_syslog(cwebsocket_log_level level);

/**
 * Flush all log backends
 */
void cwebsocket_log_flush(void);

/**
 * Rotate the log file (if file backend is enabled)
 * @return 0 on success, -1 on error
 */
int cwebsocket_log_rotate(void);

#ifdef __cplusplus
}
#endif

#endif // CWEBSOCKET_LOGGING_H
