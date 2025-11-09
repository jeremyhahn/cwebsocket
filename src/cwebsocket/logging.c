/**
 *  Production-Grade Configurable Logging System - Implementation
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

#include "logging.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

// =============================================================================
// Global Configuration
// =============================================================================

static cwebsocket_log_config g_log_config = {
    .level = CWEBSOCKET_LOG_LEVEL_ERROR,        // Default: errors only
    .backends = CWEBSOCKET_LOG_BACKEND_SYSLOG,  // Default: syslog (backward compatible)
    .log_file_path = NULL,
    .log_file = NULL,
    .callback = NULL,
    .user_data = NULL,
    .max_file_size = 0,
    .max_rotations = 5,
    .current_file_size = 0,
    .include_timestamp = 1,
    .include_level = 1,
    .include_location = 0,
    .thread_safe = 0,
    .mutex = NULL
};

static int g_log_initialized = 0;
static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;

// =============================================================================
// Helper Functions
// =============================================================================

static void log_lock(void) {
    if (g_log_config.thread_safe && g_log_config.mutex) {
        pthread_mutex_lock((pthread_mutex_t*)g_log_config.mutex);
    }
}

static void log_unlock(void) {
    if (g_log_config.thread_safe && g_log_config.mutex) {
        pthread_mutex_unlock((pthread_mutex_t*)g_log_config.mutex);
    }
}

static const char* basename_safe(const char *path) {
    const char *base = strrchr(path, '/');
    return base ? base + 1 : path;
}

static void get_timestamp(char *buf, size_t size) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    struct tm tm_info;
    localtime_r(&ts.tv_sec, &tm_info);

    size_t written = strftime(buf, size, "%Y-%m-%d %H:%M:%S", &tm_info);
    if (written > 0 && written + 8 < size) {
        snprintf(buf + written, size - written, ".%03ld", ts.tv_nsec / 1000000);
    }
}

static int should_rotate_file(void) {
    if (g_log_config.max_file_size == 0) {
        return 0;  // Rotation disabled
    }

    if (g_log_config.log_file == NULL) {
        return 0;  // File not open
    }

    return g_log_config.current_file_size >= g_log_config.max_file_size;
}

// =============================================================================
// Initialization and Shutdown
// =============================================================================

void cwebsocket_log_init(void) {
    if (g_log_initialized) {
        return;
    }

    // Open syslog by default for backward compatibility
    openlog("cwebsocket", LOG_PID | LOG_NDELAY, LOG_USER);

    g_log_initialized = 1;
}

void cwebsocket_log_shutdown(void) {
    if (!g_log_initialized) {
        return;
    }

    log_lock();

    // Close file if open
    if (g_log_config.log_file) {
        fflush(g_log_config.log_file);
        fclose(g_log_config.log_file);
        g_log_config.log_file = NULL;
    }

    // Free file path
    if (g_log_config.log_file_path) {
        free((void*)g_log_config.log_file_path);
        g_log_config.log_file_path = NULL;
    }

    // Close syslog
    closelog();

    // Destroy mutex if allocated
    if (g_log_config.mutex) {
        pthread_mutex_t *mtx = (pthread_mutex_t*)g_log_config.mutex;
        log_unlock();  // Unlock before destroying
        pthread_mutex_destroy(mtx);
        free(mtx);
        g_log_config.mutex = NULL;
    } else {
        log_unlock();
    }

    g_log_initialized = 0;
}

// =============================================================================
// Configuration API
// =============================================================================

const cwebsocket_log_config* cwebsocket_log_get_config(void) {
    return &g_log_config;
}

void cwebsocket_log_set_level(cwebsocket_log_level level) {
    if (level < CWEBSOCKET_LOG_LEVEL_NONE || level > CWEBSOCKET_LOG_LEVEL_TRACE) {
        return;
    }

    log_lock();
    g_log_config.level = level;
    log_unlock();
}

cwebsocket_log_level cwebsocket_log_get_level(void) {
    return g_log_config.level;
}

void cwebsocket_log_set_backend(cwebsocket_log_backend backend, int enable) {
    log_lock();

    if (enable) {
        g_log_config.backends |= backend;
    } else {
        g_log_config.backends &= ~backend;
    }

    log_unlock();
}

int cwebsocket_log_is_backend_enabled(cwebsocket_log_backend backend) {
    return (g_log_config.backends & backend) != 0;
}

int cwebsocket_log_set_file(const char *path) {
    if (!path) {
        log_lock();

        // Close and disable file backend
        if (g_log_config.log_file) {
            fflush(g_log_config.log_file);
            fclose(g_log_config.log_file);
            g_log_config.log_file = NULL;
        }

        if (g_log_config.log_file_path) {
            free((void*)g_log_config.log_file_path);
            g_log_config.log_file_path = NULL;
        }

        g_log_config.backends &= ~CWEBSOCKET_LOG_BACKEND_FILE;
        g_log_config.current_file_size = 0;

        log_unlock();
        return 0;
    }

    log_lock();

    // Close existing file if open
    if (g_log_config.log_file) {
        fflush(g_log_config.log_file);
        fclose(g_log_config.log_file);
        g_log_config.log_file = NULL;
    }

    // Open new file
    // Security note: fopen() is used here for log files. While there's a theoretical
    // TOCTOU race condition, it's acceptable for logging as:
    // 1. Log file paths are controlled by the application, not user input
    // 2. Symlink attacks would only affect logging, not program execution
    // 3. The file is opened in append mode, preserving existing content
    FILE *fp = fopen(path, "a");
    if (!fp) {
        log_unlock();
        return -1;
    }

    // Update configuration
    if (g_log_config.log_file_path) {
        free((void*)g_log_config.log_file_path);
    }

    g_log_config.log_file_path = strdup(path);
    g_log_config.log_file = fp;
    g_log_config.backends |= CWEBSOCKET_LOG_BACKEND_FILE;

    // Get current file size
    struct stat st;
    if (fstat(fileno(fp), &st) == 0) {
        g_log_config.current_file_size = st.st_size;
    } else {
        g_log_config.current_file_size = 0;
    }

    log_unlock();
    return 0;
}

void cwebsocket_log_set_rotation(uint64_t max_size, int max_rotations) {
    log_lock();
    g_log_config.max_file_size = max_size;
    g_log_config.max_rotations = max_rotations;
    log_unlock();
}

void cwebsocket_log_set_callback(cwebsocket_log_callback callback, void *user_data) {
    log_lock();

    g_log_config.callback = callback;
    g_log_config.user_data = user_data;

    if (callback) {
        g_log_config.backends |= CWEBSOCKET_LOG_BACKEND_CALLBACK;
    } else {
        g_log_config.backends &= ~CWEBSOCKET_LOG_BACKEND_CALLBACK;
    }

    log_unlock();
}

void cwebsocket_log_set_format(int include_timestamp, int include_level, int include_location) {
    log_lock();
    g_log_config.include_timestamp = include_timestamp;
    g_log_config.include_level = include_level;
    g_log_config.include_location = include_location;
    log_unlock();
}

int cwebsocket_log_set_thread_safe(int enable) {
    if (enable && !g_log_config.mutex) {
        pthread_mutex_t *mtx = malloc(sizeof(pthread_mutex_t));
        if (!mtx) {
            return -1;
        }

        if (pthread_mutex_init(mtx, NULL) != 0) {
            free(mtx);
            return -1;
        }

        pthread_mutex_lock(&g_log_mutex);
        g_log_config.mutex = mtx;
        g_log_config.thread_safe = 1;
        pthread_mutex_unlock(&g_log_mutex);

    } else if (!enable && g_log_config.mutex) {
        pthread_mutex_lock(&g_log_mutex);

        pthread_mutex_t *mtx = (pthread_mutex_t*)g_log_config.mutex;
        g_log_config.mutex = NULL;
        g_log_config.thread_safe = 0;

        pthread_mutex_unlock(&g_log_mutex);

        pthread_mutex_destroy(mtx);
        free(mtx);
    }

    return 0;
}

// =============================================================================
// Log Rotation
// =============================================================================

int cwebsocket_log_rotate(void) {
    if (!g_log_config.log_file_path) {
        return -1;  // No file configured
    }

    log_lock();

    // Close current file
    if (g_log_config.log_file) {
        fflush(g_log_config.log_file);
        fclose(g_log_config.log_file);
        g_log_config.log_file = NULL;
    }

    // Rotate files: log.N -> log.N+1
    // Security note: Fixed-size buffers are safe here - all uses are with snprintf()
    // which enforces bounds checking with sizeof(). Max path length is 1024 bytes.
    char old_path[1024];
    char new_path[1024];

    // Remove oldest file
    snprintf(old_path, sizeof(old_path), "%s.%d", g_log_config.log_file_path, g_log_config.max_rotations);
    unlink(old_path);  // Ignore errors

    // Rotate existing files
    for (int i = g_log_config.max_rotations - 1; i >= 1; i--) {
        snprintf(old_path, sizeof(old_path), "%s.%d", g_log_config.log_file_path, i);
        snprintf(new_path, sizeof(new_path), "%s.%d", g_log_config.log_file_path, i + 1);
        rename(old_path, new_path);  // Ignore errors
    }

    // Rotate current file to .1
    snprintf(new_path, sizeof(new_path), "%s.1", g_log_config.log_file_path);
    rename(g_log_config.log_file_path, new_path);

    // Open new file
    // Security note: See comment at line 211 - fopen() is acceptable for log rotation
    FILE *fp = fopen(g_log_config.log_file_path, "a");
    if (!fp) {
        log_unlock();
        return -1;
    }

    g_log_config.log_file = fp;
    g_log_config.current_file_size = 0;

    log_unlock();
    return 0;
}

// =============================================================================
// Core Logging Function
// =============================================================================

void cwebsocket_log_write(
    cwebsocket_log_level level,
    const char *function,
    const char *file,
    int line,
    const char *format,
    ...
) {
    // Quick check without lock for performance
    if (level > g_log_config.level) {
        return;  // Message below configured level
    }

    if (g_log_config.backends == 0) {
        return;  // No backends enabled
    }

    if (!g_log_initialized) {
        cwebsocket_log_init();
    }

    log_lock();

    // Build the log message
    // Security note: Fixed-size buffers are safe - all uses enforce bounds checking:
    // - message[4096]: used with vsnprintf(message, sizeof(message), ...)
    // - prefix[512]: used with snprintf(..., sizeof(prefix) - prefix_len, ...)
    // - timestamp[64]: used with get_timestamp(timestamp, sizeof(timestamp))
    char message[4096];
    char prefix[512];
    size_t prefix_len = 0;

    // Initialize prefix
    prefix[0] = '\0';

    // Add timestamp if enabled
    if (g_log_config.include_timestamp) {
        char timestamp[64];
        get_timestamp(timestamp, sizeof(timestamp));
        int written = snprintf(prefix + prefix_len, sizeof(prefix) - prefix_len, "%s ", timestamp);
        if (written > 0 && (size_t)written < sizeof(prefix) - prefix_len) {
            prefix_len += written;
        }
    }

    // Add log level if enabled
    if (g_log_config.include_level) {
        const char *level_str = cwebsocket_log_level_to_string(level);
        int written = snprintf(prefix + prefix_len, sizeof(prefix) - prefix_len, "[%s] ", level_str);
        if (written > 0 && (size_t)written < sizeof(prefix) - prefix_len) {
            prefix_len += written;
        }
    }

    // Add location if enabled
    if (g_log_config.include_location) {
        snprintf(prefix + prefix_len, sizeof(prefix) - prefix_len, "[%s:%d] ", basename_safe(file), line);
    }

    // Format the message
    // Security note: vsnprintf is safe here because format strings come from
    // MQTT_LOG_* macros in our codebase, not from user input. Buffer size is
    // properly enforced (4096 bytes) to prevent overflow.
    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);

    // Write to syslog backend
    if (g_log_config.backends & CWEBSOCKET_LOG_BACKEND_SYSLOG) {
        int priority = cwebsocket_log_level_to_syslog(level);
        syslog(priority, "%s%s", prefix, message);
    }

    // Write to file backend
    if ((g_log_config.backends & CWEBSOCKET_LOG_BACKEND_FILE) && g_log_config.log_file) {
        size_t written = fprintf(g_log_config.log_file, "%s%s\n", prefix, message);
        fflush(g_log_config.log_file);

        g_log_config.current_file_size += written;

        // Check if rotation is needed
        if (should_rotate_file()) {
            log_unlock();
            cwebsocket_log_rotate();
            log_lock();
        }
    }

    // Write to stderr backend
    if (g_log_config.backends & CWEBSOCKET_LOG_BACKEND_STDERR) {
        fprintf(stderr, "%s%s\n", prefix, message);
        fflush(stderr);
    }

    // Call custom callback
    if ((g_log_config.backends & CWEBSOCKET_LOG_BACKEND_CALLBACK) && g_log_config.callback) {
        va_list args_copy;
        va_start(args_copy, format);
        g_log_config.callback(level, function, file, line, format, args_copy);
        va_end(args_copy);
    }

    log_unlock();
}

// =============================================================================
// Utility Functions
// =============================================================================

const char* cwebsocket_log_level_to_string(cwebsocket_log_level level) {
    switch (level) {
        case CWEBSOCKET_LOG_LEVEL_NONE:  return "NONE";
        case CWEBSOCKET_LOG_LEVEL_ERROR: return "ERROR";
        case CWEBSOCKET_LOG_LEVEL_WARN:  return "WARN";
        case CWEBSOCKET_LOG_LEVEL_INFO:  return "INFO";
        case CWEBSOCKET_LOG_LEVEL_DEBUG: return "DEBUG";
        case CWEBSOCKET_LOG_LEVEL_TRACE: return "TRACE";
        default: return "UNKNOWN";
    }
}

cwebsocket_log_level cwebsocket_log_string_to_level(const char *str) {
    if (!str) return CWEBSOCKET_LOG_LEVEL_NONE;

    if (strcasecmp(str, "ERROR") == 0) return CWEBSOCKET_LOG_LEVEL_ERROR;
    if (strcasecmp(str, "WARN") == 0)  return CWEBSOCKET_LOG_LEVEL_WARN;
    if (strcasecmp(str, "INFO") == 0)  return CWEBSOCKET_LOG_LEVEL_INFO;
    if (strcasecmp(str, "DEBUG") == 0) return CWEBSOCKET_LOG_LEVEL_DEBUG;
    if (strcasecmp(str, "TRACE") == 0) return CWEBSOCKET_LOG_LEVEL_TRACE;
    if (strcasecmp(str, "NONE") == 0)  return CWEBSOCKET_LOG_LEVEL_NONE;

    return CWEBSOCKET_LOG_LEVEL_NONE;
}

int cwebsocket_log_level_to_syslog(cwebsocket_log_level level) {
    switch (level) {
        case CWEBSOCKET_LOG_LEVEL_ERROR: return LOG_ERR;
        case CWEBSOCKET_LOG_LEVEL_WARN:  return LOG_WARNING;
        case CWEBSOCKET_LOG_LEVEL_INFO:  return LOG_INFO;
        case CWEBSOCKET_LOG_LEVEL_DEBUG: return LOG_DEBUG;
        case CWEBSOCKET_LOG_LEVEL_TRACE: return LOG_DEBUG;
        default: return LOG_INFO;
    }
}

void cwebsocket_log_flush(void) {
    log_lock();

    if (g_log_config.log_file) {
        fflush(g_log_config.log_file);
    }

    log_unlock();
}
