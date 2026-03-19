/*
 * log.h - Lightweight logging macros for slaacbot.
 *
 * Uses fprintf(stderr, ...) with timestamp and level tag.
 * Set g_log_level at startup to control verbosity.
 */
#pragma once

#include <cstdio>
#include <ctime>

enum LogLevel { LOG_DEBUG = 0, LOG_INFO, LOG_WARN, LOG_ERROR };

inline LogLevel g_log_level = LOG_INFO;

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
#elif defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
#endif

#define LOG(level, fmt, ...)                                                  \
    do {                                                                      \
        if ((level) >= g_log_level) {                                         \
            time_t _t = time(nullptr);                                        \
            struct tm _tm;                                                    \
            localtime_r(&_t, &_tm);                                           \
            char _tbuf[32];                                                   \
            strftime(_tbuf, sizeof(_tbuf), "%Y-%m-%d %H:%M:%S", &_tm);       \
            const char *_lvl[] = {"DBG", "INF", "WRN", "ERR"};         \
            fprintf(stderr, "[%s] [%s] " fmt "\n", _tbuf, _lvl[(level)],  \
                    ##__VA_ARGS__);                                           \
        }                                                                     \
    } while (0)

#define LOG_DBG(fmt, ...) LOG(LOG_DEBUG, fmt, ##__VA_ARGS__)
#define LOG_INF(fmt, ...) LOG(LOG_INFO,  fmt, ##__VA_ARGS__)
#define LOG_WRN(fmt, ...) LOG(LOG_WARN,  fmt, ##__VA_ARGS__)
#define LOG_ERR(fmt, ...) LOG(LOG_ERROR, fmt, ##__VA_ARGS__)

#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
