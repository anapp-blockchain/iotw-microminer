#ifndef _LOGGER_H
#define _LOGGER_H

#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#if __GNUC__ > 3

#include <stdint.h>
#include <inttypes.h>
#if !defined(ESP8266_SDK_VERSION_2)
#include <sys/time.h>
#endif //!defined(ESP8266_SDK_VERSION_2)

#elif defined(CONFIG_PLATFORM_8711B) // __GNUC__ > 3

#include <stdint.h>
#include <inttypes.h>
#include <local_time.h>

#endif //defined(CONFIG_PLATFORM_8711B)

#define WITH_LOGGLY         (0)

#if !defined(ESP8266_SDK_VERSION_2)

int32_t log_timestamp(void);

#define LOG_COLOR_BLACK   "30"
#define LOG_COLOR_RED     "31"
#define LOG_COLOR_GREEN   "32"
#define LOG_COLOR_BROWN   "33"
#define LOG_COLOR_BLUE    "34"
#define LOG_COLOR_PURPLE  "35"
#define LOG_COLOR_CYAN    "36"
#define LOG_COLOR(COLOR)  "\033[0;" COLOR "m"
#define LOG_BOLD(COLOR)   "\033[1;" COLOR "m"
#define LOG_RESET_COLOR   "\033[0m"
#define LOG_COLOR_E       LOG_COLOR(LOG_COLOR_RED)
#define LOG_COLOR_W       LOG_COLOR(LOG_COLOR_BROWN)
#define LOG_COLOR_I       LOG_COLOR(LOG_COLOR_GREEN)
#define LOG_COLOR_D
#define LOG_COLOR_V

#ifndef PRId32
#define PRId32 "ld" 
#endif

#define LOG_FORMAT(letter, format)  LOG_COLOR_ ## letter #letter " (%" PRId32 ") %s: " format LOG_RESET_COLOR "\n"

#define DBG_LOGI(tag, format, ...) {printf(LOG_FORMAT(I, format), log_timestamp(), tag, ##__VA_ARGS__); }
#define DBG_LOGW(tag, format, ...) {printf(LOG_FORMAT(W, format), log_timestamp(), tag, ##__VA_ARGS__); }
#define DBG_LOGD(tag, format, ...) {printf(LOG_FORMAT(D, format), log_timestamp(), tag, ##__VA_ARGS__); }
#define DBG_LOGE(tag, format, ...) {printf(LOG_FORMAT(E, format), log_timestamp(), tag, ##__VA_ARGS__); }

#else //!defined(ESP8266_SDK_VERSION_2)

#define DBG_LOGI(tag, format, ...) {printf("I (%s): " format "\n", tag, ##__VA_ARGS__); }
#define DBG_LOGW(tag, format, ...) {printf("W (%s): " format "\n", tag, ##__VA_ARGS__); }
#define DBG_LOGD(tag, format, ...) {printf("D (%s): " format "\n", tag, ##__VA_ARGS__); }
#define DBG_LOGE(tag, format, ...) {printf("E (%s): " format "\n", tag, ##__VA_ARGS__); }

#endif //!defined(ESP8266_SDK_VERSION_2)

#endif // _LOGGER_H
