#include <stdlib.h>
#if !defined(CONFIG_PLATFORM_8711B)
#include <sys/time.h>
#endif
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "logger.h"

#if WITH_LOGGLY
#include "esp_request.h"
#endif

static char buffer[256];

#if WITH_LOGGLY
static int32_t len_to_send;
#endif

int32_t log_timestamp(void)
{
	struct timeval tv;
	static long int last_sec = 0;
	static int32_t cummulative = 0;
	int32_t time_elapsed;

	gettimeofday(&tv,NULL);
	time_elapsed = tv.tv_sec - last_sec;
	if(time_elapsed > 10000){
		time_elapsed = 0;
	}
	cummulative += time_elapsed;
	last_sec = tv.tv_sec;
	return cummulative;
}

#if WITH_LOGGLY

static int log_upload_callback(request_t *req, char *data, int len)
{
	return len;
}

void log_send_to_loggly(const char *buf)
{
	request_t *req;
	const char *url = "http://logs-01.loggly.com/inputs/84825cee-bd9c-4acb-a521-b4fed186cf7d/tag/http/";

	req = req_new(url);
	req_setopt(req, REQ_SET_METHOD, "GET");
	req_setopt(req, REQ_FUNC_UPLOAD_CB, log_upload_callback);
	req_perform(req);
	req_clean(req);
}

#endif // WITH_LOGGLY

void log_printf(char * format, ...)
{
	va_list args;
	va_start (args, format);
	vsnprintf (buffer, 255, format, args);
	va_end (args);

	printf("%s", buffer);
#if WITH_LOGGLY

	len_to_send = strlen(buffer);

#endif // WITH_LOGGLY
}
