#include <syslog.h>
#include <stdarg.h>

#include "cr-syslog.h"

void pr_syslog(const char *format, ...)
{
	static int open = 0;
	va_list params;

	if (!open) {
		open = 1;
		openlog("criu", LOG_PID, LOG_DAEMON);
	}

	va_start(params, format);
	vsyslog(LOG_NOTICE, format, params);
	va_end(params);
}
