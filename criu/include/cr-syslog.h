#ifndef __CR_SYSLOG_H__
#define __CR_SYSLOG_H__

/*
 * pr_syslog can't be added into log.h, because LOG_* constants
 * are defined in criu and in <syslog.h>.
 */

extern void pr_syslog(const char *format, ...);

#endif
