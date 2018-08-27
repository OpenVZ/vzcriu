#ifndef UAPI_COMPEL_CPU_H__
#define UAPI_COMPEL_CPU_H__

#include <stdbool.h>

#include <compel/asm/cpu.h>

extern int compel_cpuid(compel_cpuinfo_t *info);
extern bool compel_cpu_has_feature(unsigned int feature);
extern void compel_cpu_clear_feature(unsigned int feature);
extern void compel_cpu_copy_cpuinfo(compel_cpuinfo_t *c);

extern int vz_cpu_parse_cpuid_override(void);

#endif /* UAPI_COMPEL_CPU_H__ */
