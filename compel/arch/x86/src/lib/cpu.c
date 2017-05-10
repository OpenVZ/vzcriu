#include <string.h>
#include <stdbool.h>

#include <stdio.h>
#include <stdlib.h>

#include "compel-cpu.h"
#include "common/bitops.h"
#include "common/compiler.h"

#include "log.h"

#undef	LOG_PREFIX
#define LOG_PREFIX "cpu: "

static compel_cpuinfo_t rt_info;
static bool rt_info_done = false;

void compel_set_cpu_cap(compel_cpuinfo_t *c, unsigned int feature)
{
	if (likely(feature < NCAPINTS_BITS))
		set_bit(feature, (unsigned long *)c->x86_capability);
}

void compel_clear_cpu_cap(compel_cpuinfo_t *c, unsigned int feature)
{
	if (likely(feature < NCAPINTS_BITS))
		clear_bit(feature, (unsigned long *)c->x86_capability);
}

int compel_test_cpu_cap(compel_cpuinfo_t *c, unsigned int feature)
{
	if (likely(feature < NCAPINTS_BITS))
		return test_bit(feature, (unsigned long *)c->x86_capability);
	return 0;
}

/*
 * VZ specific cpuid VE masking: the kernel provides
 * the following entry /proc/vz/cpuid_override which
 * carries text representation of cpuid masking which
 * which works via cpuid faulting inside kernel in the
 * next format:
 *
 *	op     count   eax    ebx    ecx    edx
 * 	0x%08x 0x%08x: 0x%08x 0x%08x 0x%08x 0x%08x
 *
 * the @count is optional.
 */

typedef struct {
	unsigned int	op;
	unsigned int	count;
	bool		has_count;
	unsigned int	eax;
	unsigned int	ebx;
	unsigned int	ecx;
	unsigned int	edx;
} vz_cpuid_override_entry_t;

static vz_cpuid_override_entry_t *vz_cpuid_override_entries;
static unsigned int nr_vz_cpuid_override_entries;

int vz_cpu_parse_cpuid_override(void)
{
	static const char path[] = "/proc/vz/cpuid_override";
	int ret = -1;
	char s[256];
	FILE *f;

	pr_debug("Parsing %s\n", path);

	f = fopen(path, "r");
	if (!f) {
		pr_info("Can't access %s, ignoring\n", path);
			return 0;
	}

	while (fgets(s, sizeof(s), f)) {
		static vz_cpuid_override_entry_t *new;

		vz_cpuid_override_entry_t e;

		if (sscanf(s, "%x %x: %x %x %x %x",
			   &e.op, &e.count, &e.eax,
			   &e.ebx, &e.ecx, &e.edx) == 6)
			e.has_count = true;
		else if (sscanf(s, "%x: %x %x %x %x",
				&e.op, &e.eax, &e.ebx,
				&e.ecx, &e.edx) == 5) {
			e.count = 0;
			e.has_count = false;
		} else {
			pr_warn("Unexpected format in %s (%s)\n", path, s);
			break;
		}

		new = realloc(vz_cpuid_override_entries,
			      (nr_vz_cpuid_override_entries + 1) * sizeof(e));
		if (!new) {
			pr_err("No memory for cpuid override (%d entries)\n",
			       nr_vz_cpuid_override_entries + 1);
			goto out;
		}
		vz_cpuid_override_entries = new;

		pr_debug("Got cpuid override: %x %x: %x %x %x %x\n",
			   e.op, e.count, e.eax, e.ebx, e.ecx, e.edx);

		vz_cpuid_override_entries[nr_vz_cpuid_override_entries++] = e;
	}

	ret = 0;
out:
	fclose(f);
	return ret;
}

static vz_cpuid_override_entry_t *vz_cpuid_override_lookup(unsigned int op,
							   bool has_count,
							   unsigned int count)
{
	size_t i;

	for (i = 0; i < nr_vz_cpuid_override_entries; i++) {
		if (vz_cpuid_override_entries[i].op != op ||
		    vz_cpuid_override_entries[i].has_count != has_count ||
		    count != vz_cpuid_override_entries[i].count)
			continue;
		return &vz_cpuid_override_entries[i];
	}

	return NULL;
}

static inline void vz_cpuid(unsigned int op,
			    unsigned int *eax, unsigned int *ebx,
			    unsigned int *ecx, unsigned int *edx)
{
	vz_cpuid_override_entry_t *e;

	e = vz_cpuid_override_lookup(op, false, 0);
	if (e) {
		*eax = e->eax;
		*ebx = e->ebx;
		*ecx = e->ecx;
		*edx = e->edx;
	} else
		cpuid(op, eax, ebx, ecx, edx);
}

static inline void vz_cpuid_count(unsigned int op, int count,
				  unsigned int *eax, unsigned int *ebx,
				  unsigned int *ecx, unsigned int *edx)
{
	vz_cpuid_override_entry_t *e;

	e = vz_cpuid_override_lookup(op, true, count);
	if (e) {
		*eax = e->eax;
		*ebx = e->ebx;
		*ecx = e->ecx;
		*edx = e->edx;
	 } else
		 cpuid_count(op, count, eax, ebx, ecx, edx);
}

static inline unsigned int vz_cpuid_eax(unsigned int op)
{
	unsigned int eax, ebx, ecx, edx;

	vz_cpuid(op, &eax, &ebx, &ecx, &edx);
	return eax;
}

static inline unsigned int vz_cpuid_ecx(unsigned int op)
{
	unsigned int eax, ebx, ecx, edx;

	vz_cpuid(op, &eax, &ebx, &ecx, &edx);
	return ecx;
}

static inline unsigned int vz_cpuid_edx(unsigned int op)
{
	unsigned int eax, ebx, ecx, edx;

	vz_cpuid(op, &eax, &ebx, &ecx, &edx);
	return edx;
}

int compel_cpuid(compel_cpuinfo_t *c)
{
	/*
	 * See cpu_detect() in the kernel, also
	 * read cpuid specs not only from general
	 * SDM but for extended instructions set
	 * reference.
	 */

	/* Get vendor name */
	vz_cpuid(0x00000000,
	      (unsigned int *)&c->cpuid_level,
	      (unsigned int *)&c->x86_vendor_id[0],
	      (unsigned int *)&c->x86_vendor_id[8],
	      (unsigned int *)&c->x86_vendor_id[4]);

	if (!strcmp(c->x86_vendor_id, "GenuineIntel")) {
		c->x86_vendor = X86_VENDOR_INTEL;
	} else if (!strcmp(c->x86_vendor_id, "AuthenticAMD")) {
		c->x86_vendor = X86_VENDOR_AMD;
	} else {
		pr_err("Unsupported CPU vendor %s\n",
		       c->x86_vendor_id);
		return -1;
	}

	c->x86_family = 4;

	/* Intel-defined flags: level 0x00000001 */
	if (c->cpuid_level >= 0x00000001) {
		uint32_t eax, ebx, ecx, edx;

		vz_cpuid(0x00000001, &eax, &ebx, &ecx, &edx);
		c->x86_family = (eax >> 8) & 0xf;
		c->x86_model = (eax >> 4) & 0xf;
		c->x86_mask = eax & 0xf;

		if (c->x86_family == 0xf)
			c->x86_family += (eax >> 20) & 0xff;
		if (c->x86_family >= 0x6)
			c->x86_model += ((eax >> 16) & 0xf) << 4;

		c->x86_capability[0] = edx;
		c->x86_capability[4] = ecx;
	}

	/* Additional Intel-defined flags: level 0x00000007 */
	if (c->cpuid_level >= 0x00000007) {
		uint32_t eax, ebx, ecx, edx;

		vz_cpuid_count(0x00000007, 0, &eax, &ebx, &ecx, &edx);
		c->x86_capability[9] = ebx;
		c->x86_capability[11] = ecx;
	}

	/* Extended state features: level 0x0000000d */
	if (c->cpuid_level >= 0x0000000d) {
		uint32_t eax, ebx, ecx, edx;

		vz_cpuid_count(0x0000000d, 1, &eax, &ebx, &ecx, &edx);
		c->x86_capability[10] = eax;
	}

	/* AMD-defined flags: level 0x80000001 */
	c->extended_cpuid_level = cpuid_eax(0x80000000);

	if ((c->extended_cpuid_level & 0xffff0000) == 0x80000000) {
		if (c->extended_cpuid_level >= 0x80000001) {
			c->x86_capability[1] = vz_cpuid_edx(0x80000001);
			c->x86_capability[6] = vz_cpuid_ecx(0x80000001);
		}
	}

	/*
	 * We're don't care about scattered features for now,
	 * otherwise look into init_scattered_cpuid_features()
	 * in kernel.
	 */

	if (c->extended_cpuid_level >= 0x80000004) {
		unsigned int *v;
		char *p, *q;
		v = (unsigned int *)c->x86_model_id;
		vz_cpuid(0x80000002, &v[0], &v[1], &v[2], &v[3]);
		vz_cpuid(0x80000003, &v[4], &v[5], &v[6], &v[7]);
		vz_cpuid(0x80000004, &v[8], &v[9], &v[10], &v[11]);
		c->x86_model_id[48] = 0;

		/*
		 * Intel chips right-justify this string for some dumb reason;
		 * undo that brain damage:
		 */
		p = q = &c->x86_model_id[0];
		while (*p == ' ')
			p++;
		if (p != q) {
			while (*p)
				*q++ = *p++;
			while (q <= &c->x86_model_id[48])
				*q++ = '\0';	/* Zero-pad the rest */
		}
	}

	/* On x86-64 NOP is always present */
	compel_set_cpu_cap(c, X86_FEATURE_NOPL);

	switch (c->x86_vendor) {
	case X86_VENDOR_INTEL:
		/*
		 * Strictly speaking we need to read MSR_IA32_MISC_ENABLE
		 * here but on ring3 it's impossible.
		 */
		if (c->x86_family == 15) {
			compel_clear_cpu_cap(c, X86_FEATURE_REP_GOOD);
			compel_clear_cpu_cap(c, X86_FEATURE_ERMS);
		} else if (c->x86_family == 6) {
			/* On x86-64 rep is fine */
			compel_set_cpu_cap(c, X86_FEATURE_REP_GOOD);
		}

		/* See filter_cpuid_features in kernel */
		if ((int32_t)c->cpuid_level < (int32_t)0x0000000d)
			compel_clear_cpu_cap(c, X86_FEATURE_XSAVE);
		break;
	case X86_VENDOR_AMD:
		/*
		 * Bit 31 in normal CPUID used for nonstandard 3DNow ID;
		 * 3DNow is IDd by bit 31 in extended CPUID (1*32+31) anyway
		 */
		compel_clear_cpu_cap(c, 0 * 32 + 31);
		if (c->x86_family >= 0x10)
			compel_set_cpu_cap(c, X86_FEATURE_REP_GOOD);
		if (c->x86_family == 0xf) {
			uint32_t level;

			/* On C+ stepping K8 rep microcode works well for copy/memset */
			level = cpuid_eax(1);
			if ((level >= 0x0f48 && level < 0x0f50) || level >= 0x0f58)
				compel_set_cpu_cap(c, X86_FEATURE_REP_GOOD);
		}
		break;
	}

	return 0;
}

bool compel_cpu_has_feature(unsigned int feature)
{
	if (!rt_info_done) {
		compel_cpuid(&rt_info);
		rt_info_done = true;
	}
	return compel_test_cpu_cap(&rt_info, feature);
}
