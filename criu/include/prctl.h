#ifndef __CR_PRCTL_H__
#define __CR_PRCTL_H__

#include "int.h"

#ifndef PR_SET_NAME
# define PR_SET_NAME		15
#endif
#ifndef PR_GET_NAME
# define PR_GET_NAME		16
#endif
#ifndef PR_SET_SECCOMP
# define PR_SET_SECCOMP		22
#endif
#ifndef PR_CAPBSET_READ
# define PR_CAPBSET_READ	23
#endif
#ifndef PR_CAPBSET_DROP
# define PR_CAPBSET_DROP	24
#endif
#ifndef PR_GET_SECUREBITS
# define PR_GET_SECUREBITS	27
#endif
#ifndef PR_SET_SECUREBITS
# define PR_SET_SECUREBITS	28
#endif
#ifndef PR_GET_DUMPABLE
# define PR_GET_DUMPABLE	3
#endif
#ifndef PR_SET_DUMPABLE
# define PR_SET_DUMPABLE	4
#endif

#ifndef PR_SET_MM
#define PR_SET_MM		35
# define PR_SET_MM_START_CODE		1
# define PR_SET_MM_END_CODE		2
# define PR_SET_MM_START_DATA		3
# define PR_SET_MM_END_DATA		4
# define PR_SET_MM_START_STACK		5
# define PR_SET_MM_START_BRK		6
# define PR_SET_MM_BRK			7
# define PR_SET_MM_ARG_START		8
# define PR_SET_MM_ARG_END		9
# define PR_SET_MM_ENV_START		10
# define PR_SET_MM_ENV_END		11
# define PR_SET_MM_AUXV			12
# define PR_SET_MM_EXE_FILE		13
#endif

#ifndef PR_SET_MM_MAP
# define PR_SET_MM_MAP			14
# define PR_SET_MM_MAP_SIZE		15

struct prctl_mm_map {
	u64	start_code;
	u64	end_code;
	u64	start_data;
	u64	end_data;
	u64	start_brk;
	u64	brk;
	u64	start_stack;
	u64	arg_start;
	u64	arg_end;
	u64	env_start;
	u64	env_end;
	u64	*auxv;
	u32	auxv_size;
	u32	exe_fd;
};
#endif

#ifndef PR_GET_TID_ADDRESS
# define PR_GET_TID_ADDRESS	40
#endif

#ifndef PR_SET_THP_DISABLE
# define PR_SET_THP_DISABLE	41
#endif

#ifndef PR_GET_THP_DISABLE
# define PR_GET_THP_DISABLE	42
#endif

#ifndef PR_SET_TASK_CT_FIELDS
/* Set task container related fields */
#define PR_SET_TASK_CT_FIELDS	1000
#endif

#ifndef PR_TASK_CT_FIELDS_START_BOOTTIME
#define PR_TASK_CT_FIELDS_START_BOOTTIME	(1ULL << 0)

struct _prctl_task_ct_fields {
	s64 start_boottime;
};
#else
#define _prctl_task_ct_fields prctl_task_ct_fields
#endif

#endif /* __CR_PRCTL_H__ */
