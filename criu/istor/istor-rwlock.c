#include <stdint.h>

#include "istor/istor-rwlock.h"
#include "criu-log.h"

#ifdef LOG_PREFIX
# undef LOG_PREFIX
#endif

#define LOG_PREFIX "istor-lock: "

#define rlock_prefix		"rdlock"
#define runlock_prefix		"rdunlck"
#define wlock_prefix		"wrlock"
#define wunlock_prefix		"wrunlck"

#define rlock_prefix_enter	rlock_prefix"  > "
#define rlock_prefix_exit	rlock_prefix"  < "

#define runlock_prefix_enter	runlock_prefix" > "
#define runlock_prefix_exit	runlock_prefix" < "

#define wlock_prefix_enter	wlock_prefix"  > "
#define wlock_prefix_exit	wlock_prefix"  < "

#define wunlock_prefix_enter	wunlock_prefix" > "
#define wunlock_prefix_exit	wunlock_prefix" < "

#define _ISTOR_WLOCK		((uint32_t)1 << 0)
#define _ISTOR_WMASK		(_ISTOR_WLOCK)
#define _ISTOR_RMASK		(~_ISTOR_WMASK)
#define _ISTOR_SHIFT		1
#define _ISTOR_BIAS		(1u << _ISTOR_SHIFT)

static inline void cpu_relax(void)
{
#if defined(CONFIG_X86_64)
	asm volatile("rep; nop" ::: "memory");
#else
	BUILD_BUG_ON(1);
#endif
}

static void wake_waters(istor_rwlock_t *lock)
{
	LOCK_BUG_ON(sys_futex((uint32_t *)&lock->f.raw.counter,
			      FUTEX_WAKE, INT_MAX, NULL, NULL, 0) < 0);
}

static void pr_debug_stat(const char * const prefix, const istor_rwlock_t * const lock)
{
	if (!pr_quelled(LOG_DEBUG)) {
		uint32_t v = atomic_read(&lock->f.raw);
		pr_debug("%s%p pid %8d counter (r %8d w %2d)\n",
			 prefix, lock, getpid(), (v / _ISTOR_BIAS),
			 (v & _ISTOR_WMASK));
	}
}

void istor_read_lock(istor_rwlock_t *lock)
{
	pr_debug_stat(rlock_prefix_enter, lock);
	for (;;) {
		uint32_t v = atomic_add_return(_ISTOR_BIAS, &lock->f.raw);
		if (!(v & _ISTOR_WMASK))
			break;
		/* wait for writers to complete */
		atomic_sub_return(_ISTOR_BIAS, &lock->f.raw);
		futex_wait_if_not_cond(&lock->f, _ISTOR_WMASK, &);
	}
	pr_debug_stat(rlock_prefix_exit, lock);
}

void istor_read_unlock(istor_rwlock_t *lock)
{
	uint32_t v;

	pr_debug_stat(runlock_prefix_enter, lock);
	v = atomic_sub_return(_ISTOR_BIAS, &lock->f.raw);
	/* only last reader notify writers */
	if (!(v & _ISTOR_RMASK))
		wake_waters(lock);
	pr_debug_stat(runlock_prefix_exit, lock);
}

void istor_write_lock(istor_rwlock_t *lock)
{
	uint32_t n, v;
	pr_debug_stat(wlock_prefix_enter, lock);
	for (;;) {
		n = v = atomic_read(&lock->f.raw);
		if (v & _ISTOR_WMASK) {
			pr_debug_stat(wlock_prefix" wait _ISTOR_WMASK ", lock);
			futex_wait_if_not_cond(&lock->f, _ISTOR_WMASK, &);
			continue;
		}

		v = atomic_cmpxchg(&lock->f.raw, n, v + _ISTOR_WLOCK);
		if (v == n) {
			if (v & _ISTOR_RMASK)
				pr_debug_stat(wlock_prefix" wait _ISTOR_RMASK ", lock);
			futex_wait_if_not_cond(&lock->f, _ISTOR_RMASK, &);
			break;
		}
		pr_debug_stat(wlock_prefix" relax ", lock);
		cpu_relax();
	}
	pr_debug_stat(wlock_prefix_exit, lock);
}

void istor_write_unlock(istor_rwlock_t *lock)
{
	pr_debug_stat(wunlock_prefix_enter, lock);
	atomic_sub(_ISTOR_WLOCK, &lock->f.raw);
	pr_debug_stat(wunlock_prefix_exit, lock);
	wake_waters(lock);
}

void istor_rwlock_init(istor_rwlock_t *lock)
{
	futex_init(&lock->f);
}
