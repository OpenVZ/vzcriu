#ifndef __CR_ISTOR_RWLOCK_H__
#define __CR_ISTOR_RWLOCK_H__

#include "common/lock.h"

typedef struct {
	futex_t		f;
} istor_rwlock_t;

extern void istor_rwlock_init(istor_rwlock_t *lock);
extern void istor_read_lock(istor_rwlock_t *lock);
extern void istor_read_unlock(istor_rwlock_t *lock);
extern void istor_write_lock(istor_rwlock_t *lock);
extern void istor_write_unlock(istor_rwlock_t *lock);

#endif /* __CR_ISTOR_RWLOCK_H__ */
