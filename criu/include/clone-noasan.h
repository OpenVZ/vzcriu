#ifndef __CR_CLONE_NOASAN_H__
#define __CR_CLONE_NOASAN_H__

int clone_noasan(int (*fn)(void *), int flags, void *arg);
int clone_noasan_vm(int (*fn)(void *), void *stack, int flags, void *arg);

#endif /* __CR_CLONE_NOASAN_H__ */
