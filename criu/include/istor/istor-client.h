#ifndef __CR_ISTOR_CLIENT_H__
#define __CR_ISTOR_CLIENT_H__

struct cr_options;

extern int istor_client_init(struct cr_options *opts);
extern void istor_client_fini(void);

#endif /* __CR_ISTOR_CLIENT_H__ */
