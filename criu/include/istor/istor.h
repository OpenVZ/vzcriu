#ifndef __CR_ISTOR_H__
#define __CR_ISTOR_H__

#include "istor/istor-api.h"
#include "istor/istor-dock.h"

struct cr_options;

extern void istor_map_opts(const struct cr_options *s, istor_opts_t *d);
extern int istor_server(istor_opts_t *opts);

extern int istor_setup_images(const struct cr_options *s);

#endif /* __CR_ISTOR_H__ */
