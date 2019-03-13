#ifndef __CR_ISTOR_CLIENT_H__
#define __CR_ISTOR_CLIENT_H__

struct cr_options;
struct cr_img;

extern int istor_client_write_img_buf(struct cr_img *img, const void *ptr, int size);
extern int istor_client_read_img_buf_eof(struct cr_img *img, void *ptr, int size);
extern off_t istor_client_img_raw_size(struct cr_img *img);

extern int istor_client_do_open_image(struct cr_img *img, int dfd, int type,
				      unsigned long oflags, const char *path);
extern int istor_client_init(struct cr_options *opts, bool store_mode);
extern void istor_client_fini(void);

#endif /* __CR_ISTOR_CLIENT_H__ */
