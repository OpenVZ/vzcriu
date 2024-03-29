#ifndef __CR_FIFO_H__
#define __CR_FIFO_H__

struct fd_parms;
struct cr_imgset;

extern const struct fdtype_ops fifo_dump_ops;
extern struct collect_image_info fifo_cinfo;
extern struct collect_image_info fifo_data_cinfo;

struct pipe_data_dump;
extern void pipe_data_dump_fini(struct pipe_data_dump *pdd);
extern int fifo_dump_init(void);
extern void fifo_dump_fini(void);

#endif /* __CR_FIFO_H__ */
