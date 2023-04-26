#ifndef __CR_SK_QUEUE_H__
#define __CR_SK_QUEUE_H__

extern struct collect_image_info sk_queues_cinfo;

#define SK_QUEUE_DUMP_ADDR 0x2 /* save a sender address for messages */
extern int dump_sk_queue(int sock_fd, int sock_id, int flags);
extern int restore_sk_queue(int fd, unsigned int peer_id);

#endif /* __CR_SK_QUEUE_H__ */
