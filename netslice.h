#ifndef __NETSLICE_H__
#define __NETSLICE_H__

#ifndef __KERNEL__
#include <sys/types.h>
#include <linux/filter.h>
#endif

#define NETSLICE_NAME_SIZE 64

struct netslice_filter {
	uint8_t hooks;
	struct sock_fprog filter;
	char name[NETSLICE_NAME_SIZE];
};

struct netslice_queue {
	struct sk_buff_head skbs;
	unsigned long bytes;
	unsigned long dropped;
	unsigned long total;
	wait_queue_head_t wait;
};

struct netslice {
	struct list_head netslices;
	char name[NETSLICE_NAME_SIZE];
	atomic_t references;

	uint8_t hooks;
	struct net *net;
	struct sk_filter *filter;

	struct netslice_queue *read_queue[NR_CPUS];
	struct netslice_queue *write_queue[NR_CPUS];
};

struct netslice_handle {
	struct netslice *netslice;
	int cpu;
};

enum netslice_pre_tx_csum {
	NETSLICE_PRE_TX_CSUM_NONE,
	NETSLICE_PRE_TX_CSUM_IP,
	NETSLICE_PRE_TX_CSUM_TRANSPORT,
	NETSLICE_PRE_TX_CSUM_MAX,
};

#define NETSLICE_CPU_SET _IOW('p', 0x01, int)
#define NETSLICE_CPU_GET _IOR('p', 0x02, int)
#define NETSLICE_PRE_TX_CSUM_SET _IOW('p', 0x03, int)
#define NETSLICE_PRE_TX_CSUM_GET _IOR('p', 0x04, int)
#define NETSLICE_ATTACH_FILTER _IOW('p', 0x05, struct netslice_filter)
#define NETSLICE_DETACH_FILTER _IOR('p', 0x06, int)

#endif
