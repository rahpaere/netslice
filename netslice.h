#ifndef __NETSLICE_H__
#define __NETSLICE_H__

#ifndef __KERNEL__
#include <sys/types.h>
#include <linux/filter.h>
#endif

#define NETSLICE_NAME_SIZE 64

typedef char netslice_name_t[NETSLICE_NAME_SIZE];

struct netslice_filter {
	char name[NETSLICE_NAME_SIZE];
	uint8_t hooks;
	struct sock_fprog fp;
};

struct netslice_queue {
	struct sk_buff_head pending;
	unsigned long total;
	unsigned long dropped;
	wait_queue_head_t wait;
} ___cache_aligned_on_smp;

struct netslice {
	char name[NETSLICE_NAME_SIZE];
	atomic_t references;
	struct list_head list;

	struct netslice_queue rx[NR_CPUS];
	struct netslice_queue tx[NR_CPUS];

	uint8_t hooks;
	struct net *net;
	struct sk_filter *skf;
};

struct netslice_handle {
	struct netslice *netslice;
	int cpu;
};

#define NETSLICE_CPU_SET _IOW('p', 0x01, int)
#define NETSLICE_CPU_GET _IOR('p', 0x02, int)
#define NETSLICE_CREATE _IOW('p', 0x05, struct netslice_filter)
#define NETSLICE_ATTACH _IOR('p', 0x06, char *)
#define NETSLICE_DESTROY _IOR('p', 0x06, char *)

#endif
