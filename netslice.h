#ifndef __NETSLICE_H__
#define __NETSLICE_H__

#ifndef __KERNEL__
#include <sys/types.h>
#include <linux/filter.h>
#endif

enum netslice_pre_tx_csum {
	NETSLICE_PRE_TX_CSUM_NONE,
	NETSLICE_PRE_TX_CSUM_IP,
	NETSLICE_PRE_TX_CSUM_TRANSPORT,
	NETSLICE_PRE_TX_CSUM_MAX,
};

enum netslice_iov_flags {
	NETSLICE_IOV_SKIP_PACKET_MASK = 0x1,
	NETSLICE_IOV_CSUM_MASK = 0x2,
	NETSLICE_IOV_CSUM_TRANSPORT_MASK = 0x4,
};

struct netslice_iov {
	void *iov_base;
	size_t iov_len;
	size_t iov_rlen;
	int flags;
};

struct netslice_filter {
	struct sock_filter *filter;
	size_t len;
	int hook;
};

#define NETSLICE_CPU_SET _IOW('p', 0x01, int)
#define NETSLICE_CPU_GET _IOR('p', 0x02, int)
#define NETSLICE_PRE_TX_CSUM_SET _IOW('p', 0x03, int)
#define NETSLICE_PRE_TX_CSUM_GET _IOR('p', 0x04, int)
#define NETSLICE_ATTACH_FILTER _IOW('p', 0x05, struct netslice_filter)
#define NETSLICE_DETACH_FILTER _IOR('p', 0x06, int)

#endif /* __NETSLICE_H__ */
