#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/uts.h>
#include <linux/utsname.h>
#include <linux/version.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/kthread.h>
#include <linux/netdevice.h>
#include <linux/inet.h>
#include <linux/udp.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <linux/proc_fs.h>
#include <linux/highmem.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#ifdef MODVERSIONS
#  include <linux/modversions.h>
#endif
#include <linux/io.h>
#include <linux/kallsyms.h>

/* identical to something like PROC_IDE_READ_RETURN */
#define PROC_READ_RETURN(page,start,off,count,eof,len) \
{									\
	len -= off;                     \
	if (len < count) {              \
		*eof = 1;					\
		if (len <= 0)				\
			return 0;       		\
	} else /* truncate */ 			\
		len = count;            	\
	*start = page + off;            \
	return len;                     \
}

#include "netslice.h"

/* this flags exists only to check the performance w/o TX queue placement */
#define TX_SELECT_QUEUE
// TODO: double check this is needed
#define EXPLICIT_IP_ROUTE_HARD

#define	KLOG						"NETSLICE"
#define CHR_DEV_NAME				"netslice_dev"
#define COUNTERS_RESET_STRING		"reset"
#define USE_KMEM_CACHE_SKB_LIST

#define ONE_K	(1<<10)
#define ONE_MEG	(1<<20)
#define ONE_GIG	(1<<30)
#define MIN_WMEM_MAX	(2*ONE_K)
#define MIN_RMEM_MAX	(2*ONE_K)
#define SKB_SKACK_MTU	1500
static int hook_prio = NF_IP_PRI_FIRST;
module_param(hook_prio, int, 0000);
MODULE_PARM_DESC(hook_prio, "Netfilter hook priority");
static char *no_iface = "";
module_param(no_iface, charp, 0000);
MODULE_PARM_DESC(no_iface, "Interface that should not be interfered with");
static char *procfile = "netslice";
module_param(procfile, charp, 0000);
MODULE_PARM_DESC(procfile, "The name of the /proc/<file>");
static int wmem_max = 128 * ONE_MEG;
module_param(wmem_max, int, 0000);
MODULE_PARM_DESC(wmem_max, "Maximum write buffer");
/* due to packet loss w/ cores on second socket */
static int rmem_max = 128 * ONE_MEG;
module_param(rmem_max, int, 0000);
MODULE_PARM_DESC(rmem_max, "Maximum read buffer");

void *procfile_page = NULL;	/* a page to read / write the procfile */
struct proc_dir_entry *proc_entry = NULL;
struct nf_hook_ops hook_ops[NF_INET_NUMHOOKS];
/* character device structures */
static dev_t netslice_dev;
static struct cdev netslice_cdev;
#ifdef USE_KMEM_CACHE_SKB_LIST
struct kmem_cache *skb_list_cache = NULL;
#ifndef KMEM_CACHE
#define KMEM_CACHE(__struct, __flags) kmem_cache_create(#__struct,\
				sizeof(struct __struct), __alignof__(struct __struct),\
				(__flags), NULL)
#endif				/* KMEM_CACHE */
#endif

static inline int inject(struct netslice *netslice, struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	struct rtable *rt;

	rt = ip_route_output(netslice->net, iph->saddr, iph->daddr,
				RT_TOS(iph->tos), 0);
	if (IS_ERR(rt))
		return -1;

	skb_dst_set(skb, &rt->dst);
	return skb_dst(skb)->output(skb);
}

#ifdef FIXME
static void ip_checksum_skb(struct sk_buff *skb);
static void transport_ip_checksum_skb(struct sk_buff *skb);
static void dummy_pre_tx_csum(struct sk_buff *skb)
{
}

static void (*pre_tx_csum_fn[]) (struct sk_buff *) = {
dummy_pre_tx_csum, ip_checksum_skb, transport_ip_checksum_skb};

static int get_pre_tx_csum(struct netslice *slice)
{
	int i;
	for (i = 0; i < NETSLICE_PRE_TX_CSUM_MAX; i++)
		if (slice->pre_tx_csum == pre_tx_csum_fn[i])
			break;
	return i;
}
#endif






rwlock_t netslices_lock;
struct list netslices;

static struct netslice_queue *netslice_queue_create(void)
{
	struct netslice_queue *netslice_queue;
	int ret;

	netslice_queue = kmalloc(sizeof(*netslice_queue), GFP_KERNEL);
	if (!netslice_queue)
		return NULL;
	memset(netslice_queue, 0, sizeof(*netslice_queue));
	ret = skb_queue_head_init(&netslice_queue->queue);
	if (ret) {
		kfree(netslice_queue);
		return NULL;
	}
	ret = init_waitqueue_head(&netslice_queue->wait);
	if (ret) {
		/* FIXME: destroy netslice_queue->queue */
		kfree(netslice_queue);
		return NULL;
	}
	return netslice_queue;
}

static void netslice_queue_destroy(struct netslice_queue *netslice_queue)
{
	/* FIXME: destroy netslice_queue->queue and ->wait */
	kfree(netslice_queue);
}

static struct netslice *netslice_create(struct netslice_filter *netslice_filter)
{
	struct netslice *netslice;
	struct sock_fprog sock_filter;
	struct sk_filter *sk_filter;
	size_t len;
	int cpu;

	if (netslice_filter->filter.len < 1
			|| netslice_filter->filter.len > BPF_MAXINSNS)
		return NULL;
	len = sizeof(netslice_filter->filter.filter[0])
			* netslice_filter->filter.len;

	sk_filter = kmalloc(sizeof(*sk_filter) + len, GFP_KERNEL);
	if (!sk_filter)
		return NULL;
	ret = copy_from_user(sk_filter->insns, netslice_filter->filter.filter,
				len);
	if (ret) {
		kfree(sk_filter);
		return ret;
	}

	sk_filter->len = sock_fprog.len;
	sk_filter->bpf_func = sk_run_filter;
	ret = sk_chk_filter(sk_filter->insns, sk_filter->len);
	if (ret) {
		kfree(sk_filter);
		return NULL;
	}
	bpf_jit_compile(sk_filter);

	netslice = kmalloc(sizeof(*netslice), GFP_KERNEL);
	if (!netslice) {
		kfree(sk_filter);
		return NULL;
	}

	INIT_LIST_HEAD(&netslice->netslices);
	strncpy(netslice->name, netslice_filter->name);
	atomic_set(&netslice->references, 0);
	netslice->hooks = netslice_filter->hooks;
	netslice->net = current->nsproxy->net_ns;
	netslice->filter = sk_filter;

	memset(read_queues, 0, sizeof(read_queues));
	memset(write_queues, 0, sizeof(read_queues));
	for_each_possible_cpu(cpu) {
		read_queues[cpu] = netslice_queue_create();
		if (!read_queues[cpu]) {
			netslice_destroy(netslice);
			return NULL;
		}
		write_queues[cpu] = netslice_queue_create();
		if (!write_queues[cpu]) {
			netslice_destroy(netslice);
			return NULL;
		}
	}
}

static void netslice_destroy(struct netslice *netslice)
{
	int cpu;

	if (netslice->filter) {
		bpf_jit_free(netslice->filter);
		kfree(netslice->filter);
	}

	for_each_possible_cpu(cpu) {
		if (netslice->read_queues[cpu])
			netslice_queue_destroy(netslice->read_queues[cpu]);
		if (netslice->write_queues[cpu])
			netslice_queue_destroy(netslice->write_queues[cpu]);
	}

	kfree(netslice);
	break;
}

static struct netslice_handle *netslice_handle_create(void)
{
	struct netslice_handle *handle;

	handle = kmalloc(sizeof(*handle), GFP_KERNEL);
	if (!handle)
		return NULL;

	handle->netslice = NULL;
	handle->cpu = get_cpu();
	put_cpu();
	return handle;
}

static void netslice_handle_destroy(struct netslice_handle *handle)
{
	if (handle->netslice && atomic_dec_and_test(handle->netslice->refcnt))
		netslice_destroy(handle->netslice);
	kfree(handle);
}

static int netslice_open(struct inode *inode, struct file *file)
{
	file->private_data = netslice_handle_create();
	if (!file->private_data)
		return -ENOMEM;
	return 0;
}

static int netslice_release(struct inode *inode, struct file *file)
{
	netslice_handle_destroy(file->private_data);
	return 0;
}

static long netslice_ioctl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	struct netslice_handle *handle = file->private_data;
	struct netslice_filter filter;
	struct netslice *netslice;
	struct list_head *list;
	char name[NETSLICE_NAME_SIZE];
	long ret;
	int i;

	switch (cmd) {
	case NETSLICE_CREATE:
		if (handle->netslice)
			return -EEXIST;

		ret = copy_from_user(&filter,
					(struct netslice_filter __user *)arg,
					sizeof(filter));
		if (ret)
			return ret;

		handle->netslice = netslice_create(&filter);
		if (!handle->netslice)
			return -ENOMEM;
		atomic_inc(handle->netslice->references);

		write_lock(&netslices_lock);
		list_for_each(list, &netslices) {
			netslice = list_entry(list, struct netslice, netslices);
			if (strncmp(netslice->name, name) == 0) {
				write_unlock(&netslices_lock);
				return -EEXIST;
			}
		}
		list_add(handle->netslice->netslices, &netslices);
		write_unlock(&netslices_lock);
		atomic_inc(handle->netslice->references);
		break;

	case NETSLICE_DESTROY:
		if (!handle->netslice)
			return -ENOENT;

		write_lock(&netslices_lock);
		list_del(&handle->netslice->netslices);
		write_unlock(&netslices_lock);
		if (atomic_dec_and_test(handle->netslice->refcnt))
			netslice_destroy(handle->netslice);

		handle->netslice = NULL;
		if (atomic_dec_and_test(handle->netslice->refcnt))
			netslice_destroy(handle->netslice);
		break;

	case NETSLICE_ATTACH:
		if (handle->netslice)
			return -EEXIST;

		ret = copy_from_user(name, (char __user *)arg, sizeof(name));
		if (ret)
			return ret;

		read_lock(&netslices_lock);
		list_for_each(list, &netslices) {
			netslice = list_entry(list, struct netslice, netslices);
			if (netslice->net == current->nsproxy->net_ns
					&& strncmp(netslice->name, name) == 0)
				break;
		}
		read_unlock(&netslices_lock);
		if (list == &netslices)
			return -ENOENT;

		handle->netslice = netslice;
		atomic_inc(netslice->refcnt);
		break;

	case NETSLICE_CPU_SET
		ret = get_user(i, (int __user *)arg);
		if (!ret)
			return ret;
		if (!cpu_possible(i))
			return -EINVAL;
		handle->cpu = i;
		break;

	case NETSLICE_CPU_GET:
		return put_user(handle->cpu, (int __user *)arg);

#ifdef FIXME
	case NETSLICE_PRE_TX_CSUM_SET:
		ret = get_user(i, (int __user *)arg);
		if (ret)
			return ret;
		if (i < 0 || i >= NETSLICE_PRE_TX_CSUM_MAX)
			return -EINVAL;
		netslice->pre_tx_csum = pre_tx_csum_fn[i];
		break;

	case NETSLICE_PRE_TX_CSUM_GET:
		i = get_pre_tx_csum(netslice);
		return put_user(i, (int __user *)arg);
#endif

	default:
		return -ENOIOCTLCMD;
	}

	return 0;
}

static unsigned int netslice_nf_hook(unsigned int hook, struct sk_buff *skb,
				     const struct net_device *indev,
				     const struct net_device *outdev,
				     int (*okfn) (struct sk_buff *))
{
	struct netslice *netslice;
	struct list_head *list;
	struct net *net;
	struct netslice_queue *queue;
	unsigned int len;
	int err = 0;
	struct skb_list *skb_list_elem;

	if (indev)
		net = dev_net(indev);
	else if (outdev)
		net = dev_net(outdev);
	else
		return NF_ACCEPT;

	len = 0;
	read_lock(&netslices_lock);
	list_for_each(list, &netslices) {
		netslice = list_entry(list, struct netslice, netslices);
		if (netslice->net != net)
			continue;
		if (!(netslice->hooks & (1 << hook)))
			continue;
		len = SK_RUN_FILTER(slice->filters[hook], skb);
		if (len)
			break;
	}
	read_unlock(&netslices_lock);

	if (!len)
		return NF_ACCEPT;

	pskb_trim(skb, len);

	if (unlikely(skb_is_nonlinear(skb))) {
		ret = skb_linearize(skb);
		if (ret)
			return NF_DROP;
	}

	cpu = get_cpu();
	queue = netslice->read_queues[cpu];
	put_cpu();

	spin_lock(queue->skbs.lock);
	if (skb_queue_len(&queue->skbs) >= queue->capacity) {
		queue->dropped++;
		spin_unlock(queue->skbs.lock);
		return NF_DROP;
	}
	__skb_queue_tail(skb_peek_tail(&queue->skbs), skb);
	spin_unlock(queue->skbs.lock);
	wake_up_interruptible(&queue->wait);
	return NF_STOLEN;
}



static ssize_t netslice_aio_read(struct kiocb *, const struct iovec *,
					unsigned long, loff_t)
{
	/* FIXME: write */
}

static ssize_t netslice_aio_write(struct kiocb *, const struct iovec *,
					unsigned long, loff_t)
{
	/* FIXME: write */
}




static ssize_t netslice_read(struct file *file, char __user *buf,
				size_t count, loff_t *ppos)
{
	struct netslice *slice = file->private_data;
	struct skb_list_head *rcv_queue = &slice->rcv_queue;
	struct skb_list *skb_item, *tmp;
	struct netslice_iov iov_fast[UIO_FASTIOV];
	struct netslice_iov *iov = iov_fast, *free_iov = NULL;
	struct netslice_iov __user *iov_user =
	    (struct netslice_iov __user *)buf;
	ssize_t retval = 0, ret_bytes, fetched_cnt;
	int seg;

	LIST_HEAD(ret_skbs);
	DECLARE_WAITQUEUE(wait, current);

	printk(KLOG ": entering read function\n");

	if (unlikely(count == 0)) {
		printk(KLOG ": leaving because count == 0\n");
		retval = 0;
		goto out;
	}

	if (unlikely(count > UIO_MAXIOV)) {
		printk(KLOG ": leaving because count > UIO_MAXIOV\n");
		retval = -EINVAL;
		goto out;
	}

	if (count > UIO_FASTIOV) {
		iov = kmalloc(count * sizeof(*iov), GFP_KERNEL);
		if (iov == NULL) {
			printk(KLOG ": leaving because unable to kmalloc iov\n");
			retval = -ENOMEM;
			goto out;
		}
		free_iov = iov;
	}

	/* I will be writing back the iov_rlen */
	if (unlikely
	    (!access_ok(VERIFY_WRITE, iov_user, count * sizeof(*iov_user)))) {
		printk(KLOG ": leaving because unable to write back to iov_user\n");
		retval = -EFAULT;
		goto out;
	}

	if (unlikely
	    (__copy_from_user(iov, iov_user, count * sizeof(*iov_user)))) {
		printk(KLOG ": leaving because unable to copy from iov_user\n");
		retval = -EFAULT;
		goto out;
	}

	/* check parameter validity */
	ret_bytes = fetched_cnt = 0;
	for (seg = 0; seg < count; seg++) {
		void __user *ubuf = iov[seg].iov_base;
		ssize_t len = (ssize_t) iov[seg].iov_len;

		printk(KLOG ": handling seg %d\n", seg);

		/* invalid or overflow */
		if (unlikely(len < 0 || (ret_bytes + len < ret_bytes))) {
			printk(KLOG ": leaving because len is invalid or overflows\n");
			retval = -EINVAL;
			goto out;
		}

		if (unlikely(!access_ok(VERIFY_WRITE, ubuf, len))) {
			printk(KLOG ": leaving because unable to write back data\n");
			retval = -EINVAL;
			goto out;
		}

		ret_bytes += len;
	}

	add_wait_queue(&slice->wait, &wait);

	for (;;) {
		__set_current_state(TASK_INTERRUPTIBLE);

		spin_lock_bh(&rcv_queue->lock);
		list_for_each_entry_safe(skb_item, tmp, &rcv_queue->skbs, list) {
			/* can return at most count items */
			if (fetched_cnt >= count)
				break;

			/* unchain the element */
			list_del(&skb_item->list);
			rcv_queue->bytes_len -= skb_item->skb->len;
			rcv_queue->len--;

			/* chain to the return list */
			list_add_tail(&skb_item->list, &ret_skbs);
			fetched_cnt++;
		}
		spin_unlock_bh(&rcv_queue->lock);

		/* update burst stats */
		if (slice->stats.max_rcv_burst < fetched_cnt)
			slice->stats.max_rcv_burst = fetched_cnt;

		if (!list_empty(&ret_skbs))
			break;
		else if (signal_pending(current)) {
			retval = -EINTR;
			break;
		} else if (file->f_flags & O_NONBLOCK) {
			retval = -EAGAIN;
			break;
		}
		printk(KLOG ": waiting for data\n");
		schedule();	/* perhaps I should use schedule_timeout() */
	}

	__set_current_state(TASK_RUNNING);
	remove_wait_queue(&slice->wait, &wait);

	if (unlikely(retval < 0)) {
		printk(KLOG ": leaving due to error while waiting\n");
		goto out;
	}

	seg = 0;
	list_for_each_entry_safe(skb_item, tmp, &ret_skbs, list) {
		void __user *ubuf = iov[seg].iov_base;
		ssize_t len = (ssize_t) iov[seg].iov_len;
		ssize_t __user *rlen = &iov_user[seg].iov_rlen;

		printk(KLOG ": writing back to seg %d\n", seg);

		/* ret_bytes = min_t(ssize_t, len, skb_item->skb->len); */
		ret_bytes = skb_item->skb->len;
		if (unlikely(ret_bytes > len)) {
			ret_bytes = len;
			slice->stats.rcv_trunc++;
		}
		if (unlikely
		    (__copy_to_user(ubuf, skb_item->skb->data, ret_bytes))) {
			printk(KLOG ": leaving due to error copying back data\n");
			retval = -EFAULT;
			goto out_free_ret_skbs;
		}
		/* write back the iov_rlen */
		if (unlikely(__put_user(ret_bytes, rlen))) {
			printk(KLOG ": leaving due to error copying back rlen\n");
			retval = -EFAULT;
			goto out_free_ret_skbs;
		}

		seg++;
	}
	retval = seg;

	printk(KLOG ": done\n");
 out_free_ret_skbs:
	list_for_each_entry_safe(skb_item, tmp, &ret_skbs, list) {
		list_del(&skb_item->list);
		kfree_skb(skb_item->skb);
		kfree(skb_item);
	}

 out:
	if (free_iov)
		kfree(free_iov);
	printk(KLOG ": leaving\n");
	return retval;
}

struct netslice_skb_cb {
	struct netslice *slice;
	int len;
};

/* WARNING!!!! beware of the private sk_buff->cb data, 2.6.28 overwrites my 
netslice at address &(skb->cb[0]), 2.6.24 does not, so I picked an offset */
#define CB_OFFSET			(sizeof(long *))
#define NETSLICE_CB(__skb)	((struct netslice_skb_cb *)&((__skb)->cb[CB_OFFSET]))
static void netslice_skb_destructor(struct sk_buff *skb)
{
	struct netslice *slice = NETSLICE_CB(skb)->slice;
	struct skb_list_head *snd_queue = &slice->snd_queue;

	atomic_sub(NETSLICE_CB(skb)->len, &snd_queue->pending_bytes_len);
	/* Hmm, I wonder if there's a way to get rid of all the unnecessary wake_up
	   calls, without breaking correctness... */
	wake_up_interruptible(&slice->wait);
}

#ifdef TX_SELECT_QUEUE
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)

#include <linux/jhash.h>
/* yanked out of net/core/dev.c since it is not exported :( */
static u32 simple_tx_hashrnd;
static int simple_tx_hashrnd_initialized = 0;

static u16 simple_tx_hash(struct net_device *dev, struct sk_buff *skb)
{
	u32 addr1, addr2, ports;
	u32 hash, ihl;
	u8 ip_proto = 0;

	if (unlikely(!simple_tx_hashrnd_initialized)) {
		get_random_bytes(&simple_tx_hashrnd, 4);
		simple_tx_hashrnd_initialized = 1;
	}

	switch (skb->protocol) {
	case htons(ETH_P_IP):
		if (!(ip_hdr(skb)->frag_off & htons(IP_MF | IP_OFFSET)))
			ip_proto = ip_hdr(skb)->protocol;
		addr1 = ip_hdr(skb)->saddr;
		addr2 = ip_hdr(skb)->daddr;
		ihl = ip_hdr(skb)->ihl;
		break;
	case htons(ETH_P_IPV6):
		ip_proto = ipv6_hdr(skb)->nexthdr;
		addr1 = ipv6_hdr(skb)->saddr.s6_addr32[3];
		addr2 = ipv6_hdr(skb)->daddr.s6_addr32[3];
		ihl = (40 >> 2);
		break;
	default:
		return 0;
	}

	switch (ip_proto) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_DCCP:
	case IPPROTO_ESP:
	case IPPROTO_AH:
	case IPPROTO_SCTP:
	case IPPROTO_UDPLITE:
		ports = *((u32 *) (skb_network_header(skb) + (ihl * 4)));
		break;

	default:
		ports = 0;
		break;
	}

	hash = jhash_3words(addr1, addr2, ports, simple_tx_hashrnd);

	return (u16) (((u64) hash * dev->real_num_tx_queues) >> 32);
}

struct dev_select_queue {
	int netslice_select_queue;

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 28)
	const struct net_device_ops *ndo;
#else
	 u16(*select_queue) (struct net_device *, struct sk_buff *);
#endif
};
static struct dev_select_queue *devs_select_queue = NULL;
static int devs_select_queues = 0;

/* this will be called instead of the original dev_select_queue */
static u16 new_dev_select_queue(struct net_device *dev, struct sk_buff *skb)
{
	if (skb->destructor && skb->destructor == netslice_skb_destructor) {
		struct netslice *slice = NETSLICE_CB(skb)->slice;
		slice->stats.tx_select_q++;
		return (u16) (slice->cpu & (dev->real_num_tx_queues - 1));
	} else {
		if (dev->ifindex < devs_select_queues) {
			struct dev_select_queue *dsq =
			    &devs_select_queue[dev->ifindex];
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 28)
			if (dsq->netslice_select_queue && dsq->ndo)
				return dsq->ndo->ndo_select_queue(dev, skb);
#else
			if (dsq->netslice_select_queue && dsq->select_queue)
				return dsq->select_queue(dev, skb);
#endif
		}
		return (dev->real_num_tx_queues > 1) ? simple_tx_hash(dev,
								      skb) : 0;
	}
}
#endif
#endif				//TX_SELECT_QUEUE

static ssize_t netslice_write(struct file *file, const char __user *buf,
				      size_t count, loff_t *ppos)
{
	struct netslice *slice = file->private_data;
	struct skb_list_head *snd_queue = &slice->snd_queue;
	struct netslice_iov iov_fast[UIO_FASTIOV];
	struct netslice_iov *iov = iov_fast, *free_iov = NULL;
	struct netslice_iov __user *iov_user =
	    (struct netslice_iov __user *)buf;
	ssize_t retval = 0, total_bytes;
	int seg, snd_segs;

	DECLARE_WAITQUEUE(wait, current);

	if (unlikely(count == 0)) {
		retval = 0;
		goto out;
	}

	if (unlikely(count > UIO_MAXIOV)) {
		retval = -EINVAL;
		goto out;
	}

	if (count > UIO_FASTIOV) {
		iov = kmalloc(count * sizeof(*iov), GFP_KERNEL);
		if (iov == NULL) {
			retval = -ENOMEM;
			goto out;
		}
		free_iov = iov;
	}

	/* I will be writing back the iov_rlen */
	if (unlikely
	    (!access_ok(VERIFY_WRITE, iov_user, count * sizeof(*iov_user)))) {
		retval = -EFAULT;
		goto out;
	}

	if (unlikely
	    (__copy_from_user(iov, iov_user, count * sizeof(*iov_user)))) {
		retval = -EFAULT;
		goto out;
	}

	/* check parameter validity */
	total_bytes = 0;
	for (seg = 0; seg < count; seg++) {
		void __user *ubuf = iov[seg].iov_base;
		ssize_t len = (ssize_t) iov[seg].iov_rlen;

		/* invalid or overflow */
		if (unlikely(len < 0 || (total_bytes + len < total_bytes))) {
			retval = -EINVAL;
			goto out;
		}

		if (unlikely(!access_ok(VERIFY_READ, ubuf, len))) {
			retval = -EINVAL;
			goto out;
		}

		total_bytes += len;
	}

	add_wait_queue(&slice->wait, &wait);

	for (;;) {
		__set_current_state(TASK_INTERRUPTIBLE);

		/* trying to fit the most bytes (i.e. all packets) first
		   the base unit of atomic send is the packet */
		for (snd_segs = count; snd_segs > 0; snd_segs--) {
			if (atomic_add_return
			    (total_bytes,
			     &snd_queue->pending_bytes_len) <
			    snd_queue->capacity)
				break;
			else
				total_bytes =
				    -((ssize_t) iov[snd_segs - 1].iov_rlen);
		}
		if (snd_segs > 0)	/* there are snd_segs to send */
			break;

		if (signal_pending(current)) {
			retval = -EINTR;
			break;
		} else if (file->f_flags & O_NONBLOCK) {
			retval = -EAGAIN;
			break;
		}
		schedule();	/* perhaps I should use schedule_timeout() */
	}
	__set_current_state(TASK_RUNNING);
	remove_wait_queue(&slice->wait, &wait);

	if (unlikely(retval < 0))
		goto out;

	if (slice->stats.max_snd_burst < snd_segs)
		slice->stats.max_snd_burst = snd_segs;

	for (seg = 0; seg < snd_segs; seg++) {
		void __user *ubuf;
		size_t len;
		struct sk_buff *skb;

		/* packet marked to be skipped by the kernel */
		if (iov[seg].flags & NETSLICE_IOV_SKIP_PACKET_MASK)
			continue;

		ubuf = iov[seg].iov_base;
		len = iov[seg].iov_rlen;
		skb = alloc_skb(LL_MAX_HEADER + len, GFP_ATOMIC);
		if (unlikely(skb == NULL)) {
			retval = -ENOMEM;
			printk(KLOG ": Unable to allocate skb\n");
			goto out;
		}
		skb->ip_summed = CHECKSUM_NONE;
		skb_reserve(skb, LL_MAX_HEADER);
		skb_reset_network_header(skb);
		skb_put(skb, len);

		if (unlikely(__copy_from_user(skb->data, ubuf, len) != 0)) {
			kfree_skb(skb);
			retval = -EFAULT;
			goto out;
		}

		NETSLICE_CB(skb)->slice = slice;
		NETSLICE_CB(skb)->len = skb->len;
		skb->destructor = netslice_skb_destructor;

		/* re-compute IP and TCP csums in software, if needed */
		if (iov[seg].flags & NETSLICE_IOV_CSUM_MASK) {
			if (iov[seg].flags & NETSLICE_IOV_CSUM_TRANSPORT_MASK)
				transport_ip_checksum_skb(skb);
			else
				ip_checksum_skb(skb);
		} else {
			slice->pre_tx_csum(skb);
		}

		inject(skb);
	}
	retval = snd_segs;

 out:
	if (free_iov)
		kfree(free_iov);
	return retval;
}

static unsigned int netslice_poll(struct file *file, poll_table * wait)
{
	struct netslice *slice = file->private_data;
	int mask = 0;

	poll_wait(file, &slice->wait, wait);

	/* receive queue */
	spin_lock_bh(&slice->rcv_queue.lock);
	if (!list_empty(&slice->rcv_queue.skbs)) {
		mask |= (POLLIN | POLLRDNORM);
	}
	spin_unlock_bh(&slice->rcv_queue.lock);

	/* snd queue, at least 1 byte available */
	if (atomic_read(&slice->snd_queue.pending_bytes_len) +
	    SKB_SKACK_MTU < slice->snd_queue.capacity) {
		mask |= (POLLOUT | POLLWRNORM);
	}
	return mask;
}

/* e.g. for ip fragments that are modified in user-space */
static void ip_checksum_skb(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	iph->check = 0;
	iph->check = ip_fast_csum(skb_network_header(skb), iph->ihl);
	skb->ip_summed = CHECKSUM_NONE;	/* computed the checksum ourselves */
}

static void transport_ip_checksum_skb(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	if (iph->protocol == IPPROTO_TCP) {
		int iphdr_len = iph->ihl * 4;
		struct tcphdr *th = (struct tcphdr *)((void *)iph + iphdr_len);
		int tcp_pack_len = skb->len - iphdr_len;

		th->check = 0;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 20)
		th->check =
		    tcp_v4_check(th, tcp_pack_len, iph->saddr, iph->daddr,
				 csum_partial((char *)th, tcp_pack_len, 0));
#else
		th->check = tcp_v4_check(tcp_pack_len, iph->saddr, iph->daddr,
					 csum_partial((char *)th, tcp_pack_len,
						      0));
#endif
	}
	ip_checksum_skb(skb);
}

/* procfile function called to output data to userspace through /proc */
int proc_put_userland(char *page, char **start, off_t off, int count,
		      int *eof, void *data)
{
	int len = 0, cpu;
	char *dest = (char *)page;
	int i;

	for_each_online_cpu(cpu) {
		struct netslice *slice = per_cpu_ptr(&per_cpu_netslice, cpu);
		len += sprintf(&dest[len],
			       "CPU %d:\n"
			       "\trcv_q: %ld, snd_q: %ld, tx_select_q: %d\n"
			       "\tpre_tx_csum (0=none, 1=IP, 2=Transport): %d\n"
			       "\trcv_trunc: %d, max_r_burst: %d, max_w_burst: %d\n",
			       cpu,
			       slice->rcv_queue.bytes_len,
			       slice->snd_queue.bytes_len,
			       slice->stats.tx_select_q,
			       get_pre_tx_csum(slice),
			       slice->stats.rcv_trunc,
			       slice->stats.max_rcv_burst,
			       slice->stats.max_snd_burst);
		for (i = 0; i < NF_INET_NUMHOOKS; i++) {
			struct netslice_hook_stats *s =
			    &slice->hook_stats[i];
			len +=
			    sprintf(&dest[len],
				    "\tHOOK %d cnt: %lu, nons: %d, noiface: %d, nomatch %d, nofilter %d, dropped %d, nonlinear %d\n",
				    i, s->cnt, s->nons, s->noiface, s->nomatch,
				    s->nofilter, s->nf_hook_dropped,
				    s->skb_nonlinear);
		}
	}

	PROC_READ_RETURN(page, start, off, count, eof, len);
}

/* procfile read data from userspace */
int proc_get_userland(struct file *filp, const char __user * buff,
		      unsigned long count, void *data)
{
	if (!procfile_page)
		return count;

	if (count > PAGE_SIZE)
		return -EINVAL;

	if (copy_from_user(procfile_page, buff, count))
		return -EFAULT;

	if (strncmp(procfile_page,
		    COUNTERS_RESET_STRING, strlen(COUNTERS_RESET_STRING)) == 0)
	{
		int cpu;
		for_each_possible_cpu(cpu) {
			struct netslice *slice =
			    per_cpu_ptr(&per_cpu_netslice, cpu);
			memset(slice->hook_stats, 0, sizeof(slice->hook_stats));
			memset(&slice->stats, 0, sizeof(slice->stats));
		}
	}

	return count;
}

static struct file_operations netslice_fops = {
	.owner = THIS_MODULE,
	.read = netslice_read,
	.write = netslice_write,
	.poll = netslice_poll,
	.unlocked_ioctl = netslice_ioctl,
	.open = netslice_open,
};

/* module initialization - called at module load time */
static int __init netslice_init(void)
{
	int i, err = 0, cpu, max_if_idx = 0;
	struct net_device *iface_dev;
#ifdef TX_SELECT_QUEUE
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
	struct dev_select_queue *dev_sq;
#endif
#endif				//TX_SELECT_QUEUE
	struct netslice *slice;

	if (wmem_max < MIN_WMEM_MAX) {
		printk(KLOG
		       ": Correcting too small wmem_max parameter from %d to %d\n",
		       wmem_max, MIN_WMEM_MAX);
		wmem_max = MIN_WMEM_MAX;
	}
	if (rmem_max < MIN_RMEM_MAX) {
		printk(KLOG
		       ": Correcting too small rmem_max parameter from %d to %d\n",
		       rmem_max, MIN_RMEM_MAX);
		rmem_max = MIN_RMEM_MAX;
	}

	for_each_possible_cpu(cpu) {
		slice = per_cpu_ptr(&per_cpu_netslice, cpu);

		memset(slice, 0, sizeof(*slice));

		init_waitqueue_head(&slice->wait);

		INIT_LIST_HEAD(&slice->rcv_queue.skbs);
		spin_lock_init(&slice->rcv_queue.lock);
		atomic_set(&slice->rcv_queue.pending_bytes_len, 0);
		slice->rcv_queue.capacity = rmem_max;

		INIT_LIST_HEAD(&slice->snd_queue.skbs);
		spin_lock_init(&slice->snd_queue.lock);
		atomic_set(&slice->snd_queue.pending_bytes_len, 0);
		slice->snd_queue.capacity = wmem_max;
		slice->pre_tx_csum =
		    pre_tx_csum_fn[NETSLICE_PRE_TX_CSUM_NONE];
		slice->cpu = cpu;
		memset(slice->filters, 0, sizeof(slice->filters));
		memset(&slice->stats, 0, sizeof(slice->stats));
	}

	memset(&netslice_res, 0, sizeof(netslice_res));

	/* get no_iface net_device index for fast(er) int cmp instead of strcmp */
	if ((strcmp(no_iface, "") != 0)
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 20)
	    && ((iface_dev = dev_get_by_name(no_iface)) != NULL))
#else
	    && ((iface_dev = dev_get_by_name(&init_net, no_iface)) != NULL))
#endif
	{
		netslice_res.no_iface = 1;
		netslice_res.no_iface_ifindex = iface_dev->ifindex;
		dev_put(iface_dev);
	}

#ifdef TX_SELECT_QUEUE
	/* all devices except for the no_iface */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
	read_lock(&dev_base_lock);	/* rtnl_lock(); */
	for_each_netdev(&init_net, iface_dev) {
		dev_hold(iface_dev);
		if (iface_dev->ifindex > max_if_idx)
			max_if_idx = iface_dev->ifindex;
		dev_put(iface_dev);
	}
	devs_select_queues = max_if_idx + 1;
	if (!(devs_select_queue = kzalloc(sizeof(struct dev_select_queue) *
					  devs_select_queues, GFP_ATOMIC))) {
		printk(KLOG ": Unable to allocate devs_select_queue\n");
		read_unlock(&dev_base_lock);
		goto out_free_netdev_select_queue;
	}
	for_each_netdev(&init_net, iface_dev) {
		dev_hold(iface_dev);
		if (strncmp(iface_dev->name, no_iface, IFNAMSIZ) != 0) {
			dev_sq = &devs_select_queue[iface_dev->ifindex];
			BUG_ON(dev_sq->netslice_select_queue);	/* it's one shot */
			dev_sq->netslice_select_queue = 1;
			/* save old and plug in the new function */
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 28)
			dev_sq->select_queue = iface_dev->select_queue;
			iface_dev->select_queue = new_dev_select_queue;
#else
			dev_sq->ndo = iface_dev->netdev_ops;
			{
				struct net_device_ops *ndo =
				    kmalloc(sizeof(*ndo), GFP_KERNEL);
				if (!ndo) {
					printk(KLOG
					       ": Unable to allocate struct net_device_ops\n");
					dev_put(iface_dev);
					goto out_free_netdev_select_queue;
				}

				memcpy(ndo, iface_dev->netdev_ops,
				       sizeof(*ndo));
				ndo->ndo_select_queue = new_dev_select_queue;
				iface_dev->netdev_ops = ndo;
			}
#endif
		}
		dev_put(iface_dev);
	}
	read_unlock(&dev_base_lock);	/* rtnl_unlock(); */
#endif
#endif				//TX_SELECT_QUEUE

#ifdef USE_KMEM_CACHE_SKB_LIST
	if (!
	    (skb_list_cache =
	     KMEM_CACHE(skb_list, SLAB_HWCACHE_ALIGN | SLAB_PANIC))) {
		printk(KLOG ": Unable to allocate kmem-cache\n");
		err = -ENOMEM;
		goto out_no_kmem_cache;
	}
#endif				/* USE_KMEM_CACHE_SKB_LIST */

	if (!(procfile_page = (void *)get_zeroed_page(GFP_KERNEL))) {
		printk(KLOG ": Unable to allocate procfile page\n");
		err = -ENOMEM;
		goto out;
	}
	/* create the proc file */
	if (!(proc_entry = create_proc_entry(procfile, 0666, NULL))) {
		printk(KLOG ": Unable to create proc file %s\n", procfile);
		err = -EINVAL;
		goto out_free_procfile_page;
	}
	proc_entry->write_proc = proc_get_userland;
	proc_entry->read_proc = proc_put_userland;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
	proc_entry->owner = THIS_MODULE;
#endif

	err = alloc_chrdev_region(&netslice_dev, 0, 1, CHR_DEV_NAME);
	if (err < 0) {
		printk(KLOG
		       ": Unable to allocate major number for char device\n");
		goto out_free_procfile;
	}

	cdev_init(&netslice_cdev, &netslice_fops);
	err = cdev_add(&netslice_cdev, netslice_dev, 1);
	if (err < 0) {
		printk(KLOG ": Unable to allocate chrdev\n");
		goto out_free_chrdev;
	}

	/* netfilter hook */
	for (i = 0; i < NF_INET_NUMHOOKS; i++) {
		memset(&hook_ops[i], 0, sizeof(hook_ops[i]));
		hook_ops[i].hook = netslice_nf_hook;
		hook_ops[i].hooknum = i;
		hook_ops[i].pf = PF_INET;
		hook_ops[i].priority = hook_prio;
	}
	err = nf_register_hooks(hook_ops, NF_INET_NUMHOOKS);
	if (err) {
		printk(KLOG ": Unable to register hooks\n");
		goto out_free_chrdev;
	}

	printk(KLOG ": %s loaded\n", CHR_DEV_NAME);
	return err;

 out_free_chrdev:
	unregister_chrdev_region(netslice_dev, 1);

 out_free_procfile:
	if (proc_entry)
		remove_proc_entry(procfile, NULL);

 out_free_procfile_page:
	if (procfile_page)
		free_page((unsigned long)procfile_page);

 out:
#ifdef USE_KMEM_CACHE_SKB_LIST
	if (skb_list_cache)
		kmem_cache_destroy(skb_list_cache);
#ifdef TX_SELECT_QUEUE
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
 out_free_netdev_select_queue:

	for (i = 0; i < devs_select_queues; i++) {
		dev_sq = &devs_select_queue[i];
		if (!dev_sq->netslice_select_queue)
			continue;

		iface_dev = dev_get_by_index(&init_net, i);
		if (iface_dev) {
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 28)
			if (iface_dev->select_queue &&
			    iface_dev->select_queue == new_dev_select_queue)
				iface_dev->select_queue = dev_sq->select_queue;
#else
			if (iface_dev->netdev_ops &&
			    iface_dev->netdev_ops->ndo_select_queue ==
			    new_dev_select_queue) {
				const struct net_device_ops *tmp_ndo =
				    iface_dev->netdev_ops;
				iface_dev->netdev_ops = dev_sq->ndo;
				kfree(tmp_ndo);
			}
#endif
			dev_put(iface_dev);
		}
	}
	kfree(devs_select_queue);
	devs_select_queue = NULL;
#endif
#endif				//TX_SELECT_QUEUE
 out_no_kmem_cache:
#endif				/* USE_KMEM_CACHE_SKB_LIST */
	return err;
}

/* module unload, only succesful after the chrdev file descriptor is released */
static void __exit netslice_exit(void)
{
	int cpu, i;
	DECLARE_WAITQUEUE(wait, current);
	DECLARE_WAIT_QUEUE_HEAD(rmmod_waiters);
#ifdef TX_SELECT_QUEUE
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
	struct net_device *iface_dev;
	struct dev_select_queue *dev_sq;
#endif
#endif				//TX_SELECT_QUEUE

	if (proc_entry)
		remove_proc_entry(procfile, NULL);
	if (procfile_page)
		free_page((unsigned long)procfile_page);

	nf_unregister_hooks(hook_ops, NF_INET_NUMHOOKS);

	cdev_del(&netslice_cdev);
	unregister_chrdev_region(netslice_dev, 1);

	/* clean up the rx queues */
	for_each_possible_cpu(cpu) {
		struct skb_list *elem, *tmp;
		struct netslice *slice = per_cpu_ptr(&per_cpu_netslice, cpu);

		spin_lock(&slice->rcv_queue.lock);
		list_for_each_entry_safe(elem, tmp, &slice->rcv_queue.skbs,
					 list) {
			if (elem->skb)
				kfree_skb(elem->skb);
			kfree(elem);
		}
		spin_unlock(&slice->rcv_queue.lock);
	}
	printk(KLOG ": cleaned up rx queues\n");
	/* wait for all tx queues, tricky since it's callback based */
	add_wait_queue(&rmmod_waiters, &wait);
	for (;;) {
		int all_queues_depleted = 1;

		set_current_state(TASK_INTERRUPTIBLE);

		for_each_possible_cpu(cpu) {
			struct netslice *slice =
			    per_cpu_ptr(&per_cpu_netslice, cpu);
			if (atomic_read(&slice->snd_queue.pending_bytes_len)
			    > 0) {
				all_queues_depleted = 0;
				break;
			}
		}
		if (all_queues_depleted)
			break;

		schedule_timeout(1);
	}
	set_current_state(TASK_RUNNING);
	remove_wait_queue(&rmmod_waiters, &wait);
	printk(KLOG ": cleaned up tx queues\n");

#ifdef USE_KMEM_CACHE_SKB_LIST
	if (skb_list_cache)
		kmem_cache_destroy(skb_list_cache);
#endif				/* USE_KMEM_CACHE_SKB_LIST */

#ifdef TX_SELECT_QUEUE
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
	for (i = 0; i < devs_select_queues; i++) {
		dev_sq = &devs_select_queue[i];
		if (!dev_sq->netslice_select_queue)
			continue;

		iface_dev = dev_get_by_index(&init_net, i);
		if (iface_dev) {

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 28)
			if (iface_dev->select_queue &&
			    iface_dev->select_queue == new_dev_select_queue)
				iface_dev->select_queue = dev_sq->select_queue;
#else
			if (iface_dev->netdev_ops &&
			    iface_dev->netdev_ops->ndo_select_queue ==
			    new_dev_select_queue) {
				const struct net_device_ops *tmp_ndo =
				    iface_dev->netdev_ops;
				iface_dev->netdev_ops = dev_sq->ndo;
				kfree(tmp_ndo);
			}
#endif
			dev_put(iface_dev);
		}
	}
	kfree(devs_select_queue);
	devs_select_queue = NULL;
#endif
#endif				//TX_SELECT_QUEUE
	printk(KLOG ": %s removed\n", CHR_DEV_NAME);
}

module_init(netslice_init);
module_exit(netslice_exit);

MODULE_DESCRIPTION("Netslice packet filter");
MODULE_AUTHOR("Robert Surton <burgess@cs.cornell.edu>");
MODULE_LICENSE("Dual BSD/GPL");
