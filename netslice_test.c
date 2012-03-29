#define _GNU_SOURCE		/* for pthread_setaffinity_np */
#include <pthread.h>
#include <sched.h>		/* for sched_setaffinity */
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <netinet/tcp.h>	/* DEBUG: for tcp header */
#include <netinet/ip.h>		/* DEBUG: for ip header */

#include "netslice.h"

#define exit_fail()		exit(EXIT_FAILURE)
#define exit_fail_msg(msg)		\
			do { perror(msg); exit_fail(); } while (0)

#define MLOCK_FLAGS		(MCL_CURRENT | MCL_FUTURE)
//#define MLOCK_FLAGS   (MCL_CURRENT)

#define MAX_DEV_NAMEBUF			(512)
#define MTU_SMALL				(1500)
#define MTU_LARGE				(9000)
//#define BUFSZ                                 MTU_SMALL
#define BUFSZ					MTU_LARGE

static int open_flags = O_RDWR | O_NONBLOCK;	// O_RDWR

static short poll_fd_events = POLLIN;

static int finished;

#if 0
/* Match every packet. */
static struct sock_filter filter[] = {
	{0x6, 0, 0, 0x0000ffff},
};
#endif

/* Match ICMP ping. */
static struct sock_filter filter[] = {
	{0x30, 0, 0, 0x00000000},
	{0x54, 0, 0, 0x0000000f},
	{0x15, 0, 7, 0x00000005},
	{0x30, 0, 0, 0x00000009},
	{0x15, 0, 5, 0x00000001},
	{0x28, 0, 0, 0x00000006},
	{0x45, 3, 0, 0x00001fff},
	{0x30, 0, 0, 0x00000014},
	{0x15, 0, 1, 0x00000008},
	{0x6, 0, 0, 0x0000ffff},
	{0x6, 0, 0, 0x00000000},
};

static struct netslice_filter nsfilter =
    { filter, sizeof(filter) / sizeof(filter[0]), 3 };

static void handle_signal(int s)
{
	(void)s;
	finished = 1;
}

static void setup_signals(void)
{
	struct sigaction sa;

	sa.sa_handler = handle_signal;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
}

int main(int argc, char **argv)
{
	int i, iov_cnt, devs, cpu;
	struct pollfd *pfd;
	struct netslice_iov *iov;
	cpu_set_t cpuset;

	if (argc != 3) {
		fprintf(stderr, "Usage %s <device> <iovecs>\n",
			argv[0]);
		exit_fail();
	}

	iov_cnt = atoi(argv[2]);
	if (iov_cnt < 0) {
		fprintf(stderr, "Invalid number of iovs: %d\n", iov_cnt);
		exit_fail();
	}

	iov = malloc(iov_cnt * sizeof(*iov));
	if (!iov)
		exit_fail_msg("malloc iov");

	for (i = 0; i < iov_cnt; i++) {
		int iov_len = BUFSZ;
		void *iov_buf = malloc(iov_len);
		if (!iov_buf)
			exit_fail_msg("malloc iov_buf");
		iov[i].iov_base = iov_buf;
		iov[i].iov_len = iov_len;
		iov[i].iov_rlen = 0;
		iov[i].flags = 0;
	}

	devs = 0;
	CPU_ZERO(&cpuset);
	if (sched_getaffinity(getpid(), sizeof(cpuset), &cpuset) < 0)
		exit_fail_msg("sched_getaffinity");
	for (cpu = 0; cpu < CPU_SETSIZE; cpu++) {
		if (CPU_ISSET(cpu, &cpuset)) {
			printf("CPU %d is set\n", cpu);
			devs++;
		}
	}
	printf("There are %d cpus.\n", devs);

	pfd = malloc(devs * sizeof(struct pollfd));
	if (!pfd)
		exit_fail_msg("malloc pfd");
	memset(pfd, 0, devs * sizeof(struct pollfd));

	i = 0;
	for (cpu = 0; cpu < CPU_SETSIZE; cpu++) {
		int fd, tmpcpu;

		if (!CPU_ISSET(cpu, &cpuset))
			continue;

		if ((fd = open(argv[1], open_flags)) < 0) {
			fprintf(stderr, "Unable to open %s, %s\n", argv[1],
				strerror(errno));
			exit_fail();
		}

		if (ioctl(fd, NETSLICE_CPU_GET, &tmpcpu) < 0)
			exit_fail_msg("ioctl NETSLICE_CPU_GET");
		if (tmpcpu != cpu) {
			if (ioctl(fd, NETSLICE_CPU_SET, &cpu) < 0)
				exit_fail_msg("ioctl NETSLICE_CPU_SET");
			fprintf(stdout, "CPU for fd %d is %d (was %d).\n", fd, cpu, tmpcpu);
		} else {
			fprintf(stdout, "CPU for fd %d is %d.\n", fd, tmpcpu);
		}
		if (ioctl(fd, NETSLICE_ATTACH_FILTER, &nsfilter) < 0) {
			if (errno == EEXIST)
				fprintf(stdout, "Filter already attached.\n");
			else
				exit_fail_msg("ioctl NETSLICE_ATTACH_FILTER");
		}

		pfd[i].fd = fd;
		pfd[i].events = poll_fd_events;
		i++;
	}

	/* this is key so that one doesn't take page faults */
	if (mlockall(MLOCK_FLAGS) != 0)
		exit_fail_msg("mlock");

	setup_signals();
	while (!finished) {
		int err = poll(pfd, devs, -1);
		if (err < 0) {
			if (errno == EINTR)
				continue;
			exit_fail_msg("poll");
		}

		for (i = 0; i < devs && err > 0; i++) {
			if (pfd[i].revents & POLLIN) {
				ssize_t count, wr_iovs, wcount = 0;
				err--;

				count = read(pfd[i].fd, iov, iov_cnt);
				if (count < 0) {
					if (errno == EINTR)
						continue;
					exit_fail_msg("read");
				} else {
					printf("Read %d items from %d\n", (int) count, pfd[i].fd);
				}

				do {
					wr_iovs =
					    write(pfd[i].fd, &iov[wcount],
						  count - wcount);
					if (wr_iovs < 0) {
						if (errno == EINTR)
							continue;
						exit_fail_msg("write");
					}
					if (wr_iovs != count)
						printf
						    ("Unable to write in one batch\n");
					wcount += wr_iovs;
				} while (wcount < count);
			}
		}
	}

	for (i = 0; i < devs; i++) {
		if (ioctl(pfd[i].fd, NETSLICE_DETACH_FILTER, &nsfilter.hook) <
		    0)
			exit_fail_msg("ioctl NETSLICE_DETACH_FILTER");
	}

	exit(EXIT_SUCCESS);
}
