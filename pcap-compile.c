#include <pcap.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int linktype = DLT_RAW;
static int snaplen = 65535;
static int optimize = 1;
static char *expression = "";
static char *output = "filter.bpf";
static uint32_t netmask;

static void print_help_and_exit(const char *program)
{
	fprintf(stderr, "Usage: %s [OPTIONS]\n", program);
	fprintf(stderr, "\n");
	fprintf(stderr, "Compile a BPF packet filter.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -e FILTER   Compile FILTER expression.\n");
	fprintf(stderr, "  -o FILE     Write to FILE rather than bpf.out.\n");
	fprintf(stderr, "  -l TYPE     Assume a link with TYPE.\n");
	fprintf(stderr, "  -s BYTES    Capture BYTES of matched packets.\n");
	fprintf(stderr, "  -m NETMASK  Use NETMASK to filtering broadcasts.\n");
	fprintf(stderr, "  -O          Do not optimize the compiled filter.\n");
	fprintf(stderr, "  -?          Print this help message and exit.\n");
	exit(EXIT_FAILURE);
}

static void handle_options(int argc, char **argv)
{
	for (;;)
		switch (getopt(argc, argv, "e:o:l:s:m:O?")) {
		case 'e':
			expression = optarg;
			break;

		case 'o':
			output = optarg;
			break;

		case 'l':
			linktype = pcap_datalink_name_to_val(optarg);
			if (linktype == -1) {
				fprintf(stderr, "Unknown data link type.\n");
				exit(EXIT_FAILURE);
			}
			break;

		case 's':
			snaplen = atoi(optarg);
			break;

		case 'm':
			if (!inet_aton(optarg, (struct in_addr *)&netmask)) {
				fprintf(stderr, "Invalid netmask.\n");
				exit(EXIT_FAILURE);
			}
			break;

		case 'O':
			optimize = 0;
			break;

		case -1:
			return;

		default:
			print_help_and_exit(argv[0]);
		}
}

int main(int argc, char **argv)
{
	pcap_t *p;
	struct bpf_program fp;
	ssize_t bytes;
	size_t total = 0;
	const char *data;
	size_t len;
	int fd;

	handle_options(argc, argv);

	p = pcap_open_dead(linktype, snaplen);
	if (pcap_compile(p, &fp, expression, optimize, netmask) == -1) {
		pcap_perror(p, NULL);
		exit(EXIT_FAILURE);
	}
	pcap_close(p);

	fd = creat(output, 0644);
	if (fd == -1) {
		perror(output);
		exit(EXIT_FAILURE);
	}

	data = (char *)fp.bf_insns;
	len = fp.bf_len * sizeof(fp.bf_insns[0]);
	while (total < len) {
		bytes = write(fd, data + total, len - total);
		if (bytes == -1) {
			perror("write");
			exit(EXIT_FAILURE);
		}
		total += bytes;
	}

	if (close(fd) == -1) {
		perror("close");
		exit(EXIT_FAILURE);
	}

	pcap_freecode(&fp);
	return EXIT_SUCCESS;
}
