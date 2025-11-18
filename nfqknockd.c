/*
This is knockd daemon based on NFQUEUE library.
I hope require less resources than libpcap based.

Author:
    Kuzin Andrey <kuzinandrey@yandex.ru> 2025-11-04
Home:
    https://github.com/KuzinAndrey/nfqknockd
*/

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/netfilter.h>
#include <libnfnetlink/libnfnetlink.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <syslog.h>

#include <openssl/conf.h>
#include <openssl/evp.h>

#define PROG_DATE "2025-11-04"

static int working = 1;
static int dump_open_clients = 0;
static int dump_unknown_client = 0;
static int opt_foreground = 0;
static int opt_verbose = 0;
static int opt_show_ports = 0;
static uint16_t opt_queue_id = 100;
static uint32_t opt_queue_maxlen = 10000;
static uint16_t opt_touch_iptables = 0;
char *iptables_cmd = NULL;
static int opt_timeout = 10; // timeout for knocking sequence
static const EVP_MD *opt_digest_type = NULL;

#define DEFAULT_OPEN_SECRET "helloworld123"
#define DEFAULT_CLOSE_SECRET "goodbyeworld123"

static EVP_MD_CTX *digest_ctx = NULL;
static unsigned int digest_len = 0;

static char *opt_digest = "md5";
static char *opt_open_secret = NULL;
static char *opt_close_secret = NULL;

static time_t next_secret_change_time = 0;

// Dinamic array functions
struct port_array_t {
	uint16_t *ports;
	size_t count;
	size_t capacity;
};

#define DA_INIT_CAP 10
int da_init(struct port_array_t *da) {
	da->ports = (uint16_t *)calloc(DA_INIT_CAP, sizeof(*da->ports));
	if (!da->ports) {
		fprintf(stderr, "Error: Out of memory in da_init\n");
		return -ENOMEM;
	}
	da->count = 0;
	da->capacity = DA_INIT_CAP;
	return 0;
}

int da_append(struct port_array_t *da, uint16_t port) {
	uint16_t *rports;
	if (da->count >= da->capacity) {
		size_t newcap = da->capacity == 0 ? DA_INIT_CAP : da->capacity*2;
		rports = reallocarray(da->ports, newcap, sizeof(*da->ports));
		if (!rports) {
			fprintf(stderr, "Error: realloc failed in da_append\n");
			return -ENOMEM;
		} else {
			da->ports = rports;
			da->capacity = newcap;
		}
	}
	da->ports[da->count++] = port;
	return 0;
}

void da_clear(struct port_array_t *da) {
	da->count = 0;
}

void da_free(struct port_array_t *da) {
	if (da->ports) { free(da->ports); da->ports = NULL; };
	da->count = 0;
	da->capacity = 0;
}

// Guard/Knock port diapazon
static uint16_t opt_start_port = 1;
static uint16_t opt_end_port = 65535;

// Array with protected ports
static struct port_array_t guard_tcp_ports = {0};
static struct port_array_t opened_tcp_ports = {0};

// Ports knocked by digest
static struct port_array_t open_ports_sequence = {0};
static struct port_array_t close_ports_sequence = {0};

// Clients list
struct client_t {
	struct port_array_t knocked_ports;
	enum {ADDR_TYPE_IPV4, ADDR_TYPE_IPV6} addr_type;
	union nf_inet_addr remote_addr;
	time_t last_packet;
	struct client_t *prev;
	struct client_t *next;
};

static struct client_t *clients_knock_head = NULL;
static struct client_t *clients_open_head = NULL;

// qsort/bsearch compare function
static int cmp_port(const void *a, const void *b) {
	return (int)(*(const uint16_t *)a - *(const uint16_t *)b);
}

// Checks if current port knock sequence matches expected sequense (open or close)
int check_knock_port_sequence(struct port_array_t *knocks, const struct port_array_t *expected) {
	if (knocks->count > expected->count) return 0;
	for (size_t i = 0; i < knocks->count; ++i) {
		if (knocks->ports[i] != expected->ports[i]) return 0;
	}
	return 1;
}

// Insert client at head of list
void client_insert(struct client_t **head, struct client_t *client) {
	client->next = *head;
	client->prev = NULL;
	if (*head) (*head)->prev = client;
	*head = client;
}

// Remove client from list
void client_remove(struct client_t **head, struct client_t *client) {
	if (client->prev) {
		client->prev->next = client->next;
	} else {
		*head = client->next;
	}
	if (client->next) client->next->prev = client->prev;
	da_free(&client->knocked_ports);
	free(client);
}

// Move client from one list to another
void client_move(struct client_t **head1, struct client_t **head2, struct client_t *client) {
	if (client->prev) {
		client->prev->next = client->next;
	} else {
		*head1 = client->next;
	}
	if (client->next) client->next->prev = client->prev;
	client_insert(head2, client);
}

// Callback function for NFQUEUE handler
static int knock_nfq_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	struct nfq_data *nfa, void *data) {

	int ret;
	uint32_t id;
	uint32_t nf_verdict = NF_ACCEPT; // default verdict
	struct nfqnl_msg_packet_hdr *ph;
//	struct nfqnl_msg_packet_hw *hwh;
	(void) nfmsg; // unused
	(void) nfa; // unused
	(void) data; // unused

	unsigned char *payload;
	size_t payload_len;

	struct timeval nfq_tv;
	struct ip *ip_packet;
	uint16_t ip_packet_len;
	struct ip6_hdr *ip6_packet;
	uint16_t ip6_packet_len;
	struct tcphdr *tcp_packet = NULL;
	uint16_t tcp_port;
	// struct udphdr *udp_packet;
	// uint16_t udp_port;
	struct in_addr in = {0};
	struct in6_addr in6 = {0};
	struct client_t *t = NULL;
	int hit_guard_port = 0;
	int hit_opened_port = 0;
	char ipaddr[128];

	ph = nfq_get_msg_packet_hdr(nfa);
	id = ntohl(ph->packet_id);

	if (0 != nfq_get_timestamp(nfa, &nfq_tv)) {
		nfq_tv.tv_sec = time(NULL);
		nfq_tv.tv_usec = 0;
	}

	ret = nfq_get_payload(nfa, &payload);
	if (ret > 0) payload_len = ret;
	else {
		nf_verdict = NF_DROP;
		goto verdict;
	}

	// something wrong - packet len smaller then IP header
	if (payload_len < sizeof(struct ip)) {
		nf_verdict = NF_DROP;
		goto verdict;
	}

	ip_packet = (struct ip *)payload;

	// Detect IP protocol version
	if (4 == ip_packet->ip_v) {
		// IPv4
		size_t ip_hl;
		in = ip_packet->ip_src;
		ip_hl = ip_packet->ip_hl * 4;
		ip_packet_len = ntohs(ip_packet->ip_len);
		if (IPPROTO_TCP == ip_packet->ip_p
			&& ip_packet_len > ip_hl + sizeof(struct tcphdr)
		) {
			tcp_packet = (struct tcphdr *)(payload + ip_hl);
		}

		inet_ntop(AF_INET, &ip_packet->ip_src, ipaddr, sizeof(ipaddr));
	} else if (6 == ip_packet->ip_v) {
		// TODO IPv6 support
		ip6_packet = (struct ip6_hdr *)payload;
		in6 = ip6_packet->ip6_src;
		ip6_packet_len = 0; // ntohs(ip6_packet->ip6_plen); <- ip6_plen this is payload len CHECK THIS !!!
		// TODO ipv6 tcp payload find
		// tcp_packet = (struct tcphdr *)(payload + find_tcp_offset);
		// now simply accept packet

		inet_ntop(AF_INET, &ip6_packet->ip6_src, ipaddr, sizeof(ipaddr));
		(void)ip6_packet_len;

		goto verdict;
	} else {
		goto verdict; // Unknown IP version
	}

	// Process only TCP SYN packets
	if (!tcp_packet) goto verdict;
	if (0 == (tcp_packet->th_flags & TH_SYN)) goto verdict;

	tcp_port = ntohs(tcp_packet->th_dport);
	if (opt_verbose) {
		fprintf(stderr, "%ld: get TCP packet on port %" PRIu16 " from %s\n",
			nfq_tv.tv_sec, tcp_port, ipaddr);
	}

	// Check for hitting guard port list
	if (NULL != bsearch(&tcp_port, guard_tcp_ports.ports, guard_tcp_ports.count,
		sizeof(uint16_t), cmp_port)) hit_guard_port = 1;

	// Check for hitting opened port list
	if (opened_tcp_ports.count > 0 && NULL != bsearch(&tcp_port, opened_tcp_ports.ports,
		opened_tcp_ports.count, sizeof(uint16_t), cmp_port)) hit_opened_port = 1;

	// Try to find client in open list
	t = clients_open_head;
	while (t) {
		if (ip_packet->ip_v == 4 && t->addr_type == ADDR_TYPE_IPV4 &&
			0 == memcmp(&t->remote_addr.in, &in, sizeof(struct in_addr))) break;
		else if (ip_packet->ip_v == 6 && t->addr_type == ADDR_TYPE_IPV6 &&
			0 == memcmp(&t->remote_addr.in6, &in6, sizeof(struct in6_addr))) break;
		t = t->next;
	}

	// Found client in open list
	if (t) {
		// Clean close knock ports by timeout
		if (t->last_packet + opt_timeout < nfq_tv.tv_sec) {
			t->knocked_ports.count = 0;
		}
		t->last_packet = nfq_tv.tv_sec;

		if (da_append(&t->knocked_ports, tcp_port) != 0)
			goto verdict;

		if (t->knocked_ports.count == digest_len / sizeof(uint16_t)) {
			if (!check_knock_port_sequence(&t->knocked_ports, &close_ports_sequence)) {
				// Drop first port from knock sequence for next time
				memmove(&t->knocked_ports.ports[0], &t->knocked_ports.ports[1],
					(t->knocked_ports.count - 1) * sizeof(uint16_t));
				t->knocked_ports.count--;
			} else {
				// Get close ports sequence
				client_remove(&clients_open_head, t);
				if (opt_verbose)
					fprintf(stderr, "%ld: client %s close\n", nfq_tv.tv_sec, ipaddr);
				syslog(LOG_INFO, "%ld: client %s close\n", nfq_tv.tv_sec, ipaddr);
			}
		}
		goto verdict;
	}

	// Try find client in unknown knocked clients
	t = clients_knock_head;
	while (t) {
		// Remove unknown knocked client by timeout
		if (t->last_packet + opt_timeout < nfq_tv.tv_sec) {
			struct client_t *tnext = t->next;
			client_remove(&clients_knock_head, t);
			t = tnext;
			continue;
		}
		if (ip_packet->ip_v == 4 && t->addr_type == ADDR_TYPE_IPV4 &&
			0 == memcmp(&t->remote_addr.in, &in, sizeof(struct in_addr))) break;
		else if (ip_packet->ip_v == 6 && t->addr_type == ADDR_TYPE_IPV6 &&
			0 == memcmp(&t->remote_addr.in6, &in6, sizeof(struct in6_addr))) break;

		t = t->next;
	}

	// Found client in unknown knocked list
	if (t) {
		if (hit_guard_port) nf_verdict = NF_DROP;
		if (da_append(&t->knocked_ports, tcp_port) != 0) {
			nf_verdict = NF_DROP;
			goto verdict;
		};
		t->last_packet = nfq_tv.tv_sec;

		if (t->knocked_ports.count == digest_len / sizeof(uint16_t)) {
			if (!check_knock_port_sequence(&t->knocked_ports, &open_ports_sequence)) {
				memmove(&t->knocked_ports.ports[0], &t->knocked_ports.ports[1],
					(t->knocked_ports.count - 1) * sizeof(uint16_t));
				t->knocked_ports.count--;
			} else {
				// Move client to open list
				client_move(&clients_knock_head, &clients_open_head, t);
				nf_verdict = NF_ACCEPT;
				if (opt_verbose)
					fprintf(stderr, "%ld: client %s open\n", nfq_tv.tv_sec, ipaddr);
				syslog(LOG_INFO, "%ld: client %s open\n", nfq_tv.tv_sec, ipaddr);
			}
		}
		goto verdict;
	}

	// Add new client to unknown knocked list
	if (hit_guard_port) nf_verdict = NF_DROP; // protect guard port if it not open yet for that client
	struct client_t *new_client = calloc(1, sizeof(struct client_t));
	if (!new_client) goto verdict;
	new_client->last_packet = nfq_tv.tv_sec;
	new_client->addr_type = ip_packet->ip_v == 4 ? ADDR_TYPE_IPV4 : ADDR_TYPE_IPV6;
	if (new_client->addr_type == ADDR_TYPE_IPV4) {
		new_client->remote_addr.in = in;
	} else if (new_client->addr_type == ADDR_TYPE_IPV6) {
		new_client->remote_addr.in6 = in6;
	}
	if (da_init(&new_client->knocked_ports) != 0) goto verdict;
	if (da_append(&new_client->knocked_ports, tcp_port) != 0) goto verdict;

	if (opt_verbose) {
		fprintf(stderr, "%ld: new client %s\n", nfq_tv.tv_sec, ipaddr);
	}
	client_insert(&clients_knock_head, new_client);

verdict:
	if (hit_opened_port) nf_verdict = NF_ACCEPT;
	if (opt_verbose) fprintf(stderr, "verdict = %s\n", nf_verdict == NF_ACCEPT ? "accept" : "drop");
	ret = nfq_set_verdict(qh, id, nf_verdict, 0, NULL);
	// ret = nfq_set_verdict_batch(qh, id, nf_verdict);

	return ret;
}

int generate_port_sequence(struct port_array_t *head, unsigned char *digest, size_t digest_len) {
	for (size_t i = 0; i < digest_len / 2; i++) {
		uint16_t port = ((digest[i*2] << 8) | digest[i*2+1]) % (opt_end_port - opt_start_port)
				 + opt_start_port;
		if (da_append(head, port) != 0) return -1;
	}
	return 0;
}

// Prepare OpenSSL library digest context and generate secret
// sequence by hashing password/secret and current hour timestamp.
int prepare_secret_digest() {
	char *buf = NULL;
	unsigned char *digest = NULL;
	size_t buf_size = 0;
	time_t timeperiod;
	size_t s;
	struct tm tm_st;

	timeperiod = time(NULL);
	if (!localtime_r(&timeperiod, &tm_st)) {
		fprintf(stderr, "Error: Cannot get local time: %s\n", strerror(errno));
		return -EINVAL;
	}

	// move to hour start
	tm_st.tm_min = 0;
	tm_st.tm_sec = 0;
	tm_st.tm_isdst = -1;
	timeperiod = mktime(&tm_st);
	next_secret_change_time = timeperiod + 60*60; // next hour

	if (!digest_ctx) {
		digest_ctx = EVP_MD_CTX_new();
		if (!digest_ctx) {
			fprintf(stderr, "Error: cannot create EVP_MD_CTX\n");
			goto err;
		}
	}
	if (!digest) {
		digest = malloc(EVP_MD_size(opt_digest_type));
		if (!digest) {
			fprintf(stderr, "Error: cannot allocate memory for digest\n");
			goto err;
		}
	}

	da_clear(&open_ports_sequence);
	da_clear(&close_ports_sequence);

	// Generate open digest
	if (!EVP_DigestInit_ex(digest_ctx, opt_digest_type, NULL)) {
		fprintf(stderr, "Error: cannot init EVP digest type %s\n", opt_digest);
		goto err;
	}

	buf_size = strlen(opt_open_secret);
	if (buf_size < strlen(opt_close_secret)) buf_size = strlen(opt_close_secret);
	buf_size += 20; // add space for timeperiod

	buf = malloc(buf_size);
	if (!buf) {
		fprintf(stderr,"Error: cannot allocate memory for buffer size %ld\n", buf_size);
		goto err;
	}
	s = snprintf(buf, buf_size, "%s%ld", opt_open_secret, timeperiod);
	if (opt_verbose) fprintf(stderr, "Generate hash for [%s]\n", buf);
	if (!EVP_DigestUpdate(digest_ctx, buf, s)) goto err;
	if (!EVP_DigestFinal_ex(digest_ctx, digest, &digest_len)) goto err;
	if (opt_verbose) {
		fprintf(stderr, "Open digest [%d]: ", digest_len);
		for (size_t i = 0; i < digest_len; i++) {
			fprintf(stderr, "%02x", digest[i]);
		}
		fprintf(stderr, "\n");
	}
	if (generate_port_sequence(&open_ports_sequence, digest, digest_len) != 0) goto err;

	// Generate close digest
	if (!EVP_DigestInit_ex(digest_ctx, opt_digest_type, NULL)) {
		fprintf(stderr, "Can't init EVP digest type %s\n", opt_digest);
		goto err;
	}
	s = snprintf(buf, buf_size, "%s%ld", opt_close_secret, timeperiod);
	if (opt_verbose) fprintf(stderr, "Generate hash for [%s]\n", buf);
	if (!EVP_DigestUpdate(digest_ctx, buf, s)) goto err;
	if (!EVP_DigestFinal_ex(digest_ctx, digest, &digest_len)) goto err;
	if (opt_verbose) {
		fprintf(stderr, "Close digest [%d]: ", digest_len);
		for (size_t i = 0; i < digest_len; i++) {
			fprintf(stderr, "%02x", digest[i]);
		}
		fprintf(stderr, "\n");
	}
	if (generate_port_sequence(&close_ports_sequence, digest, digest_len) != 0) goto err;

	free(digest);
	free(buf);
	return 0;
err:
	if (digest_ctx) { EVP_MD_CTX_free(digest_ctx); digest_ctx = NULL; }
	free(digest);
	free(buf);
	return 1;
}

// Signal handler
void signal_handler(int sig) {
	switch (sig) {
	case SIGTERM:
	case SIGINT:
		working = 0;
		break;
	case SIGUSR1:
		dump_open_clients = 1;
		break;
	case SIGUSR2:
		dump_unknown_client = 1;
		break;
	} // swtich
} // signal_handler

// Help page
void print_usage(FILE *o, const char *prog) {
	fprintf(o, "Usage: %s [options]\n", prog);
	fprintf(o, "Options:\n");
	fprintf(o, "  -f           Running foreground\n");
	fprintf(o, "  -a           Start port number for guard/knock diapazon (default %d)\n", opt_start_port);
	fprintf(o, "  -b           End port number (default %d)\n", opt_end_port);
	fprintf(o, "  -p <port>    Guard TCP port (can be used multiple times)\n");
	fprintf(o, "  -P <port>    Opened TCP port (can be used multiple times)\n");
	fprintf(o, "  -t <seconds> Timeout for knock sequence (default: %d)\n", opt_timeout);
	fprintf(o, "  -o <secret>  Open secret (default: %s)\n", DEFAULT_OPEN_SECRET);
	fprintf(o, "  -c <secret>  Close secret (default: %s)\n", DEFAULT_CLOSE_SECRET);
	fprintf(o, "  -s           Print current secret port sequences (OPEN: and CLOSE: for shell scripts)\n");
	fprintf(o, "  -d <digest>  Digest type - md5, sha256, sha384, sha512 (default: %s)\n", opt_digest);
	fprintf(o, "  -q <queue>   Netfilter queue number (default: %d)\n", opt_queue_id);
	fprintf(o, "  -m <maxlen>  Netfilter max queue length (default: %d)\n", opt_queue_maxlen);
	fprintf(o, "  -i           Create iptables rule with NFQUEUE target\n");
	fprintf(o, "  -h           Print this help\n");
	fprintf(o, "Signals:\n");
	fprintf(o, "  USR1 - dump opened IPs in syslog\n");
	fprintf(o, "  USR2 - dump knocked IPs in syslog\n");
	fprintf(o, "Decription:\n");
	fprintf(o, "  This is nfqknockd - daemon for guard TCP ports and open/close by\n");
	fprintf(o, "  cryptographically generated port-knocking sequences rotated every hour.\n");
	fprintf(o, "  It based on NFQUEUE library and require less resources than libpcap based.\n");
	fprintf(o, "  Not need interface working in promisc mode for capture knock packets.\n");
	fprintf(o, "Author:\n");
	fprintf(o, "  Kuzin Andrey <kuzinandrey@yandex.ru> %s\n", PROG_DATE);
	fprintf(o, "Home:\n");
	fprintf(o, "  https://github.com/KuzinAndrey/nfqknock\n");
	fprintf(o, "Examples:\n");
	fprintf(o, "  %s -p 22 -p 443 -t 10 -o abracadabra -c ahalaymahalay -d sha256\n", prog);
	fprintf(o, "  Protect ssh and https port from unknown connections.\n");
	fprintf(o, "\n");
	fprintf(o, "  %s -o 123 -c 321 -s\n", prog);
	fprintf(o, "  OPEN: 19161 3854 3145 22494 24404 19309 4462 13191\n");
	fprintf(o, "  CLOSE: 3116 25580 8203 7196 17537 13124 20176 1285\n");
	fprintf(o, "  Show port knock sequences for use in shell scripts to open/close protected ports.\n");
}

void find_iptables_cmd() {
	char path[] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin";
	char *p = path;
	char *dir;
	char cmd[PATH_MAX];

	while ((dir = strsep(&p,":")) != NULL) {
		snprintf(cmd, sizeof(cmd), "%s/iptables", dir);
		if (0 == access(cmd, R_OK | X_OK)) {
			iptables_cmd = strdup(cmd);
			break;
		}
	}
}

int main(int argc, char **argv) {
	int ret = 0;
	struct nfq_handle *netfilter_h = NULL;
	struct nfnl_handle *netfilter_nh = NULL;
	struct nfq_q_handle *netfilter_qh = NULL;
	int netfilter_fd;
	int netfilter_rv;
	char netfilter_buf[4096];
	int iptables_create_rule = 0;
	int opt;
	fd_set rfds;
	struct timeval netfilter_fd_tv;

	da_init(&guard_tcp_ports);
	da_init(&opened_tcp_ports);
	da_init(&open_ports_sequence);
	da_init(&close_ports_sequence);

	// parse arguments
	while ( (opt = getopt(argc, argv, "fa:b:p:P:t:o:c:d:vhq:m:si")) != -1) {
		switch (opt) {
		case 'f': { // foreground
			opt_foreground = 1;
			break;
		}
		case 'a': // start port
		case 'b': // end port
		case 'p': // guard port
		case 'P': // opened port
		{
			long port;
			port = atol(optarg);
			if (port <= 0 || port > 65535) {
				fprintf(stderr, "Error: invalid port value - %s\n", optarg);
				ret = 1; goto exit;
			}
			if (opt == 'p' && 0 != da_append(&guard_tcp_ports, (uint16_t)port)) {
				fprintf(stderr, "Error: cannot append port %s\n", optarg);
				ret = 1; goto exit;
			} else if (opt == 'P' && 0 != da_append(&opened_tcp_ports, (uint16_t)port)) {
				fprintf(stderr, "Error: cannot append port %s\n", optarg);
				ret = 1; goto exit;
			} else if (opt == 'a') {
				opt_start_port = port;
			} else if (opt == 'b') {
				opt_end_port = port;
			}
			break;
		}
		case 't': { // timeout
			long to;
			to = atol(optarg);
			if (to <= 0 || to > 600) {
				fprintf(stderr, "Error: invalid timeout value - %s\n", optarg);
				ret = 1; goto exit;
			} else {
				opt_timeout = to;
			}
			break;
		}
		case 'o': // open secret
			if (opt_open_secret) free(opt_open_secret);
			opt_open_secret = strdup(optarg);
			if (!opt_open_secret) { ret = 1; goto exit; }
			memset(argv[optind-1], 'x', strlen(opt_open_secret));
			break;
		case 'c': // close secret
			if (opt_close_secret) free(opt_close_secret);
			opt_close_secret = strdup(optarg);
			if (!opt_close_secret) { ret = 1; goto exit; }
			memset(argv[optind-1], 'x', strlen(opt_close_secret));
			break;
		case 'd': // digest type
			opt_digest = optarg;
			break;
		case 'v': // verbose
			opt_verbose = 1;
			break;
		case 'q': // queue id
			opt_queue_id = atoi(optarg);
			break;
		case 'm': // queue maxlen
			opt_queue_maxlen = atoi(optarg);
			break;
		case 'h': // help
			print_usage(stderr, argv[0]);
			ret = 0; goto exit;
			break;
		case 's': // show ports knocks for scripting
			opt_show_ports = 1;
			break;
		case 'i': // create iptables rule
			opt_touch_iptables = 1;
			find_iptables_cmd();
			break;
		case '?':
			fprintf(stderr, "Error: unknown argument - %c\n", optopt);
			ret = 1; goto exit;
			break;
		}
	}

	if (opt_start_port > opt_end_port) {
		fprintf(stderr, "Error: start port %d must be less than end port %d\n",
			opt_start_port, opt_end_port);
		ret = 1; goto exit;
	}

	if (!opt_open_secret) {
		opt_open_secret = strdup(DEFAULT_OPEN_SECRET);
		if (!opt_open_secret) {
			fprintf(stderr, "Error: Cannot allocate memory for default open secret\n");
			ret = 1;
			goto exit;
		}
	}

	if (!opt_close_secret) {
		opt_close_secret = strdup(DEFAULT_CLOSE_SECRET);
		if (!opt_close_secret) {
			fprintf(stderr, "Error: Cannot allocate memory for default close secret\n");
			ret = 1;
			goto exit;
		}
	}

	// Select digest type for secret
	OpenSSL_add_all_digests();
	if (!strcasecmp("md5", opt_digest)) {
		opt_digest_type = EVP_md5();
	} else if (!strcasecmp("sha256", opt_digest)) {
		opt_digest_type = EVP_sha256();
	} else if (!strcasecmp("sha384", opt_digest)) {
		opt_digest_type = EVP_sha384();
	} else if (!strcasecmp("sha512", opt_digest)) {
		opt_digest_type = EVP_sha512();
	} else {
		fprintf(stderr, "Error: Unsupported digest type - %s\n", opt_digest);
		ret = 1; goto exit;
	};
	if (0 != prepare_secret_digest()) {
		fprintf(stderr, "Error: Cannot generate initial secret digest\n");
		ret = 1; goto exit;
	}

	// Show knock port sequence (useful for shell scripting)
	if (opt_show_ports) {
		printf("OPEN:");
		for (size_t i = 0; i < open_ports_sequence.count; i++) {
			printf(" %d", open_ports_sequence.ports[i]);
		}
		printf("\n");
		printf("CLOSE:");
		for (size_t i = 0; i < close_ports_sequence.count; i++) {
			printf(" %d", close_ports_sequence.ports[i]);
		}
		printf("\n");
		ret = 0; goto exit;
	}

	if (getuid() != 0) {
		fprintf(stderr, "Error: must be run as root\n");
		ret = 1; goto exit;
	}

	if (guard_tcp_ports.count == 0) {
		fprintf(stderr, "Error: No guard ports specified\n");
		ret = 1; goto exit;
	}

	// Prepare sorted array with protected and opened ports
	qsort(guard_tcp_ports.ports, guard_tcp_ports.count, sizeof(*guard_tcp_ports.ports), cmp_port);
	if (opt_verbose) fprintf(stderr, "Protected ports:");
	for (size_t i = 0; i < guard_tcp_ports.count; i++) {
		if (opt_verbose) fprintf(stderr, " %d", guard_tcp_ports.ports[i]);
		if (opt_start_port > guard_tcp_ports.ports[i] ||
		    opt_end_port < guard_tcp_ports.ports[i])
		{
			fprintf(stderr, "Warning: %s port %d not in working diapazon [ %d .. %d ]\n",
				"guard", guard_tcp_ports.ports[i], opt_start_port, opt_end_port);
		}
	}
	if (opt_verbose) fprintf(stderr, "\n");

	if (opened_tcp_ports.count > 0) {
		qsort(opened_tcp_ports.ports, opened_tcp_ports.count, sizeof(*opened_tcp_ports.ports), cmp_port);
		if (opt_verbose) fprintf(stderr, "Opened ports:");
		for (size_t i = 0; i < opened_tcp_ports.count; i++) {
			if (opt_verbose) fprintf(stderr, " %d", opened_tcp_ports.ports[i]);

			if (NULL != bsearch(&opened_tcp_ports.ports[i], guard_tcp_ports.ports,
				guard_tcp_ports.count, sizeof(uint16_t), cmp_port))
			{
				fprintf(stderr, "Warning: opened port %d found in guard port list too\n",
					opened_tcp_ports.ports[i]);
			}

			if (opt_start_port > opened_tcp_ports.ports[i] ||
			    opt_end_port < opened_tcp_ports.ports[i])
			{
				fprintf(stderr, "Warning: %s port %d not in working diapazon [ %d .. %d ]\n",
					"opened", opened_tcp_ports.ports[i], opt_start_port, opt_end_port);
			}
		}
		if (opt_verbose) fprintf(stderr, "\n");
	}

	// Daemonize
	if (!opt_foreground) {
		if (daemon(0, 0) != 0) {
			fprintf(stderr, "Error: cannot daemonize process\n");
			ret = 1; goto exit;
		};
	} else {
		fprintf(stderr, "Work in foreground mode (press Ctrl+C for break)\n");
	}

#define IPTABLES_NFQUEUE_TEMPLATE "%s -%s INPUT -p tcp --syn --dport %d:%d -j NFQUEUE --queue-bypass --queue-num %d 2> /dev/null"
	// Add iptables rule if it not present
	if (opt_touch_iptables && iptables_cmd) {
		snprintf(netfilter_buf, sizeof(netfilter_buf), IPTABLES_NFQUEUE_TEMPLATE,
			 iptables_cmd, "C", opt_start_port, opt_end_port, opt_queue_id);
		if (opt_verbose) fprintf(stderr, "Check: %s\n", netfilter_buf);
		if (0 != system(netfilter_buf)) {
			snprintf(netfilter_buf, sizeof(netfilter_buf), IPTABLES_NFQUEUE_TEMPLATE,
				 iptables_cmd, "I", opt_start_port, opt_end_port, opt_queue_id);
			if (opt_verbose) fprintf(stderr, "Call: %s\n", netfilter_buf);
			if (0 != system(netfilter_buf)) {
				fprintf(stderr, "Error: Cannot create iptables rule\n");
				ret = 1; goto exit;
			} else iptables_create_rule = 1;
		}
	}

	// Prepare Netfilter Queue library
	netfilter_h = nfq_open();
	if (!netfilter_h) {
		fprintf(stderr, "Error: Cannot open NFQUEUE handle\n");
		ret = 1; goto exit;
	}

	netfilter_nh = nfq_nfnlh(netfilter_h);
	netfilter_fd = nfnl_fd(netfilter_nh);

	netfilter_qh = nfq_create_queue(netfilter_h, opt_queue_id, &knock_nfq_callback, NULL);
	if (!netfilter_qh) {
		fprintf(stderr, "Error: Cannot create NFQUEUE %" PRIu16 "\n", opt_queue_id);
		ret = 1; goto exit;
	}

	if (nfq_set_queue_maxlen(netfilter_qh, opt_queue_maxlen) < 0) {
		fprintf(stderr, "Warning: Cannot set queue maxlen to %" PRIu32 "\n", opt_queue_maxlen);
	}

	// Accept all packets if queue is full (not drop it)
	if (nfq_set_queue_flags(netfilter_qh, NFQA_CFG_F_FAIL_OPEN, NFQA_CFG_F_FAIL_OPEN) < 0) {
		fprintf(stderr, "Warning: Cannot set fail-open flag\n");
	}

	// Copy only ip & tcp header - this enough for port knoking
	if (nfq_set_mode(netfilter_qh, NFQNL_COPY_PACKET, sizeof(struct ip) + sizeof(struct tcphdr)) < 0) {
		fprintf(stderr, "Error: Cannot set packet copy mode\n");
		ret = 1; goto exit;
	}

	signal(SIGTERM, signal_handler);
	signal(SIGINT, signal_handler);
	signal(SIGUSR1, signal_handler);
	signal(SIGUSR2, signal_handler);

	while (1 == working) {
		// Get NFQUEUE packet for work
		netfilter_fd_tv.tv_sec = 1; netfilter_fd_tv.tv_usec = 0;
		FD_ZERO(&rfds);
		FD_SET(netfilter_fd,&rfds);
		if (select(netfilter_fd + 1, &rfds, NULL, NULL, &netfilter_fd_tv) > 0) {
			if (FD_ISSET(netfilter_fd, &rfds)) {
				netfilter_rv = recv(netfilter_fd, netfilter_buf, sizeof(netfilter_buf), 0);
				if (netfilter_rv >= 0) {
					nfq_handle_packet(netfilter_h, netfilter_buf, netfilter_rv);
				};
			}
		}

		// Rotate secrets hourly
		if (time(NULL) >= next_secret_change_time) {
			if (0 != prepare_secret_digest()) {
				fprintf(stderr, "Error: Failed to rotate secrets\n");
				ret = 1; goto exit;
			}
			if (opt_verbose) {
				fprintf(stderr, "Rotated secrets at %ld\n", time(NULL));
			}
		}

		if (dump_open_clients || dump_unknown_client) {
			char ipaddr[128];
			struct client_t *t;
			int count = 0;

			t = clients_open_head;
			while (dump_open_clients && t) {
				if (t->addr_type == ADDR_TYPE_IPV4) {
					inet_ntop(AF_INET, &t->remote_addr.in, ipaddr, sizeof(ipaddr));
				} else if (t->addr_type == ADDR_TYPE_IPV6) {
					inet_ntop(AF_INET6, &t->remote_addr.in6, ipaddr, sizeof(ipaddr));
				}
				syslog(LOG_INFO, "opened for %s\n", ipaddr);
				count++;
				t = t->next;
			}
			if (dump_open_clients && !count)
				syslog(LOG_INFO, "No any opened clients");
			dump_open_clients = 0;

			count = 0;
			t = clients_knock_head;
			while (dump_unknown_client && t) {
				if (t->addr_type == ADDR_TYPE_IPV4) {
					inet_ntop(AF_INET, &t->remote_addr.in, ipaddr, sizeof(ipaddr));
				} else if (t->addr_type == ADDR_TYPE_IPV6) {
					inet_ntop(AF_INET6, &t->remote_addr.in6, ipaddr, sizeof(ipaddr));
				}
				syslog(LOG_INFO, "unknown %s ts %ld\n", ipaddr, t->last_packet);
				count++;
				t = t->next;
			}
			if (dump_unknown_client && !count)
				syslog(LOG_INFO, "No any knocked clients");
			dump_unknown_client = 0;
		}
	} // while working

exit:
	if (netfilter_qh) nfq_destroy_queue(netfilter_qh);
	if (netfilter_h) nfq_close(netfilter_h);

	if (iptables_create_rule && iptables_cmd) {
		snprintf(netfilter_buf, sizeof(netfilter_buf), IPTABLES_NFQUEUE_TEMPLATE,
			iptables_cmd, "D", opt_start_port, opt_end_port, opt_queue_id);
		if (opt_verbose) fprintf(stderr, "Call: %s\n", netfilter_buf);
		if (0 != system(netfilter_buf)) {
			fprintf(stderr, "Error: Cannot delete iptables rule\n");
		}
	}
	if (iptables_cmd) free(iptables_cmd);

	if (digest_ctx) EVP_MD_CTX_free(digest_ctx);

	da_free(&guard_tcp_ports);
	da_free(&opened_tcp_ports);
	da_free(&open_ports_sequence);
	da_free(&close_ports_sequence);

	if (opt_open_secret) free(opt_open_secret);
	if (opt_close_secret) free(opt_close_secret);

	while (clients_knock_head)
		client_remove(&clients_knock_head, clients_knock_head);
	while (clients_open_head)
		client_remove(&clients_open_head, clients_open_head);

	return ret;
}
