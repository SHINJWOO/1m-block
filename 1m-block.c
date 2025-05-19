#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <sys/types.h>
#include <errno.h>

#define MAX_HOST_LEN 256
#define ALPHABET_SIZE 256

typedef struct node {
    char host[MAX_HOST_LEN];
    struct node* next;
} Node;

int is_malicious_host(const char *host, Node *head);

Node* load_malicious_sites(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Error opening file");
        exit(1);
    }

    Node *head = NULL;
    char line[MAX_HOST_LEN];
    while (fgets(line, sizeof(line), file)) {
        Node *new_node = malloc(sizeof(Node));
        if (!new_node) {
            perror("Memory error");
            exit(1);
        }

        char *comma = strchr(line, ',');
        if (comma) {
            sscanf(comma + 1, "%s", new_node->host);
            new_node->next = head;
            head = new_node;
        }
    }

    fclose(file);
    return head;
}

void preprocess_bad_char(const char *pattern, int size, int badchar[]) {
    for (int i = 0; i < ALPHABET_SIZE; i++)
        badchar[i] = -1;
    for (int i = 0; i < size; i++)
        badchar[(int)pattern[i]] = i;
}

int boyer_moore_search(const char *text, int text_len, const char *pattern, int pattern_len) {
    int badchar[ALPHABET_SIZE];
    preprocess_bad_char(pattern, pattern_len, badchar);

    int s = 0;
    while (s <= (text_len - pattern_len)) {
        int j = pattern_len - 1;

        while (j >= 0 && pattern[j] == text[s + j])
            j--;

        if (j < 0) {
            return s;
        } else {
            s += ((j - badchar[(int)text[s + j]]) > 1) ? j - badchar[(int)text[s + j]] : 1;
        }
    }
    return -1;
}

static u_int32_t parse_packet(struct nfq_q_handle *qh, struct nfq_data *tb, char *host, Node* head) {
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    int ret;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
    }

    ret = nfq_get_payload(tb, &data);
    if (ret >= 0) {
        struct iphdr *ip_header = (struct iphdr *)data;
        if (ip_header->protocol == IPPROTO_TCP) {
            int ip_header_len = ip_header->ihl * 4;
            struct tcphdr *tcp_header = (struct tcphdr *)(data + ip_header_len);
            int tcp_header_len = tcp_header->doff * 4;
            char *http_payload = (char *)(data + ip_header_len + tcp_header_len);

            const char *pattern = "Host: ";
            int offset = boyer_moore_search(http_payload, ret - (ip_header_len + tcp_header_len), pattern, strlen(pattern));
            if (offset != -1) {
                sscanf(http_payload + offset, "Host: %" "255" "s", host);
                printf("Host found: %s\n", host);

                if (is_malicious_host(host, head)) {
                    printf("Blocking: %s\n", host);
                    return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
                }
            }
        }
    }

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
    char host[MAX_HOST_LEN] = "";
    Node *head = (Node *)data;
    u_int32_t id = parse_packet(qh, nfa, host, head);

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <site list file>\n", argv[0]);
        exit(1);
    }

    Node* head = load_malicious_sites(argv[1]);

    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    printf("Opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "Error during nfq_open()\n");
        exit(1);
    }

    printf("Unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "Error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("Binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "Error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("Binding this socket to queue '0'\n");
    qh = nfq_create_queue(h, 0, &cb, head);
    if (!qh) {
        fprintf(stderr, "Error during nfq_create_queue()\n");
        exit(1);
    }

    printf("Setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "Can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
        nfq_handle_packet(h, buf, rv);
    }

    printf("Unbinding from queue 0\n");
    nfq_destroy_queue(qh);

    printf("Closing library handle\n");
    nfq_close(h);

    return 0;
}

int is_malicious_host(const char *host, Node *head) {
    Node* current = head;
    while (current) {
        if (strcmp(host, current->host) == 0) {
            return 1;
        }
        current = current->next;
    }
    return 0;
}
