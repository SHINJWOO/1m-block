#include <iostream>
#include <fstream>
#include <string>
#include <unordered_set>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <cstring>

using namespace std;

unordered_set<string> blocked_sites;

void load_blocked_sites(const char *filename) {
    ifstream file(filename);
    string line;
    while (getline(file, line)) {
        size_t comma = line.find(',');
        if (comma != string::npos) {
            string host = line.substr(comma + 1);
            // 줄바꿈 문자 제거
            host.erase(host.find_last_not_of("\r\n") + 1);
            blocked_sites.insert(host);
        }
    }
}

bool is_malicious_host(const string &host) {
    return blocked_sites.find(host) != blocked_sites.end();
}

u_int32_t parse_packet(struct nfq_q_handle *qh, struct nfq_data *tb) {
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(tb);
    u_int32_t id = ph ? ntohl(ph->packet_id) : 0;

    unsigned char *data;
    int ret = nfq_get_payload(tb, &data);
    if (ret >= 0) {
        struct iphdr *ip_header = (struct iphdr *)data;
        if (ip_header->protocol == IPPROTO_TCP) {
            int ip_header_len = ip_header->ihl * 4;
            struct tcphdr *tcp_header = (struct tcphdr *)(data + ip_header_len);
            int tcp_header_len = tcp_header->doff * 4;
            char *http_payload = (char *)(data + ip_header_len + tcp_header_len);
            int payload_len = ret - ip_header_len - tcp_header_len;

            if (payload_len > 0) {
                string payload(http_payload, payload_len);
                size_t host_pos = payload.find("Host: ");
                if (host_pos != string::npos) {
                    size_t start = host_pos + 6;
                    size_t end = payload.find("\r\n", start);
                    string host = payload.substr(start, end - start);

                    cout << "Host found: " << host << endl;

                    if (is_malicious_host(host)) {
                        cout << "Blocked: " << host << endl;
                        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
                    }
                }
            }
        }
    }

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *, struct nfq_data *nfa, void *) {
    return parse_packet(qh, nfa);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        cerr << "Usage: " << argv[0] << " <site list file>" << endl;
        return 1;
    }

    load_blocked_sites(argv[1]);

    struct nfq_handle *h = nfq_open();
    if (!h) {
        cerr << "Error during nfq_open()" << endl;
        return 1;
    }

    if (nfq_unbind_pf(h, AF_INET) < 0 || nfq_bind_pf(h, AF_INET) < 0) {
        cerr << "Error during (un)bind_pf()" << endl;
        nfq_close(h);
        return 1;
    }

    struct nfq_q_handle *qh = nfq_create_queue(h, 0, &cb, NULL);
    if (!qh) {
        cerr << "Error during nfq_create_queue()" << endl;
        nfq_close(h);
        return 1;
    }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        cerr << "Can't set packet_copy mode" << endl;
        nfq_destroy_queue(qh);
        nfq_close(h);
        return 1;
    }

    int fd = nfq_fd(h);
    char buf[4096] __attribute__((aligned));
    int rv;

    while ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
        nfq_handle_packet(h, buf, rv);
    }

    nfq_destroy_queue(qh);
    nfq_close(h);
    return 0;
}

