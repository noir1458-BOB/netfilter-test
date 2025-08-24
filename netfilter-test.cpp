#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>         /* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#include <string>
#include <iostream>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

std::string target_host;

void dump(unsigned char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i != 0 && i % 16 == 0)
            printf("\n");
        printf("%02X ", buf[i]);
    }
    printf("\n");
}

static u_int32_t print_pkt(struct nfq_data *tb) {
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    
    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
    }
    
    // 이 부분은 디버깅에 유용하며, 과제 기능 구현에 필수적인 것은 아닙니다.
    // printf("hw_protocol=0x%04x hook=%u id=%u\n", ntohs(ph->hw_protocol), ph->hook, id);

    return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
    u_int32_t id = print_pkt(nfa);
    
    unsigned char *payload;
    int payload_len = nfq_get_payload(nfa, &payload);

    if (payload_len < 0) {
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }
    
    if (payload_len < sizeof(struct iphdr)) {
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }
    
    struct iphdr* ip_header = (struct iphdr*)payload;
    if (ip_header->protocol != IPPROTO_TCP) {
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }
    
    int ip_header_len = ip_header->ihl * 4;

    if (payload_len < ip_header_len + sizeof(struct tcphdr)) {
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }
    
    struct tcphdr* tcp_header = (struct tcphdr*)(payload + ip_header_len);
    int tcp_header_len = tcp_header->doff * 4;

    if (ntohs(tcp_header->dest) != 80 && ntohs(tcp_header->source) != 80) {
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }
    
    const char* http_payload = (const char*)payload + ip_header_len + tcp_header_len;
    int http_payload_len = payload_len - (ip_header_len + tcp_header_len);

    std::string http_data(http_payload, http_payload_len);
    
    size_t host_pos = http_data.find("Host:");
    if (host_pos != std::string::npos) {
        size_t host_value_start = http_data.find_first_not_of(" \t", host_pos + 5);
        if (host_value_start != std::string::npos) {
            size_t host_value_end = http_data.find("\r\n", host_value_start);
            if (host_value_end != std::string::npos) {
                std::string host_name = http_data.substr(host_value_start, host_value_end - host_value_start);
                
                if (host_name == target_host) {
                    std::cout << "filter: " << host_name << std::endl;
                    return nfq_set_verdict(qh, id, NF_DROP, 0, NULL); // 패킷 차단
                }
            }
        }
    }

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL); // 패킷 통과
}

int main(int argc, char **argv) {
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    if (argc != 2) {
        std::cout << "syntax : netfilter-test <host>" << std::endl;
        std::cout << "sample : netfilter-test test.gilgil.net" << std::endl;

    }
    target_host = argv[1];

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h, 0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}