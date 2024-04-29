#include <libnet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdio.h>
#include <pcap.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>

int main() {
    char errbuf_libnet[LIBNET_ERRBUF_SIZE];
    libnet_t *lc = libnet_init(LIBNET_RAW4, "en0", errbuf_libnet);
    if (lc == NULL) {
        fprintf(stderr, "=> Can't initialise libnet: %s\n", errbuf_libnet);
        return 1;
    }
    u_int32_t ip_addr = libnet_name2addr4(lc, "45.33.32.156", LIBNET_DONT_RESOLVE);
    if (ip_addr == -1) {
        fprintf(stderr, "=> Problems with func name2addr4: %s\n", errbuf_libnet);
        return 1;
    }
    libnet_ptag_t tcp_tag;
    for (int port = 1024; port <= 65535; port++) {
        tcp_tag = libnet_build_tcp(
            65535 - (rand() % 60),
            port,
            0,
            0,
            TH_SYN,
            1024,
            0,
            0,
            0,
            NULL,
            0,
            lc,
            tcp_tag
        );
        if (tcp_tag == -1) {
            fprintf(stderr, "=> TCP tag building problem: %s\n", errbuf_libnet);
            return 1;
        }
        int ret_ipv4 = libnet_autobuild_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H, IPPROTO_TCP, ip_addr, lc);
        if (ret_ipv4 == -1) {
            fprintf(stderr, "=> IP autobuild problem: %s\n", errbuf_libnet);
            return 1;
        }
        libnet_write(lc);
        tcp_tag = 0;
    }
    libnet_destroy(lc);
}
