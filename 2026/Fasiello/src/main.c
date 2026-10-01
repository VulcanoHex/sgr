#include <getopt.h>
#include <pcap/pcap.h>
#include <stdio.h>

static void print_usage() {
    printf("Usage: [OPTIONS]\n");
    printf("\nOptions:\n");
    printf("  -i, --interface IFACE    Network interface for live capture   WIP \n");
    printf("  -r, --pcap FILE          Read packets from pcap file\n");
    printf("  -o, --rrd PATH           RRD database path (default: /tmp/netflow_metrics.rrd)    WIP\n");
    printf("  -t, --threshold VAL      Anomaly probability threshold (default: 0.01)\n");
    printf("  -c, --convergence VAL    Convergence delta threshold (default: 0.001)\n");
    printf("  -m, --max-flows NUM      Maximum concurrent flows (default: 100000)\n");
    printf("  -f, --filter EXPR        BPF filter expression\n");
    printf("  -h, --help               Show this help\n");
    printf("\nExample:\n");
    printf("   -i eth0 -o /var/lib/netflow.rrd\n");
    printf("   -r capture.pcap -t 0.005\n");
}


int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage();
        return -1;
    }
    else {
        int opt;
        while ((opt = getopt(argc, argv, "i:r:o:t:c:m:f:h")) != -1) {
            switch (opt) {
                case 'i':

                    break;
                case 'r':

                    break;
                case 'o':

                    break;
                case 't':

                    break;
                case 'c':

                    break;
                case 'm':

                    break;
                case 'f':

                    break;
                case 'h':
                    print_usage();
                    return 0;
                default:
                    print_usage();
                    return -1;
            }
        }
    }


    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline("./test/capture.pcap", errbuf);
    printf("Poc Test");

    if (handle == NULL) {
        fprintf(stderr, "Error: %s\n", errbuf);
        return 1;
    }
    pcap_loop(handle, -1, packet_callback, NULL);

    pcap_close(handle);
    return 0;
}
