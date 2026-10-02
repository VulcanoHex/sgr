#include <getopt.h>
#include <pcap/pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "ingester.h"
#include "common.h"

static void print_usage() {
    printf("Usage: [OPTIONS]\n");
    printf("\nOptions:\n");
    printf("  -i IFACE                 Network interface for live capture   WIP \n");
    printf("  -r FILE                  Read packets from pcap file\n");
    printf("  -l IP                    Inbound IP address for pcap file\n");
    printf("  -o PATH                  RRD database path (default: /tmp/netflow_metrics.rrd)   WIP\n");
    printf("  -t VAL                   Anomaly probability threshold (default: 0.01)\n");
    printf("  -c VAL                   Convergence delta threshold (default: 0.001)\n");
    printf("  -m NUM                   Maximum concurrent flows (default: 100000)\n");
    printf("  -f EXPR                  BPF filter expression\n");
    printf("  -h                       Show this help\n");
    printf("\nExample:\n");
    printf("    -i eth0 -o /var/lib/netflow.rrd\n");
    printf("    -r capture.pcap -l 192.168.1.100 -t 0.005\n");
}

int main(int argc, char *argv[]) {
        Config config;
        init_config(&config);
    if (argc < 2) {
        print_usage();
        return -1;
    }
    else {
        int opt;
        while ((opt = getopt(argc, argv, "i:r:l:o:t:c:m:f:h")) != -1) {
            switch (opt) {
                case 'i':
                    config.interface = strdup(optarg);
                    config.live_capture = true;
                    break;
                case 'r':
                    config.pcap_file = strdup(optarg);
                    config.live_capture = false;
                    break;
                case 'l':
                    if (inet_pton(AF_INET, optarg, &config.local_ip) <= 0) {
                        fprintf(stderr, "Errore: Indirizzo IP non valido '%s'\n", optarg);
                        free_config(&config);
                        print_usage();
                        return -1;
                    }
                    break;
                case 'o':
                    config.rrd_path = strdup(optarg);
                    break;
                case 't':
                    config.threshold = atof(optarg);
                    break;
                case 'c':
                    config.convergence = atof(optarg);
                    break;
                case 'm':
                    config.max_flows = atoi(optarg);
                    break;
                case 'f':
                    config.filter = strdup(optarg);
                    break;
                case 'h':
                    print_usage();
                    return 0;
                default:
                    print_usage();
                    return -1;
            }
        }

        if (config.pcap_file == NULL && config.interface == NULL) {
            fprintf(stderr, "Error: Must specify either -i (interface) or -r (pcap file)\n");
            print_usage();
            free_config(&config);
            return -1;
        }
        if (config.pcap_file != NULL && config.interface != NULL) {
            fprintf(stderr, "Error: Cannot specify both -i and -r\n");
            print_usage();
            free_config(&config);
            return -1;
        }
        if (config.pcap_file == NULL && config.local_ip != 0) {
            fprintf(stderr, "Error: Must specify -r (pcap file) when using -l (local IP)\n");
            print_usage();
            free_config(&config);
            return -1;
        }
        if (config.pcap_file != NULL && config.local_ip == 0) {
            fprintf(stderr, "Error: Must specify -l (local IP) when using -r (pcap file)\n");
            print_usage();
            free_config(&config);
            return -1;
        }
    }


    char errbuf[PCAP_ERRBUF_SIZE];
    if (!config.live_capture && config.pcap_file != NULL) {
        pcap_t *handle = pcap_open_offline(config.pcap_file, errbuf);
        printf("Poc Test");

        if (handle == NULL) {
            fprintf(stderr, "Error: %s\n", errbuf);
            return 1;
        }

        CaptureContext ctx;
        ctx.handle = handle;
        ctx.config = &config;
        if (init_ndpi_engine(&ctx) != 0) {
            fprintf(stderr, "Error: Failed to initialize NDPI engine\n");
            free_config(&config);
            return 1;
        }

        pcap_loop(handle, -1, offline_packet_callback,(u_char *) &ctx);

        pcap_close(handle);
        return 0;
    }

}
