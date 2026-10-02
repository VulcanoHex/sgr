#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <ndpi_api.h>
#include <stdnoreturn.h>
#include <string.h>
#include <sys/types.h>
#include <getopt.h>
#include <pcap/pcap.h>
#include "ndpi_api.h"


/* Sposta Config,init config,free config in un file header comune
 * Gestisce le opzioni utente
 *
 */
typedef struct {
    char *interface;
    char *pcap_file;
    uint32_t local_ip;
    char *rrd_path;
    bool live_capture;
    double threshold;
    double convergence;
    uint32_t max_flows;
    char *filter;
} Config;

// Anche questo va nel coso comune
typedef struct{
    pcap_t *handle;
    Config *config;
    struct ndpi_detection_module_struct *ndpi_struct;   // ndpi?
    // altri dati da mettere nel detector vanno qui
} CaptureContext;

// Struct per identificare univocamente un flusso (only IPV4)
typedef struct {
    uint8_t layer4_protocol;    // Protocollo L4 (TCP/UDP)
    uint32_t local_ip;            // IP sorgente (network order)
    uint32_t remote_ip;            // IP destinazione (network order)
    uint16_t local_port;          // Porta sorgente (network order)
    uint16_t remote_port;          // Porta destinazione (network order)
} flow_t;

// Struct per tabella hash dei flussi
typedef struct {
    flow_t flow;                            // chiave per la tabella hash
    struct ndpi_flow_struct ndpi_flow;      // stato flusso NDPI

    uint32_t packet_count;                  // Numero di pacchetti
    uint32_t last_seen_ms;                  // Timestamp dell'ultimo pacchetto ricevuto
    uint8_t  is_identified;                 // Flag che indica se il flusso è stato identificato
} flow_table_t;


void init_config(Config *config);
void free_config(Config *config);
int init_ndpi_engine(CaptureContext *ctx);
void cleanup_context(CaptureContext *ctx);
