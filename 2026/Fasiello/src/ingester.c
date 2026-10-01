#include <net/ethernet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <ndpi/ndpi.h>
#include <string.h>
#include <sys/types.h>

// Struct per il contesto nel pcap callback
typedef struct{
    struct ndpi_detection_module_struct *ndpi_struct;
    // altri dati da mettere nel detector vanno qui
} pcap_context_t;

// Struct per identificare univocamente un flusso (only IPV4)
typedef struct {
    uint8_t layer4_protocol;    // Protocollo L4 (TCP/UDP)
    uint32_t src_ip;            // IP sorgente (network order)
    uint32_t dst_ip;            // IP destinazione (network order)
    uint16_t src_port;          // Porta sorgente (network order)
    uint16_t dst_port;          // Porta destinazione (network order)
} flow_t;


/*
 * Test callback
 * */
// void packet_callback(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
//     printf("Packet Length: %d\n", pkthdr->len);
//     struct iphdr *ip_header = (struct iphdr *)(packet + 14);
//     printf("IP Header: %d\n", ip_header->version);
//     printf("Source IP: %d\n", ip_header->saddr);
//     printf("Destination IP: %d\n", ip_header->daddr);

// }

// void ingest_packets_file(const char *filename, pcap_context_t *pcap_context){
//     char errbuf[PCAP_ERRBUF_SIZE];
//     pcap_t *handle = pcap_open_offline(filename, errbuf);
//     printf("Poc Test");

//     if (handle == NULL) {
//         fprintf(stderr, "Error: %s\n", errbuf);
//     }
//     pcap_loop(handle, -1, packet_callback, pcap_context);

//     pcap_close(handle);
// }


/**
 * Genera un flusso normalizzato a partire dal pacchetto fornito. Usato come chiave per hashmaps (UTHash?).
 *
 * @param caplen Lunghezza del pacchetto
 * @param packet Puntatore al pacchetto
 * @return flow_t Flusso normalizzato
 */
flow_t create_normalized_flow(uint16_t caplen, const u_char *packet) {
    flow_t flow = {0};

    // Analizzo il pacchetto fino al Layer Trasporto
    // (Analisi della lunghezza del protocollo di trasporto viene eseguita dinamicamente con ihl)
    size_t min_len = sizeof(struct ether_header) + sizeof(struct iphdr);

    // Verifico se il pacchetto è abbastanza lungo
    if (caplen < min_len) {
        fprintf(stderr, "Pacchetto troppo corto: caplen=%u, min_len=%zu\n", caplen, min_len);
        return flow;
    }

    struct ether_header *eth = (struct ether_header *)packet;
    // Verifico che il pacchetto sia un Ethernet frame
    if (eth->ether_type != htons(ETHERTYPE_IP)) {
        fprintf(stderr, "Pacchetto non Ethernet: ether_type=%u\n", eth->ether_type);
        return flow;
    }

    struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ether_header));
    // Verifico che il pacchetto sia un IPv4 frame
    if (ip->version != 4) {
        fprintf(stderr, "Pacchetto non IPv4: version=%u\n", ip->version);
        return flow;
    }

    uint8_t l4_proto = ip->protocol;
    // verifico che il pacchetto sia TCP o UDP
    if (l4_proto != IPPROTO_TCP && l4_proto != IPPROTO_UDP) {
        fprintf(stderr, "Pacchetto non TCP/UDP: protocol=%u\n", l4_proto);
        return flow;
    }

    // IP src e dst
    uint32_t src_ip = ip->saddr;
    uint32_t dst_ip = ip->daddr;

    // Porta src e dst
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    // Supporta IPv4 con header length variabile (ihl) (IP con Opzioni)
    if (caplen < sizeof(struct ether_header) + ip->ihl * 4) {
        fprintf(stderr, "Pacchetto troppo corto (failed at ihl): caplen=%u < min_len=%zu\n", caplen, sizeof(struct ether_header) + ip->ihl * 4);
        return flow;
    }

    // Skippo il puntatore al header L4 (TCP/UDP)
    char *l4_header = (char *)(packet + sizeof(struct ether_header) + ip->ihl * 4);

    if (l4_proto == IPPROTO_TCP) {
        if (caplen < sizeof(struct ether_header) + (ip->ihl * 4) + sizeof(struct tcphdr)) {
            fprintf(stderr, "Pacchetto TCP troppo corto: caplen=%u < min_len=%zu\n", caplen, sizeof(struct ether_header) + ip->ihl * 4 + sizeof(struct tcphdr));
            return flow;
        }
        struct tcphdr *tcp = (struct tcphdr *)(l4_header);
        src_port = tcp->source;
        dst_port = tcp->dest;
    } else if (l4_proto == IPPROTO_UDP) {
        if (caplen < sizeof(struct ether_header) + (ip->ihl * 4) + sizeof(struct udphdr)) {
            fprintf(stderr, "Pacchetto UDP troppo corto: caplen=%u < min_len=%zu\n", caplen, sizeof(struct ether_header) + ip->ihl * 4 + sizeof(struct udphdr));
            return flow;
        }
        struct udphdr *udp = (struct udphdr *)(l4_header);
        src_port = udp->source;
        dst_port = udp->dest;
    }

    // Normalizzo il flusso, invertendo src/dst se necessario (condizione d'ordinamento src_ip < dst_ip, in caso di parita src_port < dst_port)
    if ((src_ip < dst_ip) || (src_ip == dst_ip && src_port < dst_port)) {
        flow.src_ip = src_ip;
        flow.dst_ip = dst_ip;
        flow.src_port = src_port;
        flow.dst_port = dst_port;
        flow.layer4_protocol = l4_proto;
    } else {
        flow.src_ip = dst_ip;
        flow.dst_ip = src_ip;
        flow.src_port = dst_port;
        flow.dst_port = src_port;
        flow.layer4_protocol = l4_proto;
    }

    return flow;
}


/*
 * Packet callback
 * Main function da eseguire per ogni pacchetto.
 * Deve contenere tutta la logica di analisi del pacchetto.
 * Deve essere thread-safe.
 * Tutti i dati in analisi devono essere nell'pointer user (pcap_context_t).
 */
void packet_callback(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // Casto il pointer user a pcap_context_t
    pcap_context_t *pcap_context = (pcap_context_t *)user;
    // Estraggo il detection module
    struct ndpi_detection_module_struct *ndpi_struct = pcap_context->ndpi_struct;

    // Estraggo lunghezza e timestamp del pacchetto
    uint16_t caplen = pkthdr->caplen;
    uint64_t time_ms = pkthdr->ts.tv_sec * 1000 + pkthdr->ts.tv_usec / 1000;

    // Estraggo il flusso dal pacchetto
    flow_t flow = create_normalized_flow(caplen, packet);

    if (flow.layer4_protocol == 0) {
        return;
    }
    //...

    // Analizzo il pacchetto con NDPI
    ndpi_protocol prot = ndpi_detection_process_packet(
        ndpi_struct,
        flow,
        packet,     // packet bytes
        caplen,
        time_ms
    );

}


/*
 * Per ogni pacchetto, nel file pcap, lo passa a discretize.c
 * Dato che tutti i pacchetti sono nel file pcap, usa pcap_loop per iterare su tutti i pacchetti.
 * pcap_context deve essere fornito dal chiamante (il main). Inizializzando ndpi_module_detection
 * WORK IN PROGRESS
 *
 */
void ingest_pkt_file(const char *filename, pcap_context_t *pcap_context) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(filename, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Error missing handle: %s\n", errbuf);
        return;
    }

    if(pcap_loop(handle, -1, packet_callback, (u_char *)pcap_context) < 0) {
        fprintf(stderr, "Error: %s\n", pcap_geterr(handle));
    }

    pcap_close(handle);
}
