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
#include <ndpi_includes.h>
#include <stdnoreturn.h>
#include <string.h>
#include <sys/types.h>
#include "common.h"

/**
 * Genera un flusso non normalizzato a partire dal pacchetto fornito.
 * Usato come chiave per hashmaps (UTHash?).
 *
 * @param caplen Lunghezza del pacchetto
 * @param packet Puntatore al pacchetto
 * @return flow_t Flusso non normalizzato
 */
flow_t create_flow(uint16_t caplen, const u_char *packet) {
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

    flow.local_ip = src_ip;
    flow.remote_ip = dst_ip;
    flow.local_port = src_port;
    flow.remote_port = dst_port;
    flow.layer4_protocol = l4_proto;

    return flow;
}

/*
 * Normalizzazione da usare in produzione
 * local_ip: indirizzo IP INBOUND (in offline mode: fornito dall'utente, in online mode: ottenuto automaticamente tramite interfaccia di rete)
 */
flow_t normalize_topologic_flow(flow_t flow, uint32_t local_ip) {
    if (flow.local_ip != local_ip) {
        uint32_t temp_ip = flow.local_ip;
        flow.local_ip = flow.remote_ip;
        flow.remote_ip = temp_ip;
        uint16_t temp_port = flow.local_port;
        flow.local_port = flow.remote_port;
        flow.remote_port = temp_port;
    }
    return flow;
}

/*
 * Normalizzazione usata per TESTING ONLY (perde informazioni su inbound/outbound)
 * Normalizza il flusso invertendo local/remote se necessario
 */
flow_t normalize_num_flow(flow_t flow) {
    if (flow.local_ip > flow.remote_ip || (flow.local_ip == flow.remote_ip && flow.local_port > flow.remote_port)) {
        uint32_t temp_ip = flow.local_ip;
        uint16_t temp_port = flow.local_port;
        flow.local_ip = flow.remote_ip;
        flow.remote_ip = temp_ip;
        flow.local_port = flow.remote_port;
        flow.remote_port = temp_port;
    }
    return flow;
}

// online mode
uint32_t get_local_ip_from_interface(CaptureContext *ctx) {
}


/*
 * Packet callback
 * Main function da eseguire per ogni pacchetto.
 * Deve contenere tutta la logica di analisi del pacchetto.
 * Deve essere thread-safe.
 * Tutti i dati in analisi devono essere nell'pointer user (pcap_context_t).
 */
void offline_packet_callback(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // Casto il pointer user a CaptureContext
    CaptureContext *ctx = (CaptureContext *)user;
    // Estraggo il detection module
    struct ndpi_detection_module_struct *ndpi_struct = ctx->ndpi_struct;

    // Estraggo lunghezza e timestamp del pacchetto
    uint16_t caplen = pkthdr->caplen;
    uint64_t time_ms = pkthdr->ts.tv_sec * 1000 + pkthdr->ts.tv_usec / 1000;

    // Estraggo il flusso dal pacchetto
    flow_t flow = create_flow(caplen, packet);
    // Normalizzo il flusso
    flow = normalize_topologic_flow(flow, ctx->config->local_ip);

    // debug: stampa il flusso
    printf("%u.%u.%u.%u:%u -> %u.%u.%u.%u:%u\n",
        (flow.local_ip >> 24) & 0xFF, (flow.local_ip >> 16) & 0xFF, (flow.local_ip >> 8) & 0xFF, flow.local_ip & 0xFF,
        flow.local_port,
        (flow.remote_ip >> 24) & 0xFF, (flow.remote_ip >> 16) & 0xFF, (flow.remote_ip >> 8) & 0xFF, flow.remote_ip & 0xFF,
        flow.remote_port);

    if (flow.layer4_protocol == 0) {
        return;
    }
    //...

    // Analizzo il pacchetto con NDPI
    // ndpi_struct

}
