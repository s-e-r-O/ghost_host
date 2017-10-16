#include <stdio.h>
#include <stdlib.h>

#include "conf-data.h"
#include "conf-values.h"

#include "handlers.h"

/* Global variables (.-.) to avoid rebuilding packets every time */

libnet_ptag_t ether_tag;
libnet_ptag_t ip_tag;
libnet_ptag_t arp_tag;
libnet_ptag_t icmp_tag;

int main(int nargs, char* args[])
{
    /* 
        Configuration data contains:
            - Ghost Host's IP and MAC address
            - Pointer to pcap_t struct
            - Pointer to libnet_t struct
        Used as an argument for pcap_callback 
    */
    struct configuration conf_data; 

    /* errbuf is a char buffer used by libpcap and libnet to store error messages */
    char errbuf[LIBNET_ERRBUF_SIZE];
    
    /* CONF_DEVICE is a constant defined in conf-values.h */
    const char *device = CONF_DEVICE;

    printf("Initializing libnet with device: %s\n", device);
    /* 
        Initialization of libnet
            - LIBNET_LINK is for modification of packets from the Link layer 
    */
    conf_data.l = libnet_init(LIBNET_LINK, device, errbuf);

    if (conf_data.l == NULL){
        printf("libnet_init() failed: %s\n", errbuf);
        libnet_destroy(conf_data.l);
        exit(EXIT_FAILURE);
    }

    /* Initialization of tags for each header used in the project */
    ether_tag = LIBNET_PTAG_INITIALIZER;
    ip_tag = LIBNET_PTAG_INITIALIZER;
    arp_tag = LIBNET_PTAG_INITIALIZER;
    icmp_tag = LIBNET_PTAG_INITIALIZER;
    
    printf("Initializing libpcap with device: %s...\n", device);

    /* Initialization of pcap 
        -  BUFSIZ is the maximum size of the buffer used to store captured packets
        -  1 (or any non-zero value) is for opening in promiscuous mode
        -  Timeout es 5000 ms
    */
    conf_data.p = pcap_open_live(device, BUFSIZ, 1, 5000, errbuf);

    if (conf_data.p == NULL){
        perror(errbuf);
        libnet_destroy(conf_data.l);
        exit(EXIT_FAILURE);
    }

    printf("Initializing ghost host data...\n\n");
    
    int hrd_addr_length = 6;
    /* 
        GHOST_IP_ADDR is a constant defined in conf-values.h 
        LIBNET_DONT_RESOLVE is used to avoid resolution of DNS of the address
    */
    conf_data.ghost_host.ip_addr = libnet_name2addr4(conf_data.l, GHOST_IP_ADDR, LIBNET_DONT_RESOLVE);

    if (conf_data.ghost_host.ip_addr == -1){
        printf("Error initializing IP address: %s\n", libnet_geterror(conf_data.l));
        libnet_destroy(conf_data.l);
        exit(EXIT_FAILURE);
    }

    /* GHOST_HRD_ADDR is a constant definde in conf-values.h */
    conf_data.ghost_host.hrd_addr = libnet_hex_aton(GHOST_HRD_ADDR, &hrd_addr_length);

    if (conf_data.ghost_host.hrd_addr == NULL){
        printf("Error initializing Hardware address: %s\n", libnet_geterror(conf_data.l));
        libnet_destroy(conf_data.l);
        exit(EXIT_FAILURE);
    }
    
    printf("IP: %s\n", GHOST_IP_ADDR);
    printf("MAC: %s\n", GHOST_HRD_ADDR);
    printf("\nListening...\n");

    /* 
        Proccessing caputred packets by conf_data.p (until an ending condition occurs) on the pcap_callback
        routine and sending configuration data to it.
    */
    pcap_loop(conf_data.p, -1, pcap_callback, (u_char*) &conf_data);
    
    libnet_destroy(conf_data.l);
    exit(EXIT_SUCCESS);
}