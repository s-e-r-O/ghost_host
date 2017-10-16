#include "init.h"

/* Initialization of libnet and libnet tags */
void ghost_host_libnet_init(struct configuration *c, const char* device){
    
    /* errbuf is a char buffer used by libnet to store error messages */
    char errbuf[LIBNET_ERRBUF_SIZE];

    printf("Initializing libnet with device: %s\n", device);
    /* 
        Initialization of libnet
            - LIBNET_LINK is for modification of packets from the Link layer 
    */
    c->l = libnet_init(LIBNET_LINK, device, errbuf);

    if (c->l == NULL){
        printf("libnet_init() failed: %s\n", errbuf);
        libnet_destroy(c->l);
        exit(EXIT_FAILURE);
    }

    /* Initialization of tags for each header used in the project */
    c->libnet_tags.ether_tag = malloc(sizeof(libnet_ptag_t));
    *(c->libnet_tags.ether_tag) = LIBNET_PTAG_INITIALIZER;

    c->libnet_tags.ip_tag = malloc(sizeof(libnet_ptag_t));
    *(c->libnet_tags.ip_tag) = LIBNET_PTAG_INITIALIZER;
    
    c->libnet_tags.arp_tag = malloc(sizeof(libnet_ptag_t));
    *(c->libnet_tags.arp_tag) = LIBNET_PTAG_INITIALIZER;
    
    c->libnet_tags.icmp_tag = malloc(sizeof(libnet_ptag_t));
    *(c->libnet_tags.icmp_tag) = LIBNET_PTAG_INITIALIZER;
    
}
