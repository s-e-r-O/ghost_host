#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <net/ethernet.h>

#include "ghost_host.h"
#include "recv.h"

int main(int nargs, char* args[])
{
    struct g_host ghost_host; 

    if (nargs > 1) {
        /*
            TO-DO: Turn 'char* args[1]' into a uint32_t (check existence of a function for that in net libs),
            for now, 169.254.30.10 will be hardcoded :(                   
        */
        ghost_host.ip_addr = 0xA9FE1E0A; //169.254.30.10
	    printf("Ghost Host IP Address: %s\n", args[1]);
    } else {
        char host_ip_addr_str[16];
	    printf("Ghost Host IP Address: ");
        scanf("%s", host_ip_addr_str);
        /*
            TO-DO: Turn 'char* host_ip_addr_str' into a uint32_t (check existence of a function for that in net libs),
            for now, 169.254.30.10 will be hardcoded :(                   
        */
        ghost_host.ip_addr = 0xA9FE1E0A;
    }

    /* errbuf is a char buffer used by libpcap to store error messages */
    char errbuf[PCAP_ERRBUF_SIZE];
    

    printf("Looking up for devices...\n");
    /* lookupdev will return the name of the first network device found for capturing packages */
    char *device = pcap_lookupdev(errbuf);

    if(device == NULL){
        perror(errbuf);
        exit(-1);
    }

    printf("Opening %s...\n", device);

    /* 
        Opening network device with BUFSIZ as the snapshot length, in promiscuous mode
        and with a timeout of 5000 ms
    */
    pcap_t* p = pcap_open_live(device, BUFSIZ, 1, 5000, errbuf);

    if (p == NULL){
        perror(errbuf);
        exit(-1);
    }

    printf("Starting to capture...\n");
    /* 
        Proccessing packets of p until an ending condition occurs, with the routine pcap_callback 
        and sending ghost_host data to it.
    */
    pcap_loop(p, -1, pcap_callback, (u_char*) &ghost_host);
    exit(0);
}
