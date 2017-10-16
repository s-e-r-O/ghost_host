#include "conf-values.h"
#include "init.h"

/* Initialization of pcap filtering */
void ghost_host_pcap_init_filter(pcap_t** p, const char *device){
    
    /* errbuf is a char buffer used by libpcap to store error messages */
    char errbuf[PCAP_ERRBUF_SIZE];

    /* 
        '(ether dst GHOST_HRD_ADDR or broadcast) and (arp or icmp)'
        We only want to capture ARP and ICMP packets directed to our ghost.
    */
    char filter_str[61];
    sprintf(filter_str, "(ether dst %s or broadcast) and (arp or icmp)", GHOST_HRD_ADDR);

    printf("Applying filter: %s\n", filter_str);
    
    /* 
        BPF = Berkeley Packet Filter
        BPF programs can be used to apply filters on packet capture with libpcap.
            - Compile a BPF program (pcap_compile())
            - Set the compiled program as a filter (pcap_setfilter()) 
    */
    struct bpf_program filter_program;
    
    /* 
        Compiling the BPF program 
            -  1 (or any non-zero value) is used for optimization of the BPF program (if possible).
            -  PCAP_NETMASK_UNKNOWN is used because we are not using filters on IPv4 broadcasts 
    */
    if (pcap_compile(*p, &filter_program, filter_str, 1, PCAP_NETMASK_UNKNOWN) == -1){
        perror(errbuf);
        exit(EXIT_FAILURE);
    }
    
    /* Setting the freshly compiled BPF program */
    if(pcap_setfilter(*p, &filter_program) == -1){
        perror(errbuf);
        exit(EXIT_FAILURE);        
    }
}