#include <stdio.h>
#include <pcap.h>
 
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    printf("Got a packet\n");
} 

void main()
{
    pcap_t *handle;
    char errbuff[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "ip proto icmp && dest port >=10 && dest port <=100";
    bpf_u_int32 net;

    // opening socket
    handle = pcap_open_live("enp0s3", BUFSIZ,1,1000,errbuff);

    // filter_exp -> BPF pseudocode
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle,&fp);

    // capture
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
}