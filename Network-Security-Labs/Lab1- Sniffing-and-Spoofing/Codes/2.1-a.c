#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#define ETHER_ADDR_LEN 6

// ethernet header
struct ethheader
{
    // host destination IP
    unsigned char ether_dhost[ETHER_ADDR_LEN];
    // host source IP
    unsigned char ether_shost[ETHER_ADDR_LEN];
    // Protocol
    unsigned short ether_type;
};

// IP header
struct ipheader
{
    // IP header length
    unsigned char       iph_length:4;
    // IP version
    unsigned char       iph_version:4;
    // Type of service
    unsigned short int  iph_tos;
    // IP packet length(header + data)
    unsigned short int  ip_len;
    // Identification
    unsigned short int  iph_ident;
    // Fragmentation flags
    unsigned short int  iph_flag:3;
    // Flags offset
    unsigned short int  iph_offset:13;
    // time to live
    unsigned char       iph_ttl;
    // Protocol type
    unsigned char       iph_protocol;
    // IP datagram checksum
    unsigned short int  iph_chksum;
    // Source IP address
    struct in_addr      iph_sourceip;
    // Destination IP address
    struct in_addr      iph_destip;
};

struct tcpheader
{
u_short src_port;   /* source port */
u_short dst_port;   /* destination port */
};

// validating if a packet has been received
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    printf("Got a packet\n");
    struct ethheader *eth = (struct ethheader *)packet;
    
    // 0x0800 is the IP header type
    if(ntohs(eth->ether_type) == 0x0800)
    {
        struct ipheader * ip = (struct ipheader *)(packet+sizeof(struct ethheader));
        struct tcpheader *tcp= (struct tcpheader *)(packet+sizeof(struct ethheader)+sizeof(struct ipheader));
        // printing source IP
    printf("\t From:%s\n",inet_ntoa(ip->iph_sourceip));
    //   printing destination IP
    printf("\t Tp:%s\n",inet_ntoa(ip->iph_destip));
    // printing source port
    printf("\t Port:%d\n",htons(tcp->src_port));

    }
}


void main()
{
    // pcap structure handle
    pcap_t *handle;
    char errbuff[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    //filtering only icmp protocol
    char filter_exp[] = "tcp src portrange 10-100";
    bpf_u_int32 net;

    // opening socket
    handle = pcap_open_live("enp0s3", BUFSIZ,1,1000,errbuff);

    // filter_exp -> BPF pseudocode
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle,&fp);

    // capture
    pcap_loop(handle, -1, got_packet, NULL);

    // closing socket
    pcap_close(handle);
}