#include <stdio.h>
#include <string.h>
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

/* TCP header */
typedef u_int tcp_seq;

struct tcpheader 
{
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
        #define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
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
        const char *payload;
        int iph_length=ip->iph_length*4;
        int eth_length=14;
        int tcp_length=ntohs(tcp->th_offx2);
        int payload_length=header->caplen-(iph_length+eth_length+tcp_length);
        // printing source IP
        if (payload_length<1)
            return;
        printf("\t From:%s\n",inet_ntoa(ip->iph_sourceip));
        //   printing destination IP
        printf("\t Tp:%s\n",inet_ntoa(ip->iph_destip));
        // printing source port
        payload=(u_char *)(packet+(iph_length+eth_length+tcp_length));
        const u_char *temp=payload;
        // printf("%s",temp);
        for(int i=0;i<payload_length;i++)
            printf("%x",temp[i]);
        printf("\n");

    }
}


void main()
{
    // pcap structure handle
    pcap_t *handle;
    char errbuff[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    //filtering only icmp protocol
    char filter_exp[] = "tcp";
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