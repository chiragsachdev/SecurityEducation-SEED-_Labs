#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
// #include <netinet/ip_icmp.h>

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
    unsigned char       iph_length:4, iph_version:4;
    // Type of service
    unsigned char       iph_tos;
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

// icmp header
struct icmpheader
{
    // icmp message type
    unsigned char       icmp_type;
    // error code
    unsigned char       icmp_code;
    // checksum for icmp header and data
    unsigned short int  icmp_chksum;
    // used for identifying request
    unsigned short int  icmp_id;
    // sequence number
    unsigned short int  icmp_seq;
};

// calculating checksum
unsigned short in_chksum(unsigned short *buf, int length)
{
    unsigned short *w=buf;
    int nleft=length;
    int sum=0;
    unsigned short temp=0;
    while(nleft>1)
    {
        sum+=*w++;
        nleft-=2;
    }
    if(nleft==1)
    {
        *(unsigned char *)(&temp)=*(unsigned char *)w;
        sum+=temp;
    }
    sum=(sum >> 16)+(sum & 0xFFFF);
    sum+=(sum >> 16);
    sum=~sum;
    sum=(unsigned short)(sum);
    return sum;
}
// sending raw IP
void send_raw_ip_packet(struct ipheader *ip)
{
    struct sockaddr_in dest_info;
    int enable=1;

    // creating raw network packet
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    // setting up socket option
    setsockopt(sock,IPPROTO_IP, IP_HDRINCL, &enable,sizeof(enable));

    // destination info
    dest_info.sin_family=AF_INET;
    dest_info.sin_addr=ip->iph_destip;
    // dest_info.sin_port = htons(9090);

    // sending raw packet
    sendto(sock,ip,htons(ip->iph_length),0,(struct sockaddr *)&dest_info, sizeof(dest_info));
    printf("Packet sent\n");
    
    // closing socket
    close(sock);
}

// validating if a packet has been received
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    char buffer[BUFSIZ];
    memset(buffer,0,BUFSIZ);
    printf("Got a packet\n");
    struct ethheader *eth = (struct ethheader *)packet;
    struct ethheader *new_eth=(struct ethheader *)buffer;
    struct ipheader *ip = (struct ipheader *)(packet+sizeof(struct ethheader));
    struct ipheader *new_ip=(struct ipheader *)(buffer+sizeof(struct ethheader));
    struct icmpheader *icmp=(struct icmpheader *)(packet+sizeof(struct ethheader)+sizeof(struct ipheader));
    struct icmpheader *new_icmp=(struct icmpheader *)(buffer+sizeof(struct ethheader)+sizeof(struct ipheader));
    // filling new eth packet
    // strcpy(eth->ether_shost,new_eth->ether_dhost);
    // strcpy(eth->ether_dhost,new_eth->ether_shost);
    // new_eth->ether_type=eth->ether_type;
    // filling ip packet
    new_ip->ip_len=ip->ip_len;
    new_ip->iph_chksum=0;
    new_ip->iph_destip=ip->iph_sourceip;
    new_ip->iph_sourceip=ip->iph_destip;
    new_ip->iph_flag=ip->iph_flag;
    new_ip->iph_ident=ip->iph_ident;
    new_ip->iph_length=ip->iph_length;
    new_ip->iph_offset=ip->iph_offset;
    new_ip->iph_protocol=ip->iph_protocol;
    new_ip->iph_tos=ip->iph_tos;
    new_ip->iph_ttl=ip->iph_ttl;
    new_ip->iph_version=ip->iph_version;
    // filling icmp packet
    new_icmp->icmp_id=icmp->icmp_id;
    new_icmp->icmp_code=icmp->icmp_code;
    new_icmp->icmp_seq=icmp->icmp_seq;
    new_icmp->icmp_type=0;
    new_icmp->icmp_chksum=0;
    new_icmp->icmp_chksum=in_chksum((unsigned short *)icmp, sizeof(struct icmpheader));
    send_raw_ip_packet(new_ip);
    // }
}


void main()
{
    // pcap structure handle
    pcap_t *handle;
    char errbuff[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    //filtering only icmp protocol
    char filter_exp[] = "icmp && icmp[icmptype] == icmp-echo";
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