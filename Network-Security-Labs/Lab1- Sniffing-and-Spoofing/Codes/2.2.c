#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>

void main()
{
    struct sockaddr_in dest_info;
    char *data = "UDP message\n";

    // creating network socket
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    // destination info
    memset((char *) &dest_info, 0, sizeof(dest_info));
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr.s_addr = inet_addr("10.0.2.5");
    dest_info.sin_port = htons(9090);

    // sending packet
    sendto(sock, data, strlen(data), 0,(struct sockaddr *)&dest_info, sizeof(dest_info));
    // closing socket
    close(sock);
}