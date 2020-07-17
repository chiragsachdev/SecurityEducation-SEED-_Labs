#include <fcntl.h>		    // POSIX library for file control(opening, closing, changing permissions)
#include<stdio.h>	    	// standard IO library
#include<unistd.h>	    	// POSIX operating system API
#include<arpa/inet.h>		// Berkeley API for manipulating packet contents
#include<linux/if.h>		// linux Kernel modules
#include<linux/if_tun.h>	// linux kernel tunnel modules
#include<sys/ioctl.h>		// system IO control for linux calls
#include<netdb.h>           // 
#include<openssl/ssl.h>     // Openssl API for SSL protocols
#include<openssl/err.h>     // Openssl API for error handling
// #include<curses.h>

#define PORT_NO 55555
#define BUF_SIZE 2000
#define CHK_SSL(err) if ((err)<1){ERR_print_errors_fp(stderr); exit(2);}
#define CA_DIR "ca_client"

struct sockaddr_in server_addr;


int createTunDevice()
{
    int tunfd;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    // specifies that we are creating a tun interface
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI; 

    //open a tunnel interface
    tunfd = open("/dev/net/tun", O_RDWR);
    //register the tun interface with the kernel
    ioctl(tunfd, TUNSETIFF, &ifr);
    return tunfd;
}

// setting up a TCP server
int connectTCPClient(const char* hostname, int port)
{

    //Get the IP address from hostname
    struct hostent* hp = gethostbyname(hostname);

    // creating TCP socket
    int sockfd  = socket(AF_INET, SOCK_STREAM,IPPROTO_TCP);

    //assigning values to the server address
    memset(&server_addr, '\0', sizeof(server_addr));
    server_addr.sin_family=AF_INET;
    memcpy(&(server_addr.sin_addr.s_addr),hp->h_addr,hp->h_length);
    server_addr.sin_port=htons(port);

    // connecting to server socket
    connect(sockfd, (struct sockaddr*)&server_addr,sizeof(server_addr));
    printf("connected!\n");
    return sockfd;
}


// reading packet from the tun interface
void tunSelected (int tunfd, SSL* ssl)
{
    int len;
    char buff[BUF_SIZE];
    
    printf("Got a packet from the TUN\n");

    bzero(buff, BUF_SIZE);
    len = read(tunfd,buff,BUF_SIZE);
    SSL_write(ssl,buff,len);
}

// reading packet from the sock interface
void socketSelected(int tunfd, SSL* ssl)
{
    int len;
    char buff[BUF_SIZE];

    printf("Got a packet from the socket\n");

    len = SSL_read(ssl,buff,sizeof(buff)-1);
    buff[len] = '\0';

    write(tunfd, buff, len);
}

int main(int argc, char * argv[])
{
    char *hostname;
    int port; port = PORT_NO;
    if (argc<2)
        printf("Retry with hostname as a parameter\n"); 
    hostname = argv[1];
    if (argc>2)
        port = atoi(argv[2]);
    
    int tunfd, sockfd;
    
    tunfd = createTunDevice();
    sockfd = connectTCPClient(hostname, port);

    // Opening SSL library > not needed in ver  1.1.0
    SSL_library_init();
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();

    SSL_METHOD *meth;
    SSL_CTX* ctx;
    SSL *ssl;

    // SSL context initialization
    meth = (SSL_METHOD *)TLSv1_2_method();
    ctx = SSL_CTX_new(meth);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    if(SSL_CTX_load_verify_locations(ctx,NULL,CA_DIR)<1)
    {
        printf("Error in setting the verify location");
        exit(0);
    }

    // create new  ssl structure for the connection
    ssl=SSL_new(ctx);
    
    // verifying ca crt with hash
    X509_VERIFY_PARAM *verify_param = SSL_get0_param(ssl);
    X509_VERIFY_PARAM_set1_host(verify_param,hostname,0);
    
    
    // TLS handshake
    SSL_set_fd(ssl, sockfd);
    int err=SSL_connect(ssl);
    CHK_SSL(err);
    printf("SSL Connection successful using %s\n",SSL_get_cipher(ssl));


    char buff[BUF_SIZE];
    char sendBuff[200];
    sprintf(sendBuff,"GET / HTTP/1.1\nHOST: %s \n\n",hostname);
    SSL_write(ssl,sendBuff,strlen(sendBuff));


    int len = SSL_read(ssl,buff,sizeof(buff)-1);
    buff[len]='\0';
    printf("%s\n",buff);

// enter the main loop

    while(1)
    {
        fd_set readFDSet;

        FD_ZERO(&readFDSet);
        FD_SET(sockfd, &readFDSet);
        FD_SET(tunfd, &readFDSet);
        select(FD_SETSIZE, &readFDSet, NULL,NULL,NULL);

        if(FD_ISSET(tunfd, &readFDSet))
            tunSelected(tunfd, ssl);

        if(FD_ISSET(sockfd, &readFDSet))
            socketSelected(tunfd, ssl);
    }  
}
