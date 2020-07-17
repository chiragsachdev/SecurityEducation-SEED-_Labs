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
// #include<shadow.h>
// #include<crypt.h>

#define PORT_NO 55555
#define BUF_SIZE 2000
#define CHK_SSL(err) if ((err)<1){ERR_print_errors_fp(stderr); exit(2);}
#define CHK_ERR(err,s) if ((err)==-1){perror(s); exit(1);}

//structure for socket adress of peer called from arpa/inet
struct sockaddr_in peerAddr;

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
int initTCPServer()
{
    int listen_sock;
    struct sockaddr_in server;
    // char buff[100];

    //assigning values to the server
    memset(&server, 0, sizeof(server));
    server.sin_family=AF_INET;
    server.sin_addr.s_addr=htonl(INADDR_ANY);
    server.sin_port=htons(PORT_NO);

    //creating socket
    listen_sock =socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);

    //checking for error in socket created
    CHK_ERR(listen_sock,"socket");

    // getting value for binding the socket
    int err = bind(listen_sock, (struct sockaddr*)&server,sizeof(server)); 

    // checking for a binding error
    CHK_ERR(err,"bind");

    // getting the value of listening of the socket
    err = listen(listen_sock,5);

    // checking the error for listening a connection to the socket
    CHK_ERR(err,"listen")

    return listen_sock;
}

// function to process request from client
void processRequest(SSL* ssl, int sock)
{
    char buf[1024];
    int len = SSL_read (ssl, buf,sizeof(buf)-1);
    buf[len]="\0";
    printf("Received: %s",buf);

    // create html page and send
    char *html = 
    "HTTP/1.1 200 OK\r\n"
	"Content-Type: text/html\r\n\r\n"
	"<!DOCTYPE html><html>"
	"<head><title>Hello World</title></head>"
	"<style>body {background-color: black}"
	"h1 {font-size:3cm; text-align: center; color: white;"
	"text-shadow: 0 0 3mm yellow}</style></head>"
	"<body><h1>Hello, world!</h1></body></html>"; //read html file as text
    SSL_write(ssl,html,strlen(html));
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

    bzero(buff, BUF_SIZE);
    len = SSL_read(ssl,buff,sizeof(buff)-1);
    buff[len] = '\0';
    write(tunfd, buff, len);
}

int main(int argc, char * argv[])
{
    int tunfd, listen_sock;
    
    struct sockaddr_in sa_client;
    size_t client_len;

    // Opening SSL library > not needed in ver  1.1.0
    SSL_library_init();
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();


    tunfd = createTunDevice();
    listen_sock = initTCPServer();
    // SSL* ssl=setupTLSserver();

    SSL_METHOD *meth;
    SSL_CTX* ctx;
    SSL *ssl;
    int err;

    struct sockaddr_in sa_server;

    // SSL context initialization
    meth = (SSL_METHOD*)TLSv1_2_method();
    ctx = SSL_CTX_new(meth);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    // set up server crt and private key
    SSL_CTX_use_certificate_file(ctx,"./cert_server/server-cert.pem",SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx,"./cert_server/server-key.pem",SSL_FILETYPE_PEM);
    // create new  ssl structure for the connection
    ssl=SSL_new(ctx);

    int sock;
    while(1)
    {
    sock = accept(listen_sock, (struct sockaddr*)&sa_client, &client_len);
    if (fork() == 0) { // The child process
       close (listen_sock);

       SSL_set_fd (ssl, sock);
       int err = SSL_accept (ssl);
       CHK_SSL(err);
       printf ("SSL connection established!\n");

       processRequest(ssl, sock);
      
        while(1)
        {
            fd_set readFDSet;

            FD_ZERO(&readFDSet);
            SSL_set_fd(ssl, sock);
            FD_SET(sock, &readFDSet);
            FD_SET(tunfd, &readFDSet);
            select(FD_SETSIZE, &readFDSet, NULL,NULL,NULL);

            if(FD_ISSET(tunfd, &readFDSet))
                tunSelected(tunfd, ssl);

            if(FD_ISSET(sock, &readFDSet))
                socketSelected(tunfd, ssl);
        }
    } 
    else { // The parent process
        close(sock);
    }
  }
  
}
