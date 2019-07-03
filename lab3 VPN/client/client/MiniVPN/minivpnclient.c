#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <sys/signal.h>
#include <net/route.h>

#define BUFF_SIZE 2000
#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define CA_DIR "ca_client" 


int addRoute(char* ip , struct ifreq* ifr)            
{ 
   	// create the control socket.
   	int fd = socket(AF_INET, SOCK_DGRAM, 0);
 
   	struct rtentry route;
   	memset(&route, 0, sizeof(route));
 
   	// set the gateway to 0.
   	struct sockaddr_in *addr = (struct sockaddr_in *)&route.rt_gateway;
   	addr->sin_family = AF_INET;
   	addr->sin_addr.s_addr = 0;
 
   	// set the host we are rejecting. 
   	addr = (struct sockaddr_in*) &route.rt_dst;
   	addr->sin_family = AF_INET;
   	addr->sin_addr.s_addr = inet_addr(ip);
 
   	// Set the mask. In this case we are using 255.255.255.255, to block a single
   	// IP. But you could use a less restrictive mask to block a range of IPs. 
   	// To block and entire C block you would use 255.255.255.0, or 0x00FFFFFFF
   	addr = (struct sockaddr_in*) &route.rt_genmask;
   	addr->sin_family = AF_INET;
   	addr->sin_addr.s_addr = 0xFFFFFF;
 
   	// These flags mean: this route is created "up", or active
   	// The blocked entity is a "host" as opposed to a "gateway"
   	// The packets should be rejected. On BSD there is a flag RTF_BLACKHOLE
   	// that causes packets to be dropped silently. We would use that if Linux
   	// had it. RTF_REJECT will cause the network interface to signal that the 
   	// packets are being actively rejected.
   	route.rt_flags = RTF_UP;// | RTF_HOST | RTF_REJECT;
   	route.rt_metric = 0;
   	route.rt_dev=ifr->ifr_name;
   	// this is where the magic happens..
   	if (ioctl(fd, SIOCADDRT, &route))
   	{
      	perror("Route set failed!");
      	close(fd);
      	return 0;
   	}	
 
   	// remember to close the socket lest you leak handles.
   	close(fd);
   	return 1; 
}

int delRoute(char* ip)            
{ 
   	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
 
   	struct rtentry route;
   	memset(&route, 0, sizeof(route));
 
   	struct sockaddr_in *addr = (struct sockaddr_in *)&route.rt_gateway;
   	addr->sin_family = AF_INET;
   	addr->sin_addr.s_addr = 0;
 
   	addr = (struct sockaddr_in*) &route.rt_dst;
   	addr->sin_family = AF_INET;
   	addr->sin_addr.s_addr = inet_addr(ip);
 
   	addr = (struct sockaddr_in*) &route.rt_genmask;
   	addr->sin_family = AF_INET;
   	addr->sin_addr.s_addr = 0xFFFFFF;
 
   	route.rt_flags = RTF_UP;
   	route.rt_metric = 0;
 
   	// this time we are deleting the route:
   	if(ioctl(fd, SIOCDELRT, &route))
   	{
      	close(fd);
      	return 0;
   	}
 
   	close(fd);
   	return 1; 
}

void int_handler(int sig_no){
   	if(sig_no == SIGINT){		
      	delRoute("192.168.60.0");
      	printf("\nDisconnected from the remote.\n");
      	exit(0);
   	}
}


int createTunDevice(char *ip) {
   	int tunfd;
   	struct ifreq ifr;
   	memset(&ifr, 0, sizeof(ifr));

   	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;  

   	tunfd = open("/dev/net/tun", O_RDWR);
   	ioctl(tunfd, TUNSETIFF, &ifr);
    int sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(ioctl(sock, SIOCGIFFLAGS, &ifr) < 0){printf("ioctl fail to bring up tun\n");exit(0);}
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING | IFF_PROMISC;
    if(0 > ioctl(sock, SIOCSIFFLAGS, &ifr)){printf("ioctl fail to set flag\n");exit(0);}
    ifr.ifr_addr.sa_family= AF_INET;
    ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr = inet_addr(ip);
    if(0 > ioctl(sock, SIOCSIFADDR, &ifr)){printf("ioctl fail to set ip\n");exit(0);}
    ifr.ifr_netmask.sa_family= AF_INET;
    ((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr.s_addr = inet_addr("255.255.255.0");
    if(0 > ioctl(sock, SIOCSIFNETMASK, &ifr)){printf("ioctl fail to set mask\n");exit(0);}   
    addRoute("192.168.60.0",&ifr);
    if(signal(SIGINT, int_handler) == SIG_ERR) printf("can't catch SIGINT.\n'");
    return tunfd;
}

int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    char  buf[300];

    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    X509_NAME_oneline(X509_get_subject_name(cert), buf, 300);
    printf("subject= %s\n", buf);

    if (preverify_ok == 1) {
       printf("Verification passed.\n");
    } else {
       int err = X509_STORE_CTX_get_error(x509_ctx);
       printf("Verification failed: %s.\n",
                    X509_verify_cert_error_string(err));
    }
}

SSL* setupTLSClient(const char* hostname)
{
    // Step 0: OpenSSL library initialization 
   	// This step is no longer needed as of version 1.1.0.
   	SSL_library_init();
   	SSL_load_error_strings();
   	SSLeay_add_ssl_algorithms();

   	SSL_METHOD *meth;
   	SSL_CTX* ctx;
   	SSL* ssl;

   	meth = (SSL_METHOD *)TLSv1_2_method();
   	ctx = SSL_CTX_new(meth);

   	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
   	if(SSL_CTX_load_verify_locations(ctx,NULL, CA_DIR) < 1){
		printf("Error setting the verify locations. \n");
		exit(-1);
   	}
   	ssl = SSL_new (ctx);

   	X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl); 
   	X509_VERIFY_PARAM_set1_host(vpm, hostname, 0);

   	return ssl;
}

int setupTCPClient(const char* hostname, int port)
{
   	struct sockaddr_in server_addr;

   	// Get the IP address from hostname
   	struct hostent* hp = gethostbyname(hostname);

   	// Create a TCP socket
   	int sockfd= socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

   	// Fill in the destination information (IP, port #, and family)
   	memset (&server_addr, '\0', sizeof(server_addr));
   	memcpy(&(server_addr.sin_addr.s_addr), hp->h_addr, hp->h_length);
	// server_addr.sin_addr.s_addr = inet_addr ("10.0.2.14"); 
   	server_addr.sin_port   = htons (port);
   	server_addr.sin_family = AF_INET;

   	// Connect to the destination
   	connect(sockfd, (struct sockaddr*) &server_addr,
        	sizeof(server_addr));

   	return sockfd;
}

void tunSelected(int tunfd, SSL *ssl/*int sockfd*/){
    int  len;
    char buff[BUFF_SIZE];

    //printf("Got a packet from TUN\n");

    bzero(buff, BUFF_SIZE);
    len = read(tunfd, buff, BUFF_SIZE);
    SSL_write(ssl, buff, BUFF_SIZE);
    /*sendto(sockfd, buff, len, 0, (struct sockaddr *) &peerAddr,
                    sizeof(peerAddr));*/
}

void socketSelected (int tunfd, SSL *ssl/*int sockfd*/){
    int  len;
    char buff[BUFF_SIZE];

    //printf("Got a packet from the tunnel\n");

    bzero(buff, BUFF_SIZE);
    len = SSL_read(ssl, buff, sizeof(buff) - 1);
	if(len == 0)
	{
		delRoute("192.168.60.0");
      	printf("\nDisconnected by the remote.\n");
      	exit(-1);
	}
    //len = recvfrom(sockfd, buff, BUFF_SIZE, 0, NULL, NULL);
    write(tunfd, buff, len);
	
}

int main(int argc, char *argv[])
{
   	char *hostname = "svzjq.com";
   	int port = 7777;

   	if (argc > 1) hostname = argv[1];
   	if (argc > 2) port = atoi(argv[2]);

   	/*----------------TLS initialization ----------------*/
   	SSL *ssl   = setupTLSClient(hostname);

   	/*----------------Create a TCP connection ---------------*/
   	int sockfd = setupTCPClient(hostname, port);

   	/*----------------TLS handshake ---------------------*/
   	SSL_set_fd(ssl, sockfd);
   	int err = SSL_connect(ssl); CHK_SSL(err);
   	printf("SSL connection is successful\n");
   	printf ("SSL connection using %s\n", SSL_get_cipher(ssl));

   	/*----------------Login process---------------------*/
   	char str[25];
   	int len;
   	// username
   	len = SSL_read(ssl, str, sizeof(str) - 1);
   	str[len] = '\0';
   	printf("%s", str);
   	scanf("%s", str);
   	SSL_write(ssl, str, strlen(str));
   	// password
   	len = SSL_read(ssl, str, sizeof(str) - 1);
   	str[len] = '\0';
   	//printf("%s", str);
   	//scanf("%s", str);
	char* pwd = getpass(str);
   	SSL_write(ssl, pwd, strlen(pwd));
   	// login result
   	len = SSL_read(ssl, str, sizeof(str) - 1);
   	str[len] = '\0';
   	printf("%s\n", str);
	if(strcmp(str ,"Login failed.") == 0) exit(0);
	char ip[20];
	len = SSL_read(ssl, ip, sizeof(ip) - 1);
	ip[len] = '\0';
	printf("Your IP is %s.\n", ip);
   	/*----------------Send/Receive data --------------------*/
   	int tunfd = createTunDevice(ip);
   	// Enter the main loop
   	while (1) {
     	fd_set readFDSet;

     	FD_ZERO(&readFDSet);
     	FD_SET(sockfd, &readFDSet);
     	FD_SET(tunfd, &readFDSet);
     	select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

     	if (FD_ISSET(tunfd,  &readFDSet)) tunSelected(tunfd, ssl);
     	if (FD_ISSET(sockfd, &readFDSet)) socketSelected(tunfd, ssl);
  	}
}
