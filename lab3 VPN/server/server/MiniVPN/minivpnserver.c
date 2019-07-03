#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <unistd.h>
#include <shadow.h>
#include <crypt.h>


#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }

#define PORT_NUMBER 7777
#define BUFF_SIZE 2000

int table[256][3][2];
char* PEM_pass_phrase;


int createTunDevice() {
    int tunfd;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;  

    tunfd = open("/dev/net/tun", O_RDWR);
    ioctl(tunfd, TUNSETIFF, &ifr);       

    int sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(0 > ioctl(sock, SIOCGIFFLAGS, &ifr)) {printf("ioctl fail to bring up tun\n");exit(0);}
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING | IFF_PROMISC;
    if(0 > ioctl(sock, SIOCSIFFLAGS, &ifr)) {printf("ioctl fail to set flag\n");exit(0);}

    char* ip = "192.168.53.1";
    ifr.ifr_addr.sa_family= AF_INET;
    ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr = inet_addr(ip);
    if(0 > ioctl(sock, SIOCSIFADDR, &ifr)) {printf("ioctl fail to set ip\n");exit(0);}
    
    ifr.ifr_netmask.sa_family= AF_INET;
    ((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr.s_addr = inet_addr("255.255.255.0");
    if(0 > ioctl(sock, SIOCSIFNETMASK, &ifr)) {printf("ioctl fail to set mask\n");exit(0);}
    return tunfd;
}

void tunSelected_p(int tunfd){
    int  len;
    char buffer[BUFF_SIZE];
    bzero(buffer, BUFF_SIZE);
    len = read(tunfd, buffer, BUFF_SIZE);
    int ip = (int)(unsigned char)buffer[0x13];
    if(table[ip][2][0]){
        write(table[ip][0][1], buffer, len);
    }
}

void tunSelected_c(int pip, SSL *ssl){
    int  len;
    char buffer[BUFF_SIZE];
    bzero(buffer, BUFF_SIZE);
    len = read(pip, buffer, BUFF_SIZE);
    SSL_write(ssl, buffer, len);
}

void socketSelected_p (int tunfd, int pip, int ip){
    int  len;
    char buffer[BUFF_SIZE];
    bzero(buffer, BUFF_SIZE);
    len = read(pip, buffer, sizeof(buffer) - 1);
    if(strcmp(buffer,"close") == 0){
        close(table[ip][0][1]);
        close(table[ip][1][0]);
        close(table[ip][0][0]);
        close(table[ip][1][1]);
        table[ip][2][0]=0;
        printf("192.168.53.%d disconnected.\n",ip);
        return;
    }
    write(tunfd, buffer, len);

}
void socketSelected_c (int pip, int sockfd, SSL * ssl, int ip){
    int  len;
    char buffer[BUFF_SIZE];
    bzero(buffer, BUFF_SIZE);
    len = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if(len == 0){
        write(table[ip][1][1], "close", 5);
        SSL_shutdown(ssl); 
        SSL_free(ssl);
        exit(0);
    }
    write(pip, buffer, len);
}

int setupTCPServer(){
    struct sockaddr_in sa_server;
    int listen_sock;

    listen_sock= socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHK_ERR(listen_sock, "socket");
    memset (&sa_server, '\0', sizeof(sa_server));
    sa_server.sin_family      = AF_INET;
    sa_server.sin_addr.s_addr = INADDR_ANY;
    sa_server.sin_port        = htons (7777);
    int err = bind(listen_sock, (struct sockaddr*)&sa_server, sizeof(sa_server));
    CHK_ERR(err, "bind");
    err = listen(listen_sock, 5);
    CHK_ERR(err, "listen");
    return listen_sock;
}

int login(char *user, char *passwd) { 
    struct spwd *pw; 
    char *epasswd;
    pw = getspnam(user); 
    if (pw == NULL) { 
        return -1; 
    } 

    printf("Login name: %s\n", pw->sp_namp); 
    printf("Passwd : %s\n", pw->sp_pwdp); 

    epasswd = crypt(passwd, pw->sp_pwdp); 
    if (strcmp(epasswd, pw->sp_pwdp)) { 
        return -1; 
    } 
    return 1; 
}

void loginRequest(SSL* ssl, int sock)
{
    char buf[BUFF_SIZE], usr[BUFF_SIZE], pwd[BUFF_SIZE];

    char *str1 = "Enter Username:";
    SSL_write(ssl, str1, strlen(str1));
    int usrlen = SSL_read(ssl, usr, sizeof(usr) - 1);
    usr[usrlen] = '\0';

    char *str2 = "Enter Password:";
    SSL_write(ssl, str2, strlen(str2));
    int pwdlen = SSL_read(ssl, pwd, sizeof(pwd) - 1);
    pwd[pwdlen] = '\0';

    if(login(usr, pwd) == -1)
    {
        char *str = "Login failed.";
        printf("%s\n", str);
        SSL_write(ssl, str, strlen(str));
        SSL_shutdown(ssl);  SSL_free(ssl);
        close(sock);
        exit(0);
    }
    else
    {
        char *str = "Login successfully.";
        printf("%s\n", str);
        SSL_write(ssl, str, strlen(str));
    }
}

SSL* setupSSL()
{
    SSL_METHOD *meth;
    SSL_CTX* ctx;
    SSL *ssl;
    int err;

    // Step 0: OpenSSL library initialization 
    // This step is no longer needed as of version 1.1.0.
    SSL_library_init();
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();

    // Step 1: SSL context initialization
    meth = (SSL_METHOD *)TLSv1_2_method();
    ctx = SSL_CTX_new(meth);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    // Step 2: Set up the server certificate and private key
    SSL_CTX_use_certificate_file(ctx, "./aaa/server.crt", SSL_FILETYPE_PEM);
    SSL_CTX_set_default_passwd_cb_userdata(ctx, PEM_pass_phrase);
    SSL_CTX_use_PrivateKey_file(ctx, "./aaa/server.key", SSL_FILETYPE_PEM);

    // Step 3: Create a new SSL structure for a connection
    ssl = SSL_new (ctx);

    return ssl;
}

void listenSelected(int listen_sock) {
    int sockfd;

    SSL * ssl = setupSSL();
    struct sockaddr_in sa_client;
    size_t client_len = sizeof(sa_client);
    int ip;
    sockfd = accept(listen_sock, (struct sockaddr*)&sa_client, &client_len);   
    for(ip = 2; ip < 255; ip++){
        if(!table[ip][2][0]){
            table[ip][2][0] = 1;
            pipe(table[ip][0]);
            pipe(table[ip][1]);
            break;
        }
    }
    if((table[ip][2][1] = fork()) == 0){
        close(listen_sock);
        close(table[ip][0][1]);
        close(table[ip][1][0]);
        SSL_set_fd(ssl, sockfd);
        int err = SSL_accept(ssl);
        printf ("SSL connection established!\n");
        CHK_SSL(err);
        loginRequest(ssl, sockfd);
        //offer  ip
        char buffer[20];
        memset(buffer, 0, sizeof(buffer));
        sprintf(buffer,"192.168.53.%d",ip);
        SSL_write(ssl, buffer, strlen(buffer));
        printf("Offered %s %s\n", inet_ntoa(sa_client.sin_addr), buffer);
        // Enter the main loop
        while (1){
            fd_set readFDSet;  
            FD_ZERO(&readFDSet);
            FD_SET(sockfd, &readFDSet);
            FD_SET(table[ip][0][0], &readFDSet);
            select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);         
            if(FD_ISSET(sockfd, &readFDSet)){
                socketSelected_c(table[ip][1][1],sockfd, ssl, ip);
            }
            if(FD_ISSET(table[ip][0][0], &readFDSet)){
                tunSelected_c(table[ip][0][0], ssl);
            }
        }
    }   
    else{
        close(sockfd);
	close(table[ip][0][0]);
	close(table[ip][1][1]);
    }
}

int main(){
    PEM_pass_phrase = getpass("Enter PEM pass phrase:");
    struct sockaddr_in sa_client;
    size_t client_len = sizeof(sa_client);
    int listen_sock = setupTCPServer();
    int tunfd = createTunDevice();
    while(1){
        fd_set readFDSet;
        FD_ZERO(&readFDSet);
        FD_SET(tunfd, &readFDSet);
        FD_SET(listen_sock, &readFDSet);
        for(int i = 2; i < 255;i++){
            if(table[i][2][0]){
                FD_SET(table[i][1][0], &readFDSet);
            }
        }
        select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);
        if(FD_ISSET(tunfd,  &readFDSet)){
            tunSelected_p(tunfd);
        }
        if(FD_ISSET(listen_sock, &readFDSet)){
            listenSelected(listen_sock);
        }
        for(int i = 2; i < 255; i++){
            if(table[i][2][0] && FD_ISSET(table[i][1][0], &readFDSet)){
                socketSelected_p(tunfd, table[i][1][0],i);
            }
        }
    } 
}
