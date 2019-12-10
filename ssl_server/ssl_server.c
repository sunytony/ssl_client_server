#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include <pthread.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#define FAIL    -1
#define MAXSIZE_CLIENT      1000

SSL*  client_list[MAXSIZE_CLIENT];
bool isFull[MAXSIZE_CLIENT];
int size = 0;

pthread_mutex_t mutex;

int ind = 0;

// Create the SSL socket and intialize the socket address structure
int OpenListener(int port)
{
    int sd;
    struct sockaddr_in addr;
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        perror("can't bind port");
        abort();
    }
    if ( listen(sd, 10) != 0 )
    {
        perror("Can't configure listening port");
        abort();
    }
    return sd;
}
int isRoot()
{
    if (getuid() != 0)
    {
        return 0;
    }
    else
    {
        return 1;
    }
}
SSL_CTX* InitServerCTX(void)
{
    SSL_METHOD *method;
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
    SSL_load_error_strings();   /* load all error messages */
    method = TLSv1_2_server_method();  /* create new server-method instance */
    ctx = SSL_CTX_new(method);   /* create new context from method */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    /* set the local certificate from CertFile */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}
void ShowCerts(SSL* ssl)
{
    X509 *cert;
    char *line;
    cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("No certificates.\n");
}
void* Servlet(void* ssl) /* Serve the connection -- threadable */
{
    char buf[1024] = {0};
    int sd, bytes;

    printf("%x ",ssl);

    if ( SSL_accept((SSL*)ssl) == FAIL )     /* do SSL-protocol accept */
        ERR_print_errors_fp(stderr);
    else
    {
        ShowCerts((SSL*)ssl);        /* get any certificates */
        while(1){
            bytes = SSL_read((SSL*)ssl, buf, sizeof(buf)); /* get request */
            buf[bytes] = '\0';
            printf("Client msg: \"%s\"\n", buf);
            if(strcmp(buf, "quit")){
                printf("connected end\n");
                break;
            }
            if ( bytes > 0 )
            {
                SSL_write(ssl, buf, strlen(buf)); /* send reply */
            }
            else
            {
                ERR_print_errors_fp(stderr);
            }
        }
    }
    sd = SSL_get_fd((SSL*)ssl);       /* get socket connection */
    SSL_free((SSL*)ssl);         /* release SSL state */
    close(sd);          /* close connection */

    for(int i = 0; i < MAXSIZE_CLIENT; ++i){
        pthread_mutex_lock(&mutex);
        if((SSL*)ssl == client_list[i]){
            printf("index = %d\n", i);
            client_list[i] = 0;
            isFull[i] = false;
            break;
        }
        pthread_mutex_unlock(&mutex);
    }
    pthread_exit(NULL);
}

void* Servlet_broadcast(SSL* ssl) /* Serve the connection -- threadable */
{
    char buf[1024] = {0};
    int sd, bytes;

    if ( SSL_accept(ssl) == FAIL )     /* do SSL-protocol accept */
        ERR_print_errors_fp(stderr);
    else
    {
       ShowCerts(ssl);        /* get any certificates */
        while(1){
            bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request */
            buf[bytes] = '\0';
            printf("Client msg: \"%s\"\n", buf);
            if(strcmp(buf, "quit") == 0){
                printf("disconnected\n");
                break;
            }
            if ( bytes > 0 )
            {
              
                for(int i = 0; i < MAXSIZE_CLIENT; ++i){
                    pthread_mutex_lock(&mutex);
                    if(isFull[i] == true){
                        SSL_write(client_list[i], buf, strlen(buf));
                    }
                    pthread_mutex_unlock(&mutex);
                }
            }
            else
            {
                ERR_print_errors_fp(stderr);
            }
        }
    }
    sd = SSL_get_fd(ssl);       /* get socket connection */
    SSL_free(ssl);         /* release SSL state */
    close(sd);          /* close connection */

    pthread_mutex_lock(&mutex);
    for(int i = 0; i < MAXSIZE_CLIENT; ++i){
        if(ssl == client_list[i]){
            printf("index = %d\n", i);
            client_list[i] = 0;
            isFull[i] = false;
            break;
        }
    }
    pthread_mutex_unlock(&mutex);

    pthread_exit(NULL);
}

int main(int count, char *Argc[])
{
    SSL_CTX *ctx;
    int server;
    char *portnum;
//Only root user have the permsion to run the server
    if(!isRoot())
    {
        printf("This program must be run as root/sudo user!!");
        exit(0);
    }
    if ( count > 3 || count == 1 )
    {
        printf("Usage: %s <portnum>\n", Argc[0]);
        exit(0);
    }
    // Initialize the SSL library
    SSL_library_init();
    portnum = Argc[1];
    ctx = InitServerCTX();        /* initialize SSL */
    LoadCertificates(ctx, "test.com.crt", "test.com.key"); /* load certs */
    server = OpenListener(atoi(portnum));    /* create server socket */
    while (1)
    {
        pthread_t t_pthread;
        int thr_id;
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;
        int client = accept(server, (struct sockaddr*)&addr, &len);  /* accept connection as usual */
        printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        ssl = SSL_new(ctx);              /* get new SSL state with context */
        printf("ssl create");
        SSL_set_fd(ssl, client);      /* set connection socket to SSL state */

        pthread_mutex_init(&mutex, NULL);
        printf("mutex create");
       
       pthread_mutex_lock(&mutex);
        for(int i = 0; i < MAXSIZE_CLIENT; ++i){
            
            if(isFull[i] == false){
                client_list[i] = ssl;
                isFull[i]= true;
                break;
            }
        }
        pthread_mutex_unlock(&mutex);

        printf("add success");

        if(count == 3 && strcmp(Argc[2], "-b") == 0){
            thr_id = pthread_create(&t_pthread, NULL, Servlet_broadcast, (void*)ssl);
        } else {
            printf("this is not broad");
            thr_id = pthread_create(&t_pthread, NULL, Servlet, (void *)ssl);
        }

        if(thr_id < 0){
			perror("thread create error");
			exit(0);
        }
    }
    close(server);          /* close server socket */
    SSL_CTX_free(ctx);         /* release context */
}