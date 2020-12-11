#ifndef __SPINE_PROXY_H__
#define __SPINE_PROXY_H__
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <pthread.h>
#include <sys/time.h>

#ifdef __CYGWIN__
#include "cygwin.h"
#endif
/*
	spineproxy.h
	
	Defines various things shared amongst the Spine Proxy source files

*/

#define SPINE_PROXY_VERSION "Spine Proxy v2.3e"

#define INBOUND 0
#define OUTBOUND 1

#define EBXML 0
#define SOAP 1

#define BUFFER_SIZE 102400
#define KEYPASS_SIZE 10240
#define SESSION_TIMEOUT 60
#define LISTEN_BACKLOG 1024
#define FORWARDER_SELECT_TIMEOUT 2
#define ERROR_STRING_LENGTH 2048

#define DEFAULT_CLEAR_PORT 4300
#define DEFAULT_TLS_PORT 443

#define INBOUND_CONNECTION_RECEIVED_TIME 0
#define INBOUND_TLS_START_TIME 1
#define INBOUND_TLS_COMPLETE_TIME 2
#define INBOUND_READ_START_TIME 3
#define INBOUND_READ_END_TIME 4
#define INBOUND_WRITE_START_TIME 5
#define INBOUND_WRITE_END_TIME 6
#define INBOUND_TLS_CLOSE_START 7
#define INBOUND_TLS_CLOSE_END 8
#define OUTBOUND_CONNECTION_START_TIME 9
#define OUTBOUND_CONNECTION_COMPLETE_TIME 10
#define OUTBOUND_TLS_START_TIME 11
#define OUTBOUND_TLS_COMPLETE_TIME 12
#define OUTBOUND_READ_START_TIME 13
#define OUTBOUND_READ_END_TIME 14
#define OUTBOUND_WRITE_START_TIME 15
#define OUTBOUND_WRITE_END_TIME 16
#define OUTBOUND_TLS_CLOSE_START 17
#define OUTBOUND_TLS_CLOSE_END 18

#define TIMING_POINTS 19

#define MAX_SIGNALS 1000

/*
	This is a list of interaction ids (minus versions) known to be synchronous
	web services
*/
#define WEBSERVICES "QUPA_IN010000 QUPA_IN040000"

#undef max
#define max(x,y) ((x) > (y) ? (x) : (y))


typedef struct _sp_forwarder_config {
	char *name;
	char *listen_addr;
	int	listen_port;
	int listen_socket;
	char *logdir;
	char *forward_to;
	int listen_tls; 
	int forward_tls;
	int session_buffer_size;
	int verify_listener;
	int verify_client;
	int ssl_compatibility;
	char *listener_ca_cert_file;		
	char *listener_ca_cert_dir;
	char *listener_cert_file;
	char *listener_private_key_file;
	char *listener_pwfile;
	char *listener_pw;
	int listener_pw_length;
	char *client_ca_cert_file;		
	char *client_ca_cert_dir;
	char *client_cert_file;
	char *client_private_key_file;		
	char *client_pwfile;
	char *client_pw;
	int client_pw_length;
	SSL_CTX *listener_context;
	SSL_CTX *forward_context;
	SSL *listener_ssl;	
	int log_filenames;	
	int send_timeout;
	int recv_timeout;
	int do_not_forward;
	int send_ack;
	int http_200_only;
	int doTiming;
	
	struct _sp_forwarder_config* next;
	
} forwarder_config;

typedef struct _sp_session_type {
	char *from;
	char *to;
	char *buffer;
	char *action;
	char *msgid;
	char *conversationid;
	char *topartyid;
	char *frompartyid;
	int  being_destroyed;
	forwarder_config *forwarder;
	SSL *inbound_ssl;
	SSL *outbound_ssl;
	int port;
	int msg_type;
	long start_time;
	long last_op_time;
	int inbound_socket;
	int outbound_socket;
	int log_file;
	int transmission_details_received;
	int processing_ack;
	int is_done;
	int inbound_stuff_to_write;
	int outbound_stuff_to_write;
	int written_to_file;
	int forwarded_to_network;
	int buffer_read_ptr;
	int content_length;
	int transmission_length;
	int sending_ack;
	int	dead_socket_detected;
	int sending;       /* Set when all the initial data has been received */
	int buffer_size;
	struct _sp_session_type *next;
	struct timeval *timing_points;
} session;

typedef struct _sp_proxy_config {
	forwarder_config* forwarders;
	char* config_file;
	int tls_init_needed;
	int running;
	int isDestroyable;
	int buffer_size;
	session *sessions; 
	pthread_mutex_t *lock_cs;
	long	*lock_count;

	
	/*
		Need to have an efficient way to bind a working (inbound) socket to a session...
		So...
		1. Populate the fd_set for select() from the list
		2. Use the list to check the output from select using FD_ISSET()
		
		
	*/
	
} proxy_config;

char error_string[ERROR_STRING_LENGTH];
proxy_config *proxy;
int isVerbose;
int sigCount;

int loadConfig(int f, proxy_config* p);
forwarder_config* initForwarderConfig();
forwarder_config* registerForwarderConfig(forwarder_config* f);
void destroyForwarderConfig(forwarder_config* f);
proxy_config* makeProxy(char* cfgfile);
void destroyProxy();
void proxy_thread_setup();
void listener();
void* forwarder(void* a);
session* registerSession(char* from, int insock, forwarder_config* f);
void addSession(session* s);
void removeSession(session* s);
void destroySession(session* s);
void doSessionInit(session* s);
void doSessionForward(session* s); 
void createLogfile(session* s);
void setLastOpTime(session* s);
void checkTimeout(session* s);
void setSessionForAck(session* s);
void dumpSession(session* s);
void markSessionDone(session* s, int eof);
void timestampEvent(session *s, int when);
char* makeAck(session* s);
int getListenerPassword(char *buf, int size, int rwflag, void *userdata);
int getForwarderPassword(char *buf, int size, int rwflag, void *userdata);
#endif
