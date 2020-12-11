#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>

#include "spineproxy.h"

/*
  Spine Proxy v2.0, Damian Murphy, NHS CfH, October 2006

	Implement bi-directional proxy between client system and a server,
	supporting both HTTP and HTTP-over-TLS in both directions. Support
	both "pure" forwarding of HTTP streams, and the "tunnelled" data
	from the CFH NIC message transmission system.

	Data in both directions are captured to a file.

	Uses POSIX threads for:

	- Client and Spine listeners
	- Data readers and forwarders.
	
	INBOUND is client->proxy
	OUTBOUND is proxy->target
	
	Spine/client communication is MOSTLY symmetric, the main difference being that
	a spine-client forwarder will likely specify its own forward-to address (rather
	than reading it out of the message) on the grounds that the data that Spine
	puts in the message is that of the endpoint to which it is sending the
	message - which in this case is the proxy itself.
*/

proxy_config* init(char* cf) {
	proxy_config* p;
	int f = open(cf, O_RDONLY);
	if (f == -1) {
		switch (errno) {
			case EACCES:
				printf("%s %s", "Error reading configuration file - no access: ", cf);
				break;			
			case EMFILE:
				printf("%s %s", "Error reading configuration file - too many files open: ", cf);
				break;			
			case ENOENT:
				printf("%s %s", "Error reading configuration file - not found: ", cf);
				break;			
			default:
				printf("%s %s", "Error reading configuration file: ", cf);
				break;
		}
		return 0;
	}
	p = makeProxy(cf);
	if (!loadConfig(f, p)) {
		return (proxy_config*)NULL;
	} else {
		return p;
	}
}

proxy_config* doArgs(int argc, char *argv[]) {
	if (argc < 2) {
		return 0;
	}
	isVerbose = 0;
	int i;
	for (i = 1; i < argc; i++) {
		if (argv[i][0] == '-') {
			if (argv[i][1] == 'v') {
				printf("%s\n", SPINE_PROXY_VERSION);
			} else {
				if (argv[i][1] == 'w') {
					isVerbose = 1;
				} else {
					return 0;	
				}
			}
		} else {
			return init(argv[i]);
		}
	}
	return 0;
}
 
void interruptHandler(int i) {
	/*
		The working threads loop on proxy->running being true, so unset it and allow
		those threads to clean themselves up and exit tidily.
	*/
	sigCount++;
	switch(i) {
		case SIGTERM:
			perror("SIGTERM received");
			break;
		case SIGHUP:
			perror("SIGHUP received");
			break;
		case SIGINT:
			perror("SIGINT received");
			break;
		case SIGQUIT:
			perror("SIGQUIT received");
			break;
		case SIGPIPE:
			perror("SIGPIPE received");
			break;
		case SIGSEGV:
			perror("SIGSEGV received");
			break;
	}
	if (i == SIGTERM) {
		proxy->running = 0;
	} else {
		if (sigCount > MAX_SIGNALS) {
			proxy->running = 0;
			exit(1);
		}
	}
}
 
int bootProxy(proxy_config* p) {
	signal(SIGTERM, interruptHandler);
	signal(SIGHUP, interruptHandler);
	signal(SIGINT, interruptHandler);
	signal(SIGQUIT, interruptHandler);
	signal(SIGPIPE, interruptHandler);
	signal(SIGSEGV, interruptHandler);
	
	pthread_t forwarder_thread;
	int fw;
	
	/*	
		The forwarder thread is started first...
		... because the listener is run in the main thread and the routine that
		runs it doesn't return until the proxy is stopped.
	*/
	fw = pthread_create(&forwarder_thread, NULL, forwarder, NULL);		
	listener();

	return 1;
}

int main(int argc, char *argv[])
{
	proxy_config* p;
	if (!(p = doArgs(argc, argv))) {
		printf("%s", "Usage: spineproxy [-v] [-w] configfile\n");
		return EXIT_FAILURE;
  	}
	sigCount = 0;
  	proxy = p;
  	if (p->tls_init_needed) {
  		SSL_load_error_strings();
  		SSL_library_init();
  		proxy_thread_setup();
		/*
			Note: This is being developed on and for systems that have a /dev/urandom
			so there is no explicit action to seed a PRNG here. 		
		*/
  	}
  	if (!bootProxy(p)) {
  		return EXIT_FAILURE;
  	}
  	return EXIT_SUCCESS;
}










