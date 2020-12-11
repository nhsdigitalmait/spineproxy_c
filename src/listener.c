#include "spineproxy.h"
#include <stdio.h>
#include <pthread.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include <openssl/err.h>

void initForwarderTLS() {
	forwarder_config* f = proxy->forwarders;
	while(f) {
		if (f->listen_tls) {
			if (f->ssl_compatibility) {
				f->listener_context = SSL_CTX_new(SSLv23_server_method());
			} else {
				f->listener_context = SSL_CTX_new(TLSv1_server_method());
			}
			if (!SSL_CTX_load_verify_locations(f->listener_context, f->listener_ca_cert_file, f->listener_ca_cert_dir)) {
				snprintf(error_string, ERROR_STRING_LENGTH, "Failed to load %s CA certificate file: %s\n", f->name, ERR_reason_error_string(ERR_get_error()));
				errno = EINVAL;
				perror(error_string);
				exit(EXIT_FAILURE);
			} else {
				if (f->verify_listener) {
					SSL_CTX_set_verify(f->listener_context, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
				}
				if (SSL_CTX_use_certificate_chain_file(f->listener_context, f->listener_cert_file) != 1) {
					snprintf(error_string, ERROR_STRING_LENGTH, "Failed to load listener %s certificate file: %s\n", f->name, ERR_reason_error_string(ERR_get_error()));
					errno = EINVAL;
					perror(error_string);
					exit(EXIT_FAILURE);
				} else {
					if (f->listener_pwfile) {
						SSL_CTX_set_default_passwd_cb(f->listener_context, getListenerPassword);
						SSL_CTX_set_default_passwd_cb_userdata(f->listener_context, (void*)f);
					}
					if (SSL_CTX_use_PrivateKey_file(f->listener_context, f->listener_private_key_file, SSL_FILETYPE_PEM) != 1) {
						snprintf(error_string, ERROR_STRING_LENGTH, "Failed to load listener %s private key file: %s\n", f->name, ERR_reason_error_string(ERR_get_error()));
						errno = EINVAL;
						perror(error_string);
						exit(EXIT_FAILURE);
					} else {
						f->listener_ssl = SSL_new(f->listener_context);
					}
				}				
			}
		}
		f = f->next;
	}
}

/*
	Run in the main thread when the proxy is started. 
*/
void listener() {

	if (!proxy) {
		snprintf(error_string, ERROR_STRING_LENGTH, "%s","listener() - no proxy\n");
		errno = EINVAL;
		perror(error_string);
		exit(EXIT_FAILURE);					
	}

	if (proxy->tls_init_needed) {
		initForwarderTLS();
	}

	struct sockaddr_in addr, client;
	forwarder_config* f = proxy->forwarders;
	int size;
	
	if (f == NULL) {
		perror("No forwarders defined");
		destroyProxy();
		exit(EXIT_FAILURE);					
	}
	fd_set active_fd_set, read_fd_set;
	FD_ZERO(&active_fd_set);	
	while (f) {
		int listen_socket = socket(PF_INET, SOCK_STREAM, 0);
		if (listen_socket < 0) {
			if (isVerbose) {
				perror("Failed to create listening socket");
				destroyProxy();
				exit(EXIT_FAILURE);					
			}
		}
		
		memset(&addr, 0, sizeof(addr));
		/*
			Set the listening address....
		*/
		addr.sin_family = AF_INET;
		addr.sin_port = htons(f->listen_port);
		if (!inet_aton(f->listen_addr, (struct in_addr*)&(addr.sin_addr))) {
			snprintf(error_string, ERROR_STRING_LENGTH, "Forwarder %s failed - invalid address %s\nExitting proxy", f->name, f->listen_addr);
			perror(error_string);
			destroyProxy();
			exit(EXIT_FAILURE);
		} else {
			if (bind (listen_socket, (struct sockaddr *)&addr, sizeof (addr)) < 0) {
				snprintf(error_string, ERROR_STRING_LENGTH, "Forwarder %s failed to bind to %s %i\nExitting proxy", f->name, f->listen_addr, f->listen_port);
				perror(error_string);
				destroyProxy();
				exit(EXIT_FAILURE);
			} else {
				if (listen(listen_socket, LISTEN_BACKLOG) < 0) {
					snprintf(error_string, ERROR_STRING_LENGTH, "Forwarder %s failed to listen to %s &i\nExitting proxy", f->name, f->listen_addr, f->listen_port);
					perror(error_string);
					destroyProxy();
					exit(EXIT_FAILURE);					
				} else {
					f->listen_socket = listen_socket;
					FD_SET (listen_socket, &active_fd_set);
					snprintf(error_string, ERROR_STRING_LENGTH, "Forwarder %s listening on %s %i ", f->name, f->listen_addr, f->listen_port);
					/*
						This is NOT an error, but it gets the notification out.
					*/
					errno = 0;
					perror(error_string);
				}
				if (f->listen_tls) {
					if (!SSL_set_fd(f->listener_ssl, f->listen_socket)) {
						snprintf(error_string, ERROR_STRING_LENGTH, "ERROR listening for TLS connection: %s\nExitting proxy",ERR_reason_error_string(ERR_get_error()));
						perror(error_string);
						destroyProxy();
						exit(EXIT_FAILURE);											
					}
				}
			}		
		}
		f = f->next;
	}
	while(proxy->running) {
		read_fd_set = active_fd_set;		
		int sel = select (FD_SETSIZE, &read_fd_set, NULL, NULL, NULL);
		if (sel < 0) {
          perror ("Select failed");
          return;
        }		
		f = proxy->forwarders;
		while(f) {
			if (FD_ISSET (f->listen_socket, &read_fd_set)) {
				int new;
				size = sizeof (client);
				memset(&addr, 0, size);
				new = accept (f->listen_socket, (struct sockaddr *)&client, (socklen_t*)&size);
				if (new < 0) {
					perror("Accept failed");					
				} else {
					char *ca = (char*)inet_ntoa(client.sin_addr);
					char *clientaddr = (char*)malloc(sizeof(char) * (strlen(ca) + 1));
					strcpy(clientaddr, ca);
					registerSession(clientaddr, new, f);
				}
			}
			f = f->next;
		}
	}
	while(!proxy->isDestroyable);
	destroyProxy();
}




