#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "spineproxy.h"

int getListenerPassword(char *buf, int size, int rwflag, void *userdata) {
	forwarder_config* f = (forwarder_config*)userdata;
	if (size < f->listener_pw_length) return 0;
	strcpy(buf, f->listener_pw);
	return f->listener_pw_length;	
}

int getForwarderPassword(char *buf, int size, int rwflag, void *userdata) {
	forwarder_config* f = (forwarder_config*)userdata;
	if (size < f->client_pw_length) return 0;
	strcpy(buf, f->client_pw);
	return f->client_pw_length;	
}


forwarder_config* initForwarderConfig() {
	forwarder_config *f = (forwarder_config*)malloc(sizeof(forwarder_config));
	f->name = (char*)0;
	f->listen_port = 0;
	f->listen_addr = (char*)0;
	f->logdir = (char*)0;
	f->forward_to = (char*)0;
	f->listen_tls = 0;
	f->forward_tls = 0;
	f->session_buffer_size = 0;
	f->verify_listener = 1;
	f->verify_client = 1;
	f->ssl_compatibility = 0;
	f->listener_ca_cert_file = (char*)0;
	f->listener_ca_cert_dir = (char*)0;
	f->listener_cert_file = (char*)0;
	f->listener_private_key_file = (char*)0;
	f->listener_pwfile = (char*)0;
	f->listener_pw = (char*)0;
	f->listener_pw_length = 0;
	f->client_ca_cert_file = (char*)0;
	f->client_ca_cert_dir = (char*)0;
	f->client_cert_file = (char*)0;
	f->client_private_key_file = (char*)0;
	f->client_pwfile = (char*)0;
	f->client_pw = (char*)0;
	f->client_pw_length = 0;
	f->listener_context = (SSL_CTX*)0;
	f->forward_context = (SSL_CTX*)0;
	f->log_filenames = 0;
	f->send_timeout = 0;
	f->recv_timeout = 0;
	f->do_not_forward = 0;
	f->send_ack = 1;
	f->http_200_only = 0;
	f->doTiming = 0;
	f->listen_socket = -1;
	f->next = NULL;
	return f;
}

forwarder_config* registerForwarderConfig(forwarder_config* f) {
	if (proxy->forwarders) {
		forwarder_config* g = proxy->forwarders;
		while (g->next) g = g->next;
		g->next = f;
	} else {
		proxy->forwarders = f;
	}	
	return f;
}

void destroyForwarderConfig(forwarder_config* f) {
	if (!f) return;
	if (f->next)
		destroyForwarderConfig(f->next);
	if (f->listener_ssl) {
		SSL_shutdown(f->listener_ssl);
		SSL_free(f->listener_ssl);
		f->listener_ssl = (SSL*)0;
	}
	if (f->listener_ca_cert_file) free (f->listener_ca_cert_file);
	if (f->listener_ca_cert_dir) free(f->listener_ca_cert_dir);
	if (f->client_ca_cert_file) free (f->client_ca_cert_file);
	if (f->client_ca_cert_dir) free(f->client_ca_cert_dir);
	if (f->listener_cert_file) free(f->listener_cert_file);
	if (f->listener_pwfile) free(f->listener_pwfile);
	if (f->listener_pw) {
		memset(f->listener_pw, 0, strlen(f->listener_pw));
		free(f->listener_pw);
	}
	if (f->listener_private_key_file) free(f->listener_private_key_file);
	if (f->client_cert_file) free(f->client_cert_file);
	if (f->client_pwfile) free(f->client_pwfile);
	if (f->client_pw) {
		memset(f->client_pw, 0, strlen(f->client_pw));
		free(f->client_pw);
	}
	if (f->client_private_key_file) free(f->client_private_key_file);
	if (f->name) free(f->name);
	if (f->forward_to) free(f->forward_to);
	if (f->listen_addr) free(f->listen_addr);
	if (f->logdir) free(f->logdir);
	free(f);
}

