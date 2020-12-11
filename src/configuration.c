#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include "spineproxy.h"

#define CONFIG_FILE_BUFFER_SIZE 20000

#define FORWARDER_NAMES "FORWARDER_NAMES"

#define CFG_PORT ".port"
#define CFG_BUFFERSIZE ".buffersize"
#define CFG_ADDRESS ".address"
#define CFG_LOG ".logdir"
#define CFG_SEND_TIMEOUT ".send.timeout"
#define CFG_RECV_TIMEOUT ".recv.timeout"
#define CFG_ASYNC_SESSION ".async.session"
#define CFG_LISTEN_TLS ".listen.tls"
#define CFG_FORWARD_TLS ".forward.tls"
#define CFG_TLS_LISTENER_CA_CERTFILE ".tls.listener.ca.cert.file"
#define CFG_TLS_LISTENER_CA_CERTDIR ".tls.listener.ca.cert.directory"
#define CFG_TLS_FORWARDER_CA_CERTFILE ".tls.forwarder.ca.cert.file"
#define CFG_TLS_FORWARDER_CA_CERTDIR ".tls.forwarder.ca.cert.directory"
#define CFG_TLS_COMPATIBILITY ".tls.accept.sslv3"
#define CFG_TLS_LISTENER_CERTFILE ".tls.listener.cert.file"
#define CFG_TLS_LISTENER_KEYFILE ".tls.listener.key.file"
#define CFG_TLS_LISTENER_NO_VERIFY ".tls.listener.no.verify"
#define CFG_TLS_CLIENT_CERTFILE ".tls.forwarder.cert.file"
#define CFG_TLS_CLIENT_KEYFILE ".tls.forwarder.key.file"
#define CFG_TLS_CLIENT_NO_VERIFY ".tls.forwarder.no.verify"
#define CFG_TLS_LISTENER_PWFILE ".tls.listener.pwfile"
#define CFG_TLS_CLIENT_PWFILE ".tls.forwarder.pwfile"
#define CFG_FWD_TO ".forwardto"
#define CFG_NO_FWD ".donotforward"
#define CFG_SEND_ACK ".send.ack"
#define CFG_HTTP_200_ONLY ".http200only"
#define CFG_DOTIMINGS ".timings"
#define CFG_LOG_FILENAMES ".logfilenames"

void getProperty(char *readbuffer, char *valuebuffer, char *property) {
	/*
		Find property in readbuffer, go to the end of the instance of property we
		just found. Skip any whitespace, colon or equals characters. Then start
		copying into valuebuffer until we reach the end of the line, or the
		end of the readbuffer. Then append zero.
	*/
	char *p = strstr(readbuffer, property);
	if (!p) {
		valuebuffer[0] = (char)0;
		return;
	}
	p += strlen(property);
	while (isspace(*(++p)));
	int i = 0;
	while (*p && (*p != '\r') && (*p != '\n')) {
		valuebuffer[i] = *p;
		p++;
		i++;
	}	
	valuebuffer[i] = (char)0;
}

int makeForwarderConfig(forwarder_config* f, char *buffer, char *name) {
	
	char pname[64];
	char pvalue[1024];
		
	f->name = (char*)malloc((strlen(name) + 1) * sizeof(char));
	strcpy(f->name, name);
	strcpy(pname, name);
	strcat(pname, CFG_PORT);
	getProperty(buffer, pvalue, pname);
	errno = 0;
	f->listen_port = strtol(pvalue, (char**)0, 0);
	if (errno) {
		return 0;
	}
	pvalue[0] = (char)0;
	strcpy(pname, name);
	strcat(pname, CFG_ADDRESS);
	getProperty(buffer, pvalue, pname);
	f->listen_addr = (char*)malloc(sizeof(char) * (strlen(pvalue) + 1));
	strcpy(f->listen_addr, pvalue);
	pvalue[0] = (char)0;
	strcpy(pname, name);
	strcat(pname, CFG_LOG);
	getProperty(buffer, pvalue, pname);
	f->logdir = (char*)malloc(sizeof(char) * (strlen(pvalue)+ 1));
	strcpy(f->logdir, pvalue);

	strcpy(pname, name);
	strcat(pname, CFG_FWD_TO);
	getProperty(buffer, pvalue, pname);
	if (strlen(pvalue)) {
		f->forward_to = (char*)malloc(sizeof(char) * (strlen(pvalue)+ 1));
		strcpy(f->forward_to, pvalue);
	}	
	pvalue[0] = (char)0;
	strcpy(pname, name);
	strcat(pname, CFG_LISTEN_TLS);
	getProperty(buffer, pvalue, pname);
	if (pvalue[0] == 'Y' || pvalue[0] == 'y') {
		f->listen_tls = 1;
	} else {
		f->listen_tls = 0;
	}
	pvalue[0] = (char)0;
	strcpy(pname, name);
	strcat(pname, CFG_DOTIMINGS);
	getProperty(buffer, pvalue, pname);
	if (pvalue[0] == 'Y' || pvalue[0] == 'y') {
		f->doTiming = 1;
	} else {
		f->doTiming = 0;
	}
	pvalue[0] = (char)0;
	strcpy(pname, name);
	strcat(pname, CFG_SEND_ACK);
	getProperty(buffer, pvalue, pname);
	if (pvalue[0] == 'Y' || pvalue[0] == 'y') {
		f->send_ack = 1;
	} else {
		f->send_ack = 0;
	}
	pvalue[0] = (char)0;
	strcpy(pname, name);
	strcat(pname, CFG_HTTP_200_ONLY);
	getProperty(buffer, pvalue, pname);
	if (pvalue[0] == 'Y' || pvalue[0] == 'y') {
		f->http_200_only = 1;
	} else {
		f->http_200_only = 0;
	}
	pvalue[0] = (char)0;
	strcpy(pname, name);
	strcat(pname, CFG_TLS_COMPATIBILITY);
	getProperty(buffer, pvalue, pname);
	if (pvalue[0] == 'Y' || pvalue[0] == 'y') {
		f->ssl_compatibility = 1;
	}
	pvalue[0] = (char)0;
	strcpy(pname, name);
	strcat(pname, CFG_TLS_LISTENER_NO_VERIFY);
	getProperty(buffer, pvalue, pname);
	if (pvalue[0] == 'Y' || pvalue[0] == 'y') {
		f->verify_listener = 0;
	}
	pvalue[0] = (char)0;
	strcpy(pname, name);
	strcat(pname, CFG_TLS_CLIENT_NO_VERIFY);
	getProperty(buffer, pvalue, pname);
	if (pvalue[0] == 'Y' || pvalue[0] == 'y') {
		f->verify_client = 0;
	}
	pvalue[0] = (char)0;
	strcpy(pname, name);
	strcat(pname, CFG_FORWARD_TLS);
	getProperty(buffer, pvalue, pname);
	if (pvalue[0] == 'Y' || pvalue[0] == 'y') {
		f->forward_tls = 1;
	} else {
		f->forward_tls = 0;
	}
	pvalue[0] = (char)0;
	strcpy(pname, name);
	strcat(pname, CFG_TLS_LISTENER_CA_CERTFILE);
	getProperty(buffer, pvalue, pname);
	if (strlen(pvalue)) {
		f->listener_ca_cert_file = (char*)malloc(sizeof(char) * (strlen(pvalue)+ 1));
		strcpy(f->listener_ca_cert_file, pvalue);
	}
	pvalue[0] = (char)0;
	strcpy(pname, name);
	strcat(pname, CFG_TLS_LISTENER_CA_CERTDIR);
	getProperty(buffer, pvalue, pname);
	if (strlen(pvalue)) {
		f->listener_ca_cert_dir = (char*)malloc(sizeof(char) * (strlen(pvalue)+ 1));
		strcpy(f->listener_ca_cert_dir, pvalue);
	}
	pvalue[0] = (char)0;
	strcpy(pname, name);
	strcat(pname, CFG_TLS_FORWARDER_CA_CERTFILE);
	getProperty(buffer, pvalue, pname);
	if (strlen(pvalue)) {
		f->client_ca_cert_file = (char*)malloc(sizeof(char) * (strlen(pvalue)+ 1));
		strcpy(f->client_ca_cert_file, pvalue);
	}
	pvalue[0] = (char)0;
	strcpy(pname, name);
	strcat(pname, CFG_TLS_FORWARDER_CA_CERTDIR);
	getProperty(buffer, pvalue, pname);
	if (strlen(pvalue)) {
		f->client_ca_cert_dir = (char*)malloc(sizeof(char) * (strlen(pvalue)+ 1));
		strcpy(f->client_ca_cert_dir, pvalue);
	}
	pvalue[0] = (char)0;
	strcpy(pname, name);
	strcat(pname, CFG_TLS_LISTENER_CERTFILE);
	getProperty(buffer, pvalue, pname);
	if (strlen(pvalue)) {
		f->listener_cert_file = (char*)malloc(sizeof(char) * (strlen(pvalue)+ 1));
		strcpy(f->listener_cert_file, pvalue);
	}
	pvalue[0] = (char)0;
	strcpy(pname, name);
	strcat(pname, CFG_TLS_LISTENER_KEYFILE);
	getProperty(buffer, pvalue, pname);
	if (strlen(pvalue)) {
		f->listener_private_key_file = (char*)malloc(sizeof(char) * (strlen(pvalue)+ 1));
		strcpy(f->listener_private_key_file, pvalue);
	}
	pvalue[0] = (char)0;
	strcpy(pname, name);
	strcat(pname, CFG_TLS_CLIENT_CERTFILE);
	getProperty(buffer, pvalue, pname);
	if (strlen(pvalue)) {
		f->client_cert_file = (char*)malloc(sizeof(char) * (strlen(pvalue)+ 1));
		strcpy(f->client_cert_file, pvalue);
	}
	pvalue[0] = (char)0;
	strcpy(pname, name);
	strcat(pname, CFG_TLS_CLIENT_KEYFILE);
	getProperty(buffer, pvalue, pname);
	if (strlen(pvalue)) {
		f->client_private_key_file = (char*)malloc(sizeof(char) * (strlen(pvalue)+ 1));
		strcpy(f->client_private_key_file, pvalue);
	}
	pvalue[0] = (char)0;
	strcpy(pname, name);
	strcat(pname, CFG_TLS_LISTENER_PWFILE);
	getProperty(buffer, pvalue, pname);
	if (strlen(pvalue)) {
		f->listener_pwfile = (char*)malloc(sizeof(char) * (strlen(pvalue)+ 1));
		strcpy(f->listener_pwfile, pvalue);
	}
	pvalue[0] = (char)0;
	strcpy(pname, name);
	strcat(pname, CFG_TLS_CLIENT_PWFILE);
	getProperty(buffer, pvalue, pname);
	if (strlen(pvalue)) {
		f->client_pwfile = (char*)malloc(sizeof(char) * (strlen(pvalue)+ 1));
		strcpy(f->client_pwfile, pvalue);
	}
		
	pvalue[0] = (char)0;
	strcpy(pname, name);
	strcat(pname, CFG_SEND_TIMEOUT);
	getProperty(buffer, pvalue, pname);
	errno = 0;
	f->send_timeout = strtol(pvalue, (char**)0, 0);
	if (errno) {
		return 0;
	}
	pvalue[0] = (char)0;
	strcpy(pname, name);
	strcat(pname, CFG_BUFFERSIZE);
	getProperty(buffer, pvalue, pname);
	errno = 0;
	f->session_buffer_size = strtol(pvalue, (char**)0, 0);
	if (errno) {
		return 0;
	}
	pvalue[0] = (char)0;
	strcpy(pname, name);
	strcat(pname, CFG_RECV_TIMEOUT);
	getProperty(buffer, pvalue, pname);
	errno = 0;
	f->recv_timeout = strtol(pvalue, (char**)0, 0);
	if (errno) {
		return 0;
	}
	pvalue[0] = (char)0;
	strcpy(pname, name);
	strcat(pname, CFG_NO_FWD);
	getProperty(buffer, pvalue, pname);
	if (pvalue[0]) {
		f->do_not_forward = 1;
	}
	pvalue[0] = (char)0;
	strcpy(pname, name);
	strcat(pname, CFG_LOG_FILENAMES);
	getProperty(buffer, pvalue, pname);
	if (pvalue[0]) {
		f->log_filenames = 1;
	}
	return 1;	
}

char* getPassword(char* filename) {
	int f = open(filename, O_RDONLY);
	if (f == -1) {
		perror("Reading password file");
		return (char*)0;	
	}
	char b[KEYPASS_SIZE];
	memset(b, 0, KEYPASS_SIZE);
	int rSize = read(f, b, KEYPASS_SIZE);
	if (rSize < 0) {
		close(f);
		return (char*)0;		
	} else {
		if (rSize) {
			char *p = (char*)malloc((rSize + 1) * sizeof(char));
			b[rSize] = (char)0;
			strcpy(p, b);
			memset(b, 0, rSize);
			close(f);
			return p;
		} else {
			close(f);
			return (char*)0;
		}
	} 
}

void loadPasswordFiles(forwarder_config* f) {
	if (f->listener_pwfile) {
		f->listener_pw = getPassword(f->listener_pwfile);
		if (f->listener_pw) f->listener_pw_length = strlen(f->listener_pw);
	}		
	if (f->client_pwfile) {
		f->client_pw = getPassword(f->client_pwfile);
		if (f->client_pw) f->client_pw_length = strlen(f->client_pw);
	}
}

void addForwarderConfig(char* buffer, char *name, proxy_config* p) {
	forwarder_config* f = initForwarderConfig();	
	if (makeForwarderConfig(f, buffer, name)) {
		registerForwarderConfig(f);
		if (f->listen_tls || f->forward_tls) {
			p->tls_init_needed = 1;
			loadPasswordFiles(f);
		}
	} else {
		printf("Forwarder configuration %s failed to initialise", name);
		destroyForwarderConfig(f);
	}	
}

int getNextName(char *buffer, char *name) {
	static char namelist[1024];
	static int nlsize = 0;
	static int finished = 0;
	static char* next;
	char *b;
	
	if (finished) return 0;
	if (!nlsize) {
		getProperty(buffer, namelist, FORWARDER_NAMES);
		next = namelist;
		nlsize = strlen(namelist);
	}
	b = next;
	while(*b && !isspace(*b)) {
		++b;
		if ((b - next) > nlsize) return 0;
	}
	*b = (char)0;
	strcpy(name, next);
	++b;
	while(*b && isspace(*b)) {
		++b;
		if ((b - next) >= nlsize) finished = 1;		
	}
	next = b;
	if (strlen(name) == 0) {
		finished = 1;
		return 0;
	}
	return 1;
}

int loadConfig(int f, proxy_config* p) {
	/*
		Read the configuration file and build the proxy configuration. Read the
		whole file, then process it.
	*/
	int retVal = 0;
	char *buf = (char*)malloc(sizeof(char) * CONFIG_FILE_BUFFER_SIZE);
	int cfgSize = read(f, buf, (size_t)CONFIG_FILE_BUFFER_SIZE);
	close(f);
	retVal = 0;
	if (cfgSize > 0) {
		char name[1024];
		while(getNextName(buf, name)) {
			addForwarderConfig(buf, name, p);
		}
		retVal = 1;
	}
	free(buf);
	return retVal;
}
