#include "spineproxy.h"
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netdb.h>

#ifndef _EXCLUDE_VALUES_H_
#include <values.h>
#endif

#define ACTION "soapaction: "
#define CONTENTLENGTH "content-length: "
#define HOST "Host: "
/*
	Changed 20070209 DJM, to :messageid to avoid problems when the
	message id element contains a namespace declaration
#define MSGID "messageid>"
*/
#define MSGID ":messageid"
#define CONVERSATIONID "sationid>"
#define ADDRESSTYPE "Instance"
#define FROMPARTY ":From"
#define TOPARTY  ":To"

#define FROM 1
#define TO 0

#define HLBUF 1024
#define HLINCREMENT 32

#define TIMINGREPORTBUFFERSIZE 2056

static char *timing_point_names[] = {"Connection received","To proxy TLS start","To proxy TLS complete",\
					"To proxy read start","To proxy read end","To sender write start",\
					"To sender write end","To proxy TLS close start","To proxy TLS close complete",\
					"From proxy connection start","From proxy connection complete",\
					"From proxy TLS start","From proxy TLS complete","From proxy read start",\
					"From proxy read end","From receiver write start","From receiver write end",\
					"From receiver TLS close start","From receiver TLS close end"};

static struct timezone tz;

#ifdef _NEED_OWN_STRCASESTR_
/*
	Need this here because glibc provides strcasestr() but the Cygwin
	"newlib" library does not.
*/
char* strcasestr(const char* haystack, const char* needle) {
	char *c, *s;
	int len = strlen(needle);
	int hlen = strlen(haystack);
	if (!len || !hlen) return (char*)0;
	if (len > hlen) return (char*)0;
	s = (char*)haystack;
	c = s + len;
	do {
		if ((*s == (char)0) || (*(++c) == (char)0)) return (char*)0;
	} while(strncasecmp(s++, needle, len));
	return --s;
}
#endif

void reportTimingPoints(session *s) {
	if (s == (session*)0)
		return;		
	if (s->log_file == -1) {
		return;
	}
	char buffer[TIMINGREPORTBUFFERSIZE];
	int i;
	write(s->log_file, "\n\n\n\n", 4*sizeof(char));
	for (i = 0; i < TIMING_POINTS; i++) {
		if (s->timing_points[i].tv_sec) {
			snprintf(buffer, TIMINGREPORTBUFFERSIZE, "TIME %s: %i.%.6i\n", timing_point_names[i], s->timing_points[i].tv_sec, s->timing_points[i].tv_usec);
			if (write(s->log_file, buffer, strlen(buffer)) == -1) {
				perror("Writing timings");
			}
		}
	}
}

void timestampEvent(session* s, int when) {
	if (s == (session*)0)
		return;		
	if ((when < 0) || (when > TIMING_POINTS)) {
		return;
	}
	if (gettimeofday(&(s->timing_points[when]), &tz) == -1) {
		perror("Error reporting timing point");
	}
}


void markSessionDone(session* s, int eof) {
	if (s == (session*)0)
		return;		
	if (s->is_done)
		return;
	if (s->forwarder->doTiming) {
		timestampEvent(s, INBOUND_TLS_CLOSE_START);
	}
	if (!eof) {
		if (s->inbound_ssl) {
			if (s->dead_socket_detected != s->inbound_socket) {	
				SSL_shutdown(s->inbound_ssl);
			}
		}
		if (s->forwarder->doTiming) {
			timestampEvent(s, INBOUND_TLS_CLOSE_END);
			timestampEvent(s, OUTBOUND_TLS_CLOSE_START);
		}	
		if (s->outbound_ssl) {
			if (s->dead_socket_detected != s->outbound_socket) {	
				SSL_shutdown(s->outbound_ssl);
			}
		}
		if (s->forwarder->doTiming) {
			timestampEvent(s, OUTBOUND_TLS_CLOSE_END);
		}
	}
	struct linger lngr;
	lngr.l_onoff = 0;
	lngr.l_linger = 0;
	setsockopt(s->inbound_socket, SOL_SOCKET, SO_LINGER, (void*)&lngr, (socklen_t)sizeof(lngr));
	if (s->inbound_socket != -1) {
		if (close(s->inbound_socket)) {
			if (errno != EBADF)
				perror("Inbound socket close");
		}
	}
	if (s->outbound_socket != -1) {
		setsockopt(s->outbound_socket, SOL_SOCKET, SO_LINGER, (void*)&lngr, (socklen_t)sizeof(lngr));
		if (close(s->outbound_socket)) {
			if (errno != EBADF)
				perror("Outbound socket close");
		}
	}
	reportTimingPoints(s);
	if (close(s->log_file)) {
		perror("Logfile close");
	}
	s->log_file = -1;
	s->is_done = 1;
}



session* registerSession(char* client, int skt, forwarder_config *f) {
	int i;
	/*
		Create a session structure, put it into the session list in the proxy,
		and return a pointer to it.
	*/
	session* s = (session*)0;
	s = (session*)malloc(sizeof(session));
	s->being_destroyed = 0;
	s->timing_points = (struct timeval*)malloc(TIMING_POINTS * sizeof(struct timeval));
	for (i = 0; i < TIMING_POINTS; i++) {
		s->timing_points[i].tv_sec = 0;
		s->timing_points[i].tv_usec = 0;
	}
	if (f->doTiming) {
		timestampEvent(s, INBOUND_CONNECTION_RECEIVED_TIME);	
	}
	s->inbound_socket = skt;
	s->outbound_socket = -1;
	s->forwarder = f;
	if (f->listen_tls) {
		if (!(s->inbound_ssl = SSL_new(f->listener_context))) {
			snprintf(error_string, ERROR_STRING_LENGTH, "ERROR creating TLS session: %s",ERR_reason_error_string(ERR_get_error()));
			errno = ECANCELED;
			perror(error_string);
			free(s);
			return (session*)0;
		}
		if (!SSL_set_fd(s->inbound_ssl, skt)) {
			snprintf(error_string, ERROR_STRING_LENGTH, "ERROR binding TLS connection session: %s",ERR_reason_error_string(ERR_get_error()));
			errno = ECANCELED;
			perror(error_string);
			free(s);
			return (session*)0;
		}
		int ret;
		if (f->doTiming) {
			timestampEvent(s, INBOUND_TLS_START_TIME);
		}
		ret = SSL_accept(s->inbound_ssl);
		if (f->doTiming) {
			timestampEvent(s, INBOUND_TLS_COMPLETE_TIME);
		}
		if (ret < 1) {
			snprintf(error_string, ERROR_STRING_LENGTH, "ERROR accepting, terminating session: %s",ERR_reason_error_string(ERR_get_error()));
			errno = ECANCELED;
			perror(error_string);
			free(s);
			return (session*)0;
		}
	} else {
		s->inbound_ssl = (SSL*)0;
	}
	s->outbound_ssl = (SSL*)0;
	s->from = client;
	s->to = (char*)0;
	s->next = (session*)0;
	s->port = 0;
	s->transmission_details_received = 0;
	s->is_done = 0;
	s->inbound_stuff_to_write = 0;
	s->outbound_stuff_to_write = 0;
	s->written_to_file = 0;
	s->forwarded_to_network = 0;
	s->buffer_read_ptr = 0;
	s->log_file = -1;
	s->content_length = -1;
	s->transmission_length = INT_MAX;
	s->sending = 0;
	s->processing_ack = 0;
	s->sending_ack = 0;
	s->start_time = time((time_t*)0);
	s->dead_socket_detected = 0;
	s->msgid = (char*)0;
	s->action = (char*)0;
	s->conversationid = (char*)0;
	s->topartyid = (char*)0;
	s->frompartyid = (char*)0;
	s->buffer = (char*)malloc(f->session_buffer_size * sizeof(char));
	memset(s->buffer, 0, f->session_buffer_size);
	setLastOpTime(s);
	addSession(s);
	return s;
	
} 

struct sockaddr_in* gethostname(char* host, struct sockaddr_in* socketaddress) {
	char* c;
	int p;
	int result, herror;
	size_t buflen;
	struct hostent hent, *hp;
	buflen = HLBUF;
	
	if ((c = strchr(host, ':'))) {
		p = atol(c + 1);	
		socketaddress->sin_port = htons(p);
		*c = (char)0;
	} else {
		socketaddress->sin_port = 0;
	}
#ifndef _NO_REENTRANT_GETHOSTBYNAME_
	char* tmpbuf = (char*)malloc(buflen);
	while ((result = gethostbyname_r(host, &hent, tmpbuf, buflen, &hp, &herror)) == ERANGE) {
		buflen += HLINCREMENT;
		tmpbuf = (char*)realloc(tmpbuf, buflen);
	}
	if (result || hp == NULL) {
		free(tmpbuf);
		return NULL;
	}
	socketaddress->sin_addr = *(struct in_addr *)hent.h_addr;	
	free(tmpbuf);
#else
	hp = gethostbyname(host);
	socketaddress->sin_addr = *(struct in_addr *)(hp->h_addr);
#endif
	return socketaddress;
}


void doClearForwardConnection(session* s, char* h, int useTLSport) {
	struct sockaddr_in socketaddress;
	int e;
	socketaddress.sin_family = AF_INET;
	if (!gethostname(h, &socketaddress)) {
		e = errno;
		snprintf(error_string, ERROR_STRING_LENGTH, "Failed to get forward address: %s", h);
		errno = e;
		perror(error_string);
		return;
	}
	if (!socketaddress.sin_port) {
		if (useTLSport) {
			socketaddress.sin_port = htons(DEFAULT_TLS_PORT);
		} else {
			socketaddress.sin_port = htons(DEFAULT_CLEAR_PORT);
		}
	}
	int sock = socket (PF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("Failed to create forwarding socket");
		return;
	}
	if (s->forwarder->doTiming) {
		timestampEvent(s, OUTBOUND_CONNECTION_START_TIME);
	}
	if (connect(sock, (struct sockaddr*)&socketaddress, sizeof(socketaddress))) {
		perror("Failed to connect forwarding socket");
		return;
	}
	if (s->forwarder->doTiming) {
		timestampEvent(s, OUTBOUND_CONNECTION_COMPLETE_TIME);
	}
	s->outbound_socket = sock;
}

void doTLSforwardConnection(session* s, char* h) {
	if (!s->forwarder->forward_context) {
		if (!(s->forwarder->forward_context = SSL_CTX_new(TLSv1_client_method()))) {
			snprintf(error_string, ERROR_STRING_LENGTH, "ERROR creating outbound TLS context: %s\n", ERR_reason_error_string(ERR_get_error()));
			errno = ECANCELED;
			perror(error_string);
			markSessionDone(s, 1);
			return;
		}
		if (s->forwarder->verify_client) {
			SSL_CTX_set_verify(s->forwarder->forward_context, SSL_VERIFY_PEER, NULL);
		}
		if (SSL_CTX_use_certificate_chain_file(s->forwarder->forward_context, s->forwarder->client_cert_file) != 1) {
			snprintf(error_string, ERROR_STRING_LENGTH, "ERROR reading outbound TLS certificate file: %s\n", ERR_reason_error_string(ERR_get_error()));
			errno = ECANCELED;
			perror(error_string);
			markSessionDone(s, 1);
			return;			
		}
		if (!SSL_CTX_load_verify_locations(s->forwarder->forward_context, s->forwarder->client_ca_cert_file, s->forwarder->client_ca_cert_dir)) {
			snprintf(error_string, ERROR_STRING_LENGTH, "ERROR reading outbound TLS CA file: %s\n", ERR_reason_error_string(ERR_get_error()));
			errno = ECANCELED;
			perror(error_string);
			markSessionDone(s, 1);
			return;			
		}
		if (s->forwarder->client_pwfile) {
			SSL_CTX_set_default_passwd_cb(s->forwarder->forward_context, getForwarderPassword);
			SSL_CTX_set_default_passwd_cb_userdata(s->forwarder->forward_context, (void*)s->forwarder);
		}
		if (SSL_CTX_use_PrivateKey_file(s->forwarder->forward_context, s->forwarder->client_private_key_file, SSL_FILETYPE_PEM) != 1) {
			snprintf(error_string, ERROR_STRING_LENGTH, "ERROR reading outbound TLS key file: %s\n", ERR_reason_error_string(ERR_get_error()));
			errno = ECANCELED;
			perror(error_string);
			markSessionDone(s, 1);
			return;
		}
	}
	if (!(s->outbound_ssl = SSL_new(s->forwarder->forward_context))) {
		snprintf(error_string, ERROR_STRING_LENGTH, "ERROR creating outbound TLS session: %s\n", ERR_reason_error_string(ERR_get_error()));
		errno = ECANCELED;
		perror(error_string);
		markSessionDone(s, 1);
		return;
	}
	doClearForwardConnection(s, h, 1);
	if (!SSL_set_fd(s->outbound_ssl, s->outbound_socket)) {
		snprintf(error_string, ERROR_STRING_LENGTH, "ERROR binding outbound TLS to socket: %s\n", ERR_reason_error_string(ERR_get_error()));
		errno = ECANCELED;
		perror(error_string);
		markSessionDone(s, 1);
		return;
	}
	if (s->forwarder->doTiming) {
		timestampEvent(s, OUTBOUND_TLS_START_TIME);
	}
	if (!SSL_connect(s->outbound_ssl)) {
		snprintf(error_string, ERROR_STRING_LENGTH, "ERROR connecting outbound TLS socket: %s\n", ERR_reason_error_string(ERR_get_error()));
		errno = ECANCELED;
		perror(error_string);
		markSessionDone(s, 1);
		return;
	}
	if (s->forwarder->doTiming) {
		timestampEvent(s, OUTBOUND_TLS_COMPLETE_TIME);
	}

} 


void setForwardSocket(session* s) {

/*
	Forwarders TO spine should have no forward_to defined and should read the message
	to find out where to send it. Forwarders FROM spine won't know where to return the message
	but can use the forward_to directive to find out.
*/

	char* forwardhost = (char*)0;
	if (s->outbound_socket != -1) {
		return;
	} 
	if (s->forwarder->forward_to) {
		/*
			This is for messages FROM spine, which are forwarded to the address given in the
			configuration file for the forwarder instance.
		*/
		forwardhost = (char*)malloc((strlen(s->forwarder->forward_to) + 1) * sizeof(char));
		strcpy(forwardhost, s->forwarder->forward_to);
	} else {
		/*
			This is for messages TO spine, which are forwarded to the address given in the
			Host header of the inbound HTTP.
		*/
		if (s->forwarder->do_not_forward)
			return;
		forwardhost = (char*)malloc((strlen(s->to) + 1) * sizeof(char));
		strcpy(forwardhost, s->to);
	}
	if (!strlen(forwardhost)) {
		errno = EADDRNOTAVAIL;
		perror("No forward host");
		markSessionDone(s, 0);
		return;
	}
	if (s->forwarder->forward_tls) {
		doTLSforwardConnection(s, forwardhost);
	} else {
		doClearForwardConnection(s, forwardhost, 0);	
	}
	free(forwardhost);
}


void checkTimeout(session* s) {
	if (!s) return;
	if (s->being_destroyed) return;
	if (s->is_done) return;
	long now = (long)time((time_t*)0);
	if ((now - s->last_op_time) > SESSION_TIMEOUT) {
		char estr[1024];
		strcpy(estr, "Timing out ");
		if (s->forwarder && s->forwarder->name) {
			strcat(estr, s->forwarder->name);
		} else {
			strcat(estr, "Unnamed ");
		}
		strcat(estr, " session from ");
		if (s->from) {
			strcat(estr, s->from);
		} else {
			strcat(estr, "UNKNOWN ");
		}
		strcat(estr, " to ");
		if (s->to) {
			strcat(estr, s->to);
		} else {
			strcat(estr, "PROXY");
		}
		if (s->msgid) {
			strcat(estr, " MsgId: ");
			strcat(estr, s->msgid);
		} else {
			strcat(estr, " MsgId: UNKNOWN");
		}		
		errno = ETIMEDOUT;		
		perror(estr);
		markSessionDone(s, 1);
	}
}

void destroySession(session* s) {
	if (!s) return;
	if (!s->msgid) return; 
	if (s->being_destroyed) return;
	s->being_destroyed = 1;
	if (s->inbound_ssl) {
		SSL_free(s->inbound_ssl);
		s->inbound_ssl = (SSL*)0;	
	}
	if (s->outbound_ssl) {
		SSL_free(s->outbound_ssl);
		s->outbound_ssl = (SSL*)0;		
	}
	if (s->from) {
		free(s->from); 
		s->from = (char*)0;
	}
	if (s->to) {
		free(s->to);
		s->to = (char*)0;
	}
	if (s->buffer) {	
		free(s->buffer);
		s->buffer = (char*)0;
	}
	if (s->action) {
		free(s->action);
		s->action = (char*)0;
	}
	if (s->msgid) {
		free(s->msgid);
		s->msgid = (char*)0;
	}
	if (s->conversationid) {
		free(s->conversationid);
		s->conversationid = (char*)0;
	}
	if (s->topartyid) {
		free(s->topartyid);
		s->topartyid = (char*)0;
	}
	if (s->frompartyid) {
		free(s->frompartyid);
		s->frompartyid = (char*)0;
	}
	if (s->timing_points) {
		free(s->timing_points);
		s->timing_points = (struct timeval*)0;
	}
	free(s);
}


int transmissionDetailsReceived(session* s) {
	if (s == (session*)0) {
		return 0;
	}
	if (s->content_length == -1) return 0;
	if (s->action == (char*)0) return 0;
	if (s->msgid == (char*)0) return 0;
	if (s->to == (char*)0) return 0;
	return 1;
}

void setMessageType(session* s) {
	if (strstr(WEBSERVICES, s->action)) {
		s->msg_type = SOAP;
	} else {
		s->msg_type = EBXML;
	}
}

char* getPartyId(session* s, const char* id) {
	/*
		Doing this as a string operation is a bit involved. First we find the identifying
		tag. However due to whitespace, there is a variable number of characters between
		this and what we're actually looking for. So then look for the ADDRESSTYPE string,
		and then a "greater-than". Everything between that and the next "less than", non-
		inclusive, is the party id that we're after.
	*/
	char* partyid;
	char* found = (char*)strcasestr(s->buffer, id);	
	if (found == (char*)0) return (char*)0;
	found = (char*)strcasestr(found, ADDRESSTYPE);
	if (found == (char*)0) return (char*)0;
	while(*found != '>') {
		if (!*found) return (char*)0;
		found++;
	}
	found++;
	char* lost = found;
	while (*lost != '<') {
		if (!*lost) return (char*)0;
		lost++;
	}
	int sz = lost - found;
	partyid = (char*)malloc((sz + 1) * sizeof(char));
	memcpy(partyid, found, sz * sizeof(char));
	partyid[sz] = (char)0;		
	return partyid;
}

void getAddress(session* s, int t) {
	char* id;
	
	switch (t) {
		case FROM:
			if (s->frompartyid) return;
			id = FROMPARTY;
			s->frompartyid = getPartyId(s, id);
			break;
		case TO:
			if (s->topartyid) return;
			id = TOPARTY;
			s->topartyid = getPartyId(s, id);
			break;
		default:
			return;
	}	
}

void getAction(session* s) {
	if (s->action) return;
	char* found = (char*)strcasestr(s->buffer, ACTION);	
	if (found == (char*)0) return;
	/*
		We should have found the soapaction here, so find the start of the
		actual interaction id (after the /) and read until not A-Z0-9. The bit
		between the / and the EOL is the interation id.
		
		Also set the message type.
	*/
	found = strchr(found, '/');
	if (found == (char*)0) return;
	found++;
	char* lost = found;
	while (isalnum((int)*lost) || *lost == '_') {
		if (!*lost) return; 
		++lost;
	}
	int sz = lost - found;
	s->action = (char*)malloc((sz + 1) * sizeof(char));
	memcpy(s->action, found, sz * sizeof(char));
	s->action[sz] = (char)0;
	setMessageType(s);
}

void getHost(session* s) {
	char* found = (char*)strcasestr(s->buffer, HOST);	
	if (found == (char*)0) return;
	found += strlen(HOST);
	char* lost = found + 1;
	while(isalnum((int)*lost) || (*lost == '.') || (*lost == '-') || (*lost == ':')) {
		if (!*lost) return;
		++lost;
	}
	int sz = (lost - found);
	s->to = (char*)malloc((sz + 1) * sizeof(char));
	memcpy(s->to, found, sz * sizeof(char));
	s->to[sz] = (char)0;
}

void getContentLength(session* s) {
	char* found = (char*)strcasestr(s->buffer, CONTENTLENGTH);	
	if (found == (char*)0) return;
	found += strlen(CONTENTLENGTH);
	/*
		Scan forward from found until we reach something that is a number, and 
		then collate that until we get to something that is not a number.
	*/
	while (!isdigit((int)*found)) ++found;
	char* lost = found;
	while (isdigit((int)*lost)) lost++;
	int l = 0;
	int f = 1;
	do {
		--lost;
		l += ((int)(lost[0] - '0') * f);
		f *= 10;
	} while (lost != found);
	s->content_length = l;
}

void getMessageId(session* s) {
	if (s->msgid) return;
	char* found = (char*)strcasestr(s->buffer, MSGID);	
	if (found == (char*)0) return;
	found = (char*)strcasestr(found, ">");
	if (found == (char*)0) return;
	found++;
	char* lost = found;
	while (*lost != '<') {
		if (!*lost) return;
		lost++;
	}
	int sz = lost - found;
	s->msgid = (char*)malloc((sz + 1) * sizeof(char));
	memcpy(s->msgid, found, sz * sizeof(char));
	s->msgid[sz] = (char)0;	
}

void getConversationId(session* s) {
	if (s->conversationid) return;
	char* found = (char*)strcasestr(s->buffer, CONVERSATIONID);	
	if (found == (char*)0) return;
	found += strlen(CONVERSATIONID);
	/*
		In this case we're extracting the message id from XML, and the id starts
		straight away. It finishes when we reach "<"
	*/
	char* lost = found;
	while (*lost != '<') {
		if (!*lost) return;
		lost++;
	}
	int sz = lost - found;
	s->conversationid = (char*)malloc((sz + 1) * sizeof(char));
	memcpy(s->conversationid, found, sz * sizeof(char));
	s->conversationid[sz] = (char)0;	
}

void createLogfile(session* s) {
	char filename[512];
	char ftime[32];

	filename[0] = (char)0;
	strcat(filename, s->forwarder->logdir);
	time_t t = time((time_t*)0);
	snprintf(ftime, 32, "%li", (long)t);
	strcat(filename, s->action);
	strcat(filename, "_");	
	strcat(filename, ftime);
	strcat(filename, "_");
	strcat(filename, s->msgid);
	if (s->msg_type == EBXML) {
		strcat(filename, "_ebxml");
	} else {
		strcat(filename, "_ws");
	}
	strcat(filename, ".log");	
	/*
		Make the log file - need to see which way we're going to get the
		directory right. Also, ONLY ONE FILE.
	*/
	if (isVerbose) {
		printf("Making log file: %s\n", filename);
	}
	s->log_file = open(filename, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
	if (s->log_file == -1) {
		s->is_done = 1;
		perror("createLogFile()");
	}
}

void setLastOpTime(session* s) {
	s->last_op_time = time((time_t*)0);
	/*
		Have we read all we expect to read ?
	*/
	if (!s->sending) {
		if ((s->transmission_length) <= s->buffer_read_ptr) {
			s->sending = 1;
		}
	}
}

void setSessionForAck(session* s) {
	/*
		By this time, all of the data received from the originator has been forwarded,
		and we're now expecting to get some sort of acknowledgement.
		
		1. Clear down the buffer
		2. Clear the recorded sizes
				
		If we were already receiving the ack, then this marks the point at which the
		session has done its job. We also clear s->outbound_stuff_to_write because
		there won't be another opportunity to do so, and if it isn't cleared it will
		mess up select() next time around.
	*/
	if (s->processing_ack) {
		markSessionDone(s, 0);
	} else {
		s->transmission_length = 0;
		s->content_length = -1;
		s->transmission_details_received = 0;
		s->processing_ack = 1;
		s->sending = 0;
		s->buffer_read_ptr = 0;
		s->forwarded_to_network = 0;
		s->written_to_file = 0;
		s->outbound_stuff_to_write = 0;
		if (s->msgid) {
			free(s->msgid);
			s->msgid = (char*)0;
		}
		memset(s->buffer, 0, BUFFER_SIZE);
	}
}

void dumpSession(session* s) {
	// This is called when there has been a read error. We don't bother whether or not
	// we have all the transmission management data (there may not be any if what has
	// happened is that we got an HTTP response and the other end closed the connection)
	// so just write s->buffer_read_ptr bytes to the log file.
	if (!s) return;
	if (s->being_destroyed) return;
	if (s->is_done) return;	
	if (!s->buffer_read_ptr) {
		return;
	}	
	if (s->log_file == -1) {
		// This should only happen if we've not made the logfile yet, in which case
		// we don't really care about what was received.
		errno = ENOENT;
		perror("Emergency session dump not writing to logfile");
	} else {
		int w = write(s->log_file, s->buffer, (s->buffer_read_ptr - s->written_to_file));
		if (w < 0) {
			perror("Emergency session dump failed to write to logfile");
		}
	}
}

void doSessionForward(session* s) {
	if (s == (session*)0)
		return;
	/*
		The buffer should be big enough to take the complete message for this
		version. So this is a check to see if there is anything to write, it
		doesn't actually do the network writing, that is done by the doWrite() in
		forwarder.c which will also update the buffer write counters. However
		it *does* do the logfile writing.
	*/
	if (s->processing_ack) {
		s->inbound_stuff_to_write = (s->forwarded_to_network < s->buffer_read_ptr) ? 1 : 0;
		s->outbound_stuff_to_write = 0;
	} else {
		s->outbound_stuff_to_write = (s->forwarded_to_network < s->buffer_read_ptr) ? 1 : 0;
		s->inbound_stuff_to_write = 0;
	}
	if (s->written_to_file < s->buffer_read_ptr) {
		if (s->log_file == -1) {
			perror("Log file creation failed, not writing to log");		
		} else {
			int w = write(s->log_file, (s->buffer + s->written_to_file), (s->buffer_read_ptr - s->written_to_file));	
			if (w  < 0) {
				perror("doSessionForward(), writing to log file");
			} else {
				s->written_to_file += w;
				/*
					If this forwarder is set "donotforward" (i.e. log only),
					then we need to determine here if we've read and logged everything 
					and can mark the session done. Otherwise the session will never be
					removed.
				*/
				if (s->forwarder->do_not_forward) {
					/*
						If the proxy is supposed to send an acknowledgement, then it needs to
						get that acknowledgement and put it in the buffer, and set everything
						up to return it as if it were an ack from a forward system. Otherwise,
						just mark the session done if we've written everything we need to.
					*/
					if (s->written_to_file == s->transmission_length) {
						if (s->forwarder->send_ack) {
							char *a = makeAck(s);
							strcpy(s->buffer, a);
							free(a);
							s->transmission_length = strlen(s->buffer);
							s->buffer_read_ptr = s->transmission_length;
							s->forwarded_to_network = 0;
							s->inbound_stuff_to_write = 1;
							s->sending = 1;
							s->processing_ack = 1;
							w = write(s->log_file, "\n\n\n\n", 4);
							w = write(s->log_file, s->buffer, s->transmission_length);
							if (w < 0) {
								perror("doSessionForward(), writing ack to log file");
							}
						} else {								
							markSessionDone(s, 0);
						}
					}
				}
			}
		}
	}	
	setLastOpTime(s);
}


void getTransmissionLength(session* s) {
	int sz = 4;
	char* found = strstr(s->buffer, "\r\n\r\n");
	if (!found) {
		/*
			HACK: openssl s_client converts \r\n into \n\n (which is idiotic, but it seems that that
			is what it is doing), which causes \r\n terminated first lines to be misinterpreted as header/body
			breaks which in turn causes the read process to truncate. So... Check for \n\n\n\n BEFORE
			looking for \n\n. Yes. It is bloody horrible.
		*/
		found = strstr(s->buffer, "\n\n\n\n");
		if (!found) {
			/*
				Not delimited correctly, but check in case there are newlines...
			*/
			sz = 2;
			found = strstr(s->buffer, "\n\n");
			if (!found) {
				snprintf(error_string, ERROR_STRING_LENGTH, "getHeaderLength() - header/body delimiter not found");
				errno = EBADMSG;
				perror(error_string);
				markSessionDone(s, 0);
				return;
			}
		}
	}
	s->transmission_length = (int)(found - s->buffer) + (sz * sizeof(char)) + s->content_length;
	if (s->transmission_length >= s->forwarder->session_buffer_size) {
		errno = EFBIG;
		perror("Offered transmission larger than forwarder buffer");
	}
}

void doSessionInit(session* s) {
	if (s == (session*)0)
		return;

	/*
		There are some things we need to get out of the message before we can forward
		it. These are:
		
		1. SOAPaction
		2. Content-length (preferrably), at least for sending TO spoine
		3. MessageId 
		
		These come either from the HTTP headers or the first few K of the message.
		Once we have them we can start the logging and forwarding process and the
		session is no longer considered "new". 
				
	*/
	if (!s->action) getAction(s);		
	if (s->content_length == -1) getContentLength(s);
	if (!s->msgid) getMessageId(s);
	if (!s->to) getHost(s);
	if (s->forwarder->send_ack) {
		if (!s->conversationid) getConversationId(s);
		getAddress(s, FROM);
		getAddress(s, TO);
	}
	setLastOpTime(s);
	if (transmissionDetailsReceived(s)) {
		s->transmission_details_received = 1;
		if (!s->processing_ack) createLogfile(s);
		getTransmissionLength(s);
		setForwardSocket(s);
		doSessionForward(s);
	}
}


