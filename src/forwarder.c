#include "spineproxy.h"
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>


int getSessions(fd_set* rd, fd_set* wr) {
	int nfds = 0;
	session* s = proxy->sessions;
	session* deadsession = (session*)0;
	while(s) {	
		if (s->being_destroyed) 
			continue;
		checkTimeout(s);
		if (!s->is_done) {
			if (s->processing_ack && (s->outbound_socket != -1)) {
				FD_SET(s->outbound_socket, rd);
				nfds = max(nfds, s->outbound_socket);
			} else {
				if (!s->buffer_read_ptr ||(s->buffer_read_ptr < s->transmission_length)) {
					if (s->inbound_socket != -1) {
						FD_SET(s->inbound_socket, rd);
						nfds = max(nfds, s->inbound_socket);
					}			
				}
			}
			if (s->inbound_stuff_to_write) {
				if (s->inbound_socket != -1) {
					FD_SET(s->inbound_socket, wr);
					nfds = max(nfds, s->inbound_socket);
				}
			}
			if ((s->outbound_socket != -1) && s->outbound_stuff_to_write) {
				FD_SET(s->outbound_socket, wr);
				nfds = max(nfds, s->outbound_socket);
			}			
		} else {
			deadsession = s;
		}
		s = s->next;
		if (deadsession) {
			removeSession(deadsession);
			destroySession(deadsession);
			if (!proxy->sessions)
				return 0;
			deadsession = (session*)0;
		}		
	}
	return nfds;
}

void doRead(session* s, int direction) {
	int readskt;
	SSL *ssl_session;
	int cread = 0;
	
	switch (direction) {
		case INBOUND:
			readskt = s->inbound_socket;
			ssl_session = s->inbound_ssl;
			if (s->forwarder->doTiming) {
				if (!s->timing_points[INBOUND_READ_START_TIME].tv_sec) {
					timestampEvent(s, INBOUND_READ_START_TIME);
				}
			}
			break;
			
		case OUTBOUND:
			readskt = s->outbound_socket;
			ssl_session = s->outbound_ssl;
			if (s->forwarder->doTiming) {
				if (!s->timing_points[OUTBOUND_READ_START_TIME].tv_sec) {
					timestampEvent(s, OUTBOUND_READ_START_TIME);
				}
			}			
			break;
			
		default:
			return;
	}
	if (s->dead_socket_detected == readskt) {
		snprintf(error_string, ERROR_STRING_LENGTH, "ERROR: Read socket dead");
		errno = EIO;
		perror(error_string);
		return;
	}
	/*
		Do the read into the buffer. If the session is new, try to find out what
		to call the file, and open the logfile (setting logfile as we do so). Then
		write to it and write to the wrtsocket. If we find a conversation id, save
		that for the ebXML ack. If we find a message id, save that, too.
	*/
	if (ssl_session) {
		//cread = SSL_read(ssl_session, s->buffer + s->buffer_read_ptr, s->transmission_length);
		cread = SSL_read(ssl_session, s->buffer + s->buffer_read_ptr, s->buffer_size - s->buffer_read_ptr);
		if (cread < 0) {
			if (ERR_reason_error_string(ERR_get_error())) {
				dumpSession(s);
				snprintf(error_string, ERROR_STRING_LENGTH, "ERROR reading, terminating session: %s", ERR_reason_error_string(ERR_get_error()));
				errno = EIO;
				perror(error_string);
			}
			s->dead_socket_detected = readskt;
			markSessionDone(s, 1);
			return;
		}
	} else {
		//cread = read(readskt, s->buffer + s->buffer_read_ptr, s->transmission_length);
		cread = read(readskt, s->buffer + s->buffer_read_ptr, s->buffer_size - s->buffer_read_ptr);
	}
	setLastOpTime(s);
	if (cread == -1) {
		perror("doRead() - error reading from network");
		s->dead_socket_detected = readskt;
		markSessionDone(s, 1);
		return;
	}
	if (!cread) {
		markSessionDone(s, 1);
	}
	s->buffer_read_ptr += cread;
	if (s->forwarder->doTiming) {
		if (s->buffer_read_ptr == s->transmission_length) {
			if (direction == INBOUND) {
				timestampEvent(s, INBOUND_READ_END_TIME);
			} else {
				timestampEvent(s, OUTBOUND_READ_END_TIME);
			}	
		}
	}
	if (s->transmission_details_received) {
		doSessionForward(s);
	} else {
		doSessionInit(s);
	}
}

void doWrite(session* s, int direction) {
	int wrtskt;
	char * buffer;
	SSL* ssl = (SSL*)0;
	int cwritten = 0;
	int towrt = 0;
	
	switch (direction) {
		case INBOUND:
			wrtskt = s->inbound_socket;
			ssl = s->inbound_ssl;
			if (s->forwarder->doTiming) {
				if (!s->timing_points[INBOUND_WRITE_START_TIME].tv_sec) {
					timestampEvent(s, INBOUND_WRITE_START_TIME);
				}
			}			
			break;
			
		case OUTBOUND:
			wrtskt = s->outbound_socket;
			ssl = s->outbound_ssl;
			if (s->forwarder->doTiming) {
				if (!s->timing_points[OUTBOUND_WRITE_START_TIME].tv_sec) {
					timestampEvent(s, OUTBOUND_WRITE_START_TIME);
				}
			}			
			break;
			
		default:
			return;
	}
	if (s->dead_socket_detected == wrtskt) {
		snprintf(error_string, ERROR_STRING_LENGTH, "ERROR: Write socket dead");
		errno = EIO;
		perror(error_string);
		return;
	}
	buffer = s->buffer + s->forwarded_to_network;
	towrt = s->buffer_read_ptr;
	int amount = s->buffer_read_ptr - s->forwarded_to_network;
	if (towrt > 0) {	
		if (ssl) {
			/* int amount = s->transmission_length - s->forwarded_to_network; */
			if (amount) {
				while ((cwritten = SSL_write(ssl, (void*)buffer, amount)) < 0) {
					int err = SSL_get_error(ssl, cwritten);
					if ((err == SSL_ERROR_WANT_READ) || (err == SSL_ERROR_WANT_WRITE)) {
						continue;
					} else {
						perror("TLS write");
						snprintf(error_string, ERROR_STRING_LENGTH, "ERROR writing: Terminating session: %s\n", ERR_reason_error_string(ERR_get_error()));
						errno = EIO;
						perror(error_string);
						s->dead_socket_detected = wrtskt;
						markSessionDone(s, 1);
						return;		
					}
				}
			}
		} else {
			cwritten = write(wrtskt, buffer, amount);
		}
		if (cwritten > -1) {
			s->forwarded_to_network += cwritten;
		} else {
			s->dead_socket_detected = wrtskt;
			perror("doWrite(), forwarding");
			markSessionDone(s, 1);
		}
	}
	if (s->forwarded_to_network == s->transmission_length) {
		if (s->forwarder->doTiming) {
			if (direction == INBOUND) {
				timestampEvent(s, INBOUND_WRITE_END_TIME);
			} else {
				timestampEvent(s, OUTBOUND_WRITE_END_TIME);
			}
		}
		if (s->sending) {
			setSessionForAck(s);
		}
	}
}

void doChecks(fd_set* rd, fd_set* wr, fd_set* er) {
	session* s = proxy->sessions;
	if (s == (session*)0) 
		return;
	do {
		if (FD_ISSET(s->inbound_socket, er)) {
			snprintf(error_string, ERROR_STRING_LENGTH, "%s", "OOB data on inbound socket");
			perror(error_string);
		}
		if ((s->outbound_socket != -1) && FD_ISSET(s->outbound_socket, er)) {
			snprintf(error_string, ERROR_STRING_LENGTH, "%s", "OOB data on outbound socket");
			perror(error_string);
		}
		if (FD_ISSET(s->inbound_socket, wr)) {
			doWrite(s, INBOUND);
		}
		if ((s->outbound_socket != -1) && FD_ISSET(s->outbound_socket, wr)) {
			doWrite(s, OUTBOUND);
		}
		if (FD_ISSET(s->inbound_socket, rd)) {
			doRead(s, INBOUND);
		}
		if ((s->outbound_socket != -1) && FD_ISSET(s->outbound_socket, rd)) {
			doRead(s, OUTBOUND);
		}
	} while ((s = s->next) != (session*)0);
}

/*
	Run in its own thread when the proxy is started. The argument is currently unused.
*/

void* forwarder(void* a) {
/*	proxy_config* p = proxy; */
	if (!proxy) {
		snprintf(error_string, ERROR_STRING_LENGTH, "%s","forwarder() - no proxy\n");
		errno = EINVAL;
		perror(error_string);
		pthread_exit(NULL);
	}
	fd_set rd, wr, er;
	int nfds;
	int r, e;
	struct timeval tv;
	while(proxy->running) {
		FD_ZERO(&rd);
		FD_ZERO(&wr);
		FD_ZERO(&er);
		nfds = getSessions(&rd, &wr);	
		tv.tv_sec = FORWARDER_SELECT_TIMEOUT;
		tv.tv_usec = 0;
		if (nfds) {
			r = select(nfds + 1, &rd, &wr, &er, &tv);
			if (r > 0) {
				doChecks(&rd, &wr, &er);
			} else {
				if (r < 0) {
					e = errno;
					if (e == EINTR) {
						continue;
					} else {
						if (e != EBADF)
							perror("forwarder()");
					}
				}
			}
		} else {
			sleep(1);
		}
	}
	session* s = proxy->sessions;
	while (s) {
		markSessionDone(s, 0);
		s = s->next;
	}
	proxy->isDestroyable = 1;
	pthread_exit(NULL);
}




