#include "spineproxy.h"
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <openssl/crypto.h>

void proxy_thread_cleanup() {
        int i;

        CRYPTO_set_locking_callback(NULL);
        for (i = 0; i < CRYPTO_num_locks(); i++) {
        	pthread_mutex_destroy(&(proxy->lock_cs[i]));
        }
        OPENSSL_free(proxy->lock_cs);
        OPENSSL_free(proxy->lock_count);
}

unsigned long pthreads_thread_id(void) {
	unsigned long ret;

	ret=(unsigned long)pthread_self();
	return(ret);
}


void pthreads_locking_callback(int mode, int type, char *file, int line) 
{
	if (mode & CRYPTO_LOCK) {
    	pthread_mutex_lock(&(proxy->lock_cs[type]));
        proxy->lock_count[type]++;
    } else {
		pthread_mutex_unlock(&(proxy->lock_cs[type]));
	}
}

void proxy_thread_setup() {
        int i;

        proxy->lock_cs = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
        proxy->lock_count = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(long));
        for (i = 0; i < CRYPTO_num_locks(); i++) {
        	proxy->lock_count[i]=0;
            pthread_mutex_init(&(proxy->lock_cs[i]),NULL);
        }
        CRYPTO_set_id_callback((unsigned long (*)())pthreads_thread_id);
        CRYPTO_set_locking_callback((void (*)())pthreads_locking_callback);

}
void destroyProxy() {
	free(proxy->config_file);
	forwarder_config* f = proxy->forwarders;
	if (f) {
		destroyForwarderConfig(f);
	}
	if (proxy->tls_init_needed) {
		proxy_thread_cleanup();
	}
	free(proxy);
}

proxy_config* makeProxy(char *cfgfile) {
	proxy = (proxy_config*)malloc(sizeof(proxy_config));
	proxy->config_file = (char*)malloc(sizeof(char) * (strlen(cfgfile) + 1));
	strcpy(proxy->config_file, cfgfile);
	proxy->sessions = NULL;
	proxy->forwarders = NULL;
	proxy->running = 1;
	proxy->isDestroyable = 0;
	proxy->tls_init_needed = 0;
	return proxy;
}

void addSession(session* s) {
	session* base = proxy->sessions;
	if (base == (session*)0) {
		proxy->sessions = s;
		s->next = (session*)0;
		return;
	}
	while (base->next != (session*)0) {
		base = base->next;
	}
	base->next = s;
}

void removeSession(session* s) {
	/* proxy_config* z = proxy; */
	session* base = proxy->sessions;
	if (base == (session*)0) {
		return;
	}
	if (base == s) {
		if (base->next) {
			proxy->sessions = base->next;
		} else {
			proxy->sessions = (session*)0;
		}
		return;
	}
	while (base->next) {
		if (base->next == s) {
			base->next = s->next;
			break;
		}
		base = base->next;
	}
}
