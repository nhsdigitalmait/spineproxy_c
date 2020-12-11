bin_PROGRAMS = spineproxy
spineproxy_SOURCES = spineproxy.c proxy.c forwarder.c forwarderconfig.c \
		listener.c session.c configuration.c ack.c

# set the include path found by configure
INCLUDES= $(all_includes)

# the library search path.
spineproxy_LDFLAGS = $(all_libraries) 
noinst_HEADERS = spineproxy.h
spineproxy_LDADD = -luuid -lcrypto -lpthread -lssl
