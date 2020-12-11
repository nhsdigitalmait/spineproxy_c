#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <uuid/uuid.h>
#include "spineproxy.h"

#define UUID_LENGTH 37
#define ACK_BUFFER_SIZE 3000
#define ACK_HEADER_SIZE 1000
#define TIMESTAMP_LENGTH 22
#define TIMESTAMP_FORMAT "%.4d-%.2d-%.2dT%.2d:%.2d:%.2dZ"
#define RFC1123_DATE_FORMAT "%s, %.2d %s %.4d %2.d:%.2d:%.2d GMT"
#define RFC1123_DATE_LENGTH 31

#define ACK_BODY_1 "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n<soap-env:Envelope xmlns:soap-env=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:eb=\"http://www.oasis-open.org/committees/ebxml-msg/schema/msg-header-2_0.xsd\" xsi:schemaLocation=\"http://schemas.xmlsoap.org/soap/envelope/ http://www.oasis-open.org/committees/ebxml-msg/schema/envelope.xsd\">\r\n<soap-env:Header><eb:MessageHeader soap-env:mustUnderstand=\"1\" eb:version=\"2.0\">\r\n<eb:From><eb:PartyId eb:type=\"urn:nhs:names:partyType:ocs+serviceInstance\">"

#define ACK_BODY_2 "</eb:PartyId></eb:From><eb:To><eb:PartyId eb:type=\"urn:nhs:names:partyType:ocs+serviceInstance\">"

#define ACK_BODY_3 "</eb:PartyId></eb:To>\r\n<eb:CPAId>oasis0001</eb:CPAId>\r\n<eb:ConversationId>"

#define ACK_BODY_4 "</eb:ConversationId>\r\n<eb:Service>urn:oasis:names:tc:ebxml-msg:service</eb:Service>\r\n<eb:Action>Acknowledgment</eb:Action>\r\n<eb:MessageData>\r\n<eb:MessageId>"

#define ACK_BODY_5 "</eb:MessageId>\r\n<eb:Timestamp>"

#define ACK_BODY_6 "</eb:Timestamp>\r\n<eb:RefToMessageId>"

#define ACK_BODY_7 "</eb:RefToMessageId>\r\n</eb:MessageData>\r\n</eb:MessageHeader>\r\n<eb:Acknowledgment  soap-env:mustUnderstand=\"1\" eb:version=\"2.0\"  soap-env:actor=\"urn:oasis:names:tc:ebxml-msg:actor:nextMSH\">\r\n<eb:Timestamp>"

#define ACK_BODY_8 "</eb:Timestamp>\r\n<eb:RefToMessageId>"

#define ACK_BODY_9 "</eb:RefToMessageId>\r\n</eb:Acknowledgment>\r\n</soap-env:Header>\r\n<soap-env:Body/>\r\n</soap-env:Envelope>\r\n"

#define ACK_HEADER_1 "HTTP/1.1 200 OK\r\nDate: "
#define ACK_HEADER_2 "\r\nServer: "
#define ACK_HEADER_3 "\r\nContent-Length: "
#define ACK_HEADER_4 "\r\nConnection: close\r\nContent-Type: text/xml; charset=utf-8\r\nContent-Language: en-GB\r\n\r\n"

#define PING_HEADER "HTTP/1.1 501 Not Implemented\r\n"

static char *days[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
static char *months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};


char* makeAckMessageId() {
	uuid_t u;	
	uuid_generate(u);
	char* c = (char*)malloc(UUID_LENGTH * sizeof(char));
	uuid_unparse(u, c);
	char *i = c;
	while(*i) {
		if ((*i >= 'a') && (*i <= 'f')) {
			*i = (*i -'a') + 'A';
		}
		i++;
	}
	return c;
}

char* makeAckMessageTime() {
	struct tm t;
	time_t timep = time((time_t*)0);
	char *out = (char*)0;
	if (!gmtime_r(&timep, &t)) return out;
	out = (char*)malloc(TIMESTAMP_LENGTH * sizeof(char));
	snprintf(out, TIMESTAMP_LENGTH - 1, TIMESTAMP_FORMAT, t.tm_year + 1900, t.tm_mon + 1, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec);
	out[TIMESTAMP_LENGTH] = (char)0;
	return out;
}

char* makeRFC1123Date() {
	struct tm t;
	time_t timep = time((time_t*)0);
	char *out = (char*)0;
	if (!gmtime_r(&timep, &t)) return out;
	out = (char*)malloc(RFC1123_DATE_LENGTH * sizeof(char));
	snprintf(out, RFC1123_DATE_LENGTH - 1, RFC1123_DATE_FORMAT, days[t.tm_wday], t.tm_mday, months[t.tm_mon], t.tm_year + 1900,  t.tm_hour, t.tm_min, t.tm_sec);
	out[RFC1123_DATE_LENGTH] = (char)0;
	return out;	
}

/*
	TODO: Figure out where is the best place to call this, given that it is only
	used in "donotforward" mode and that it is done after the received message is 
	all processed and saved. This needs to be called, and made available for writing
	back to the sender BEFORE the session gets nuked by markSessionDone()
*/
char* makeAck(session* s) {
	if (!s) return (char*)0;
	if (!strcmp(s->action, "Ping")) {
		/*
			Return an HTTP "not implemented" and exit
		*/
		char *ping = (char*)malloc(strlen(PING_HEADER) * sizeof(char));
		strcpy(ping, PING_HEADER);
		return ping;	
	}
	char l[8];
	char *body = (char*)malloc((ACK_BUFFER_SIZE - ACK_HEADER_SIZE) * sizeof(char));;
	char *header = (char*)malloc(ACK_HEADER_SIZE * sizeof(char));
	char *ack = (char*)malloc(ACK_BUFFER_SIZE * sizeof(char));
	/*
		Make the ack by assembling the parts around the dynamic data. Do the body first
		so that we know how big the ack actually is, for the content-length header.
	*/
	strcpy(body, ACK_BODY_1);
	strcat(body, s->topartyid);
	strcat(body, ACK_BODY_2);
	strcat(body, s->frompartyid);
	strcat(body, ACK_BODY_3);
	strcat(body, s->conversationid);
	strcat(body, ACK_BODY_4);
	char *ackmsgid = makeAckMessageId();
	strcat(body, ackmsgid);
	free(ackmsgid);
	strcat(body, ACK_BODY_5);
	char *ts = makeAckMessageTime();	
	strcat(body, ts);
	strcat(body, ACK_BODY_6);
	strcat(body, s->msgid);
	strcat(body, ACK_BODY_7);
	strcat(body, ts);
	strcat(body, ACK_BODY_8);
	strcat(body, s->msgid);
	strcat(body, ACK_BODY_9);
	
	int length = strlen(body);
	strcpy(header, ACK_HEADER_1);
	free(ts);
	ts = makeRFC1123Date();
	strcat(header, ts);
	strcat(header, ACK_HEADER_2);
	strcat(header, SPINE_PROXY_VERSION);	
	strcat(header, ACK_HEADER_3);
	snprintf(l, 8, "%i", length);
	strcat(header, l);
	strcat(header, ACK_HEADER_4);	
	strcpy(ack, header);
	strcat(ack, body);
	free(ts);
	free(body);
	free(header);
	return ack;
}

