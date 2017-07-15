//-----------------------------------------------------------------------------
/*
    librispstrem
    see rispstream.h for details.
    Copyright (C) 2015  Clinton Webb

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser Public License for more details.

    You should have received a copy of the GNU Lesser Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.


*/
//-----------------------------------------------------------------------------



#include "rispstream.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <event.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/dns.h>
#include <event2/listener.h>
#include <fcntl.h>
#include <risp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>




// global constants and other things go here.
#define DEFAULT_MAXCONNS	1024
#define DEFAULT_CHUNKSIZE	(1024*512)

// the number of slots to add to our sessions array every time we need to expand it.  Initial array size will be this size.
#define SESSION_SLOT_INCR 4

#define INVALID_HANDLE -1

#define STRUCT_VERIFIER 92749473038


// Each connection is treated as a session.  Which also includes buffer for unprocessed data, 
// and a buffer for pending outgoing data.
// When the session object is created, the read/write and any other events should be constructed.  Then, when we activate them, we dont have to keep re-creating them.
typedef struct {
// 	int handle;
	RISPSTREAM stream;
	
	// The index is used to find this session entry in the array of pointers of all the sessions.  
	// If we are in a service that has thousands of connections opening and closing, it could be 
	// bad performance to iterate through the array looking for a particular session.   So this 
	// index will point to the slot in the array that the pointer to this session exists.   
	// It will only be manipulated when a session is created, when other sessions close, and used 
	// when this session is closed.  
	// NOTE that it will change independantly of this session.
	int index;

	struct bufferevent *bev;
	long long buffwait;
	
	int closing;
	struct event *close_event;
	
	SSL *client_ssl;

	risp_cb_newconn newconn_fn;
	risp_cb_connclosed connclosed_fn;
	
	void *usersession;
	
} session_t;
// session_new() also needs to be updated.




// The stream_t structure is not exposed to the external library interface.  
// We instead use a void pointer to reference the structure.  
// This is to discourage direct manipulation of the structure.
// This structure is initialised by rispstream_init()
typedef struct {
	long long sverify;
	RISP risp;
	
	char flag_internal_event_base;		// (0=not internal; 1=internal)
	struct event_base *main_event_base;
	struct evdns_base *dns_base;

	int use_ssl;
	SSL_CTX *server_ctx;
	SSL_CTX *client_ctx;
	risp_cb_passphrase passphrase_fn;
	
	struct evconnlistener *listener;
	struct event *stream_cleanup_event;
	struct event *break_event;
	
	// The sessions are maintained in an array.  
	// This will be maintained from the stream side of things, rather than the sessions themselves.  
	// When sessions are closed, a timed event will be created, to go through the array and clean-up.
	session_t **sessions;
	int max_sessions;
	int next_session_slot;
	
	risp_cb_idle       idle_callback_fn;
	risp_cb_break      break_callback_fn;
	risp_cb_newconn    newconn_callback_fn;
	risp_cb_connclosed connclosed_callback_fn;
	void *userdata;
} stream_t;




struct timeval auth_timeout = {10,0};		// timeout if new socket hasn't authenticated.




//--------------------------------------------------------------------------------------------------
// ignore SIGPIPE signals; we can use errno == EPIPE if we need that information.   We can actually 
// intercept these as part of the event system, but have not implemented that in order to reduce 
// complexity.
static void ignore_sigpipe(void) {
	struct sigaction sa;
	
	sa.sa_handler = SIG_IGN;
	sa.sa_flags = 0;
	if (sigemptyset(&sa.sa_mask) == -1 || sigaction(SIGPIPE, &sa, 0) == -1) {
		perror("failed to ignore SIGPIPE; sigaction");
		exit(EXIT_FAILURE);
	}
}




// initialise the libarary.
RISPSTREAM rispstream_init(struct event_base *base)
{
	stream_t *stream = calloc(1, sizeof(stream_t));
	assert(stream);

	// This library requires features from librisp v4.02.00 or higher, namely risp_needs().
	if (risp_version() < 0x00040200) {
		// Version v4.02.00 is required.
		fprintf(stderr, "librisp version 4.02.00 or greater is required for librispstream.\n");
		return(NULL);
	}
	
	// This value is used to determine if a correct STREAM pointer is provided as an argument.
	stream->sverify = STRUCT_VERIFIER;

	if (base == NULL) {
		// No libevent was provided, therefore we must initiate our own.
		stream->main_event_base = event_base_new();
		assert(stream->main_event_base);
		
		// this is used to indicate if we created the libevent base internally, or are using an externally managed event base.
		stream->flag_internal_event_base = 1;
	}
	else {
		stream->main_event_base = base;
		stream->flag_internal_event_base = 0;
	}

	// setup the event DNS resolver, so that it can resolve DNS requests without blocking.
// 	assert(stream->main_event_base);
// 	stream->dns_base = evdns_base_new(stream->main_event_base, 1);
// 	assert(stream->dns_base);

	stream->use_ssl = 0;
	stream->server_ctx = NULL;
	stream->client_ctx = NULL;
	stream->passphrase_fn = NULL;
	
	stream->idle_callback_fn = NULL;
	stream->break_callback_fn = NULL;
	stream->newconn_callback_fn = NULL;
	stream->connclosed_callback_fn = NULL;
	stream->listener = NULL;
	
	// The stream_cleanup_event will be set when a socket is closed, and the array that maintains the streams needs to be compressed.
	stream->stream_cleanup_event = NULL;
	
	stream->break_event = NULL;
	
	// allocate enough space in the array for at least several entries.  These should be preset with NULL.
	stream->max_sessions = SESSION_SLOT_INCR;
	stream->sessions = calloc(stream->max_sessions, sizeof(void *));
	stream->next_session_slot = 0;
	assert(stream->sessions[0] == NULL);
		
	stream->risp = NULL;
	stream->userdata = NULL;
	
	// SIGPIPE interrupts will occur if the socket on the other end is closed before we have finished reading the data that was buffered 
	// for it.  This is necessary for instances where a client connects, sends some commands, and then closes the connection before we 
	// have a chance to process the data.
	ignore_sigpipe();

	return((RISPSTREAM) stream);
}



// When the underlying transport is closed (normally from the other side), we need to do some cleanup.
static void session_close(session_t *session) 
{
	assert(session);

	// the session was also closed from this side, so we can remove the close event.
	if (session->close_event) {
		event_del(session->close_event);
		session->close_event = NULL;
	}

	if (session->bev) {
		assert(session->bev);
		bufferevent_free(session->bev);
		session->bev = NULL;
	}

	assert(session->stream);
	stream_t *stream = session->stream;

	// if a callback was specified, then we need to let the initiator know that a session has been closed.
	if (stream->connclosed_callback_fn) {
		(*stream->connclosed_callback_fn)(session, stream->userdata);
	}
	
	// Now that the session itself has been cleaned up, we need to do some work on the 
	// list of sessions that is kept in the main stream object.
	//
	// The way we manage this, is that we have an array of pointers.  When a session closes, 
	// we move all the other entries in the array down.  So empty entries will be at the end.  
	// Note that we dont need to keep the array in order.  So we just have to take the last 
	// entry at the end of the array and move it to this newly empty spot.
	
	// since we are closing a session, we can be sure that the 'next' session slot should definately 
	// be greater than zero.  There should be definately at least one session in the array.
	assert(stream->next_session_slot > 0);
	int slot = stream->next_session_slot - 1;
	assert(slot >= 0);
	
	if (stream->sessions[slot] == session) {
		// the last slot is actually this session.
		stream->sessions[slot] = NULL;
	}
	else {
		// the last entry in the list is NOT the current session we are closing, so we will move that entry to the current session location.
		
		// check that the current session index, actually points to slot that has the pointer to it.
		assert(session->index >= 0);
		assert(stream->sessions[session->index] == session);
		
		stream->sessions[session->index] = stream->sessions[slot];
		stream->sessions[session->index]->index = session->index;
		stream->sessions[slot] = NULL;		
	}
	stream->next_session_slot = slot;
	assert(stream->next_session_slot >= 0);
	
	// now we are done clearing out everything in the actual session object, we can get rid of the object itself.
	free(session);
}


void rispstream_shutdown(RISPSTREAM streamptr)
{
	assert(streamptr);
	stream_t *stream = streamptr;
	
	
	while (stream->max_sessions > 0) {
		stream->max_sessions --;
		if (stream->sessions[stream->max_sessions]) {
			session_close(stream->sessions[stream->max_sessions]);
		}
	}
	stream->next_session_slot = 0;
	free(stream->sessions);
	stream->sessions = NULL;

	if (stream->flag_internal_event_base == 1) {
		// we initiated the libevent for the user.  So we should clean it up now.
		event_base_free(stream->main_event_base);
		stream->main_event_base = NULL;
	}
	
	free(stream);
}



// if the libevents are not controlled by the calling software, then we initialise and maintain our own.
void rispstream_init_events(RISPSTREAM streamptr)
{
	stream_t *stream = streamptr;
	assert(stream);
	assert(stream->sverify == STRUCT_VERIFIER);
	if (stream->sverify == STRUCT_VERIFIER) {
	
		if (stream->main_event_base == NULL) {
			
			assert(0);
			
		}
	}
}



//--------------------------------------------------------------------------------------------------
// This function is called when we have received enough data in our buffer to attempt to process it.  
// At a minimum we need 2 bytes.  From those two bytes, we can then determine how much more data we 
// need for the command.  Note that it is possible and likely to receive multiple commands at a time.
static void session_read_handler(struct bufferevent *bev, void *data)
{
	session_t *session = data;
	assert(session != NULL);

// 	fprintf(stderr, "Data received.\n");
	
	assert(bev == session->bev);

	stream_t *stream = session->stream;
	assert(stream);
	assert(stream->risp);
	
	// if we are reading data, the session should NOT be closing.
	assert(session->closing == 0);

	// if buffwait is -1, it means it wasn't configured when the session was created.
	assert(session->buffwait != -1);
	
	// at this point, the amount of data we are waiting on should be at least 2 or greater.  
	// This is because the minimum command size is 2 bytes.  Once we know those 2 bytes, 
	// we can determine what the size of the complete command should be.
	assert(session->buffwait >= 2);
	
	struct evbuffer *input = bufferevent_get_input(bev);
	assert(input);
	
	size_t len = evbuffer_get_length(input);
	while (len >= session->buffwait) {

		// The low-watermark should have allowed a trigger as soon as we have the minimum we need 
		// (which is 2 bytes for the start of the command, or the rest that we are waiting for). 
		
		// NOTE: we are not pulling data out of the buffer.  We will leave the data in there, and process it directly.  
		//       Therefore, we need to make sure the entire command is in contiguous memory.  
		//       There may be more than one command in the first chunk of data though.
		
		// NOTE: In many circumstances, it might be more efficient to just pullup the entire buffer, so that much more can be processed in a single loop.  However, the danger is that we receive a large amount of data, and pulling it all together in one go could be too much.  Therefore, it may be better to have some logic around it, pull-up a certain amount each time.  Some performance testing of various situations should be undertaken.
		
		unsigned char *inbuffer = evbuffer_pullup(input, session->buffwait);
		assert(inbuffer);
		
		// now that we have at least the data that we need to start with, we should try and process as much as we can 
		// (if we dont have the full amount of data, it doesn't matter, we will detect that and prepare for the next iteration.)
		// Note also, we dont process the minimum (buffwait), because we might actually have much more than that in our buffer, 
		// and we want to process as much as we can.
		size_t avail = evbuffer_get_contiguous_space(input);
		assert(avail <= len);
		
		// process the data that we have.
		risp_length_t processed = risp_process(stream->risp, session->usersession, avail, inbuffer);
		assert(processed <= avail);
		assert(processed >= 0);
		
		// if we processed data from the buffer, we should remove at least that part now.
		if (processed > 0) {
			evbuffer_drain(input, processed);
			avail -= processed;

			// inbuffer is probably invalid now.
			inbuffer = NULL;
			
			// what we have processed, need to decrement.
			len -= processed;
			assert(len >= 0);
		}
		
		if (avail >= 2) {
			// there is a command still in the local buffer, we need to find out how much data it needs, and set the watermark to that.
			
			if (inbuffer == NULL) {
				// pullup at least the 2 bytes required in a command.
				inbuffer = evbuffer_pullup(input, sizeof(risp_command_t));
				assert(inbuffer);
				
				avail = evbuffer_get_contiguous_space(input);
			}
			
			// find out how much data we need (based on the info we have already).
			session->buffwait = risp_needs(avail, inbuffer);
		}
		else {
			session->buffwait = 2;
		}
		
	}
	
	// set the watermark.
	assert(session->buffwait >= 2);
	bufferevent_setwatermark(bev, EV_READ, session->buffwait, 0);
}


// If a session is connected, then we call the callback handler if one was set and then process as normal.  
// If the connection fails, we call the 'closed' callback if one was specified, and clean up the connection.  
// Once connected, if the connection is closed, cleanup and call callback handler.
void session_buffer_handler(struct bufferevent *bev, short events, void *ptr)
{
	session_t *session = ptr;
	assert(session);
	assert(bev);
	assert(events != 0);

    if (events & BEV_EVENT_CONNECTED) {
		// we have successfully connected.
		assert(session->bev == NULL || session->bev == bev);
		if (session->bev == NULL) { 
			session->bev == bev; 
			
			// Need to set the watermark for the minimum data needed (2 bytes).  
			// Once 2 bytes have been read, we will know how much more data we need for the command, so we can then set a new watermark.
			session->buffwait = 2;
			bufferevent_setwatermark(session->bev, EV_READ, session->buffwait, 0);
		}
		fprintf(stderr, "Connection received.\n");
		if (session->newconn_fn) {
			// a callback was specified so we call it.
			(*session->newconn_fn)(session, session->usersession);
		}
    } 
    else if (events & (BEV_EVENT_ERROR|BEV_EVENT_EOF)) {
		fprintf(stderr, "SESSION CLOSED\n");
		assert(session->bev == bev);
		if (session->connclosed_fn) {
			(*session->connclosed_fn)(session, session->usersession);
			session_close(session);
		}
    }
}








//--------------------------------------------------------------------------------------------------
// allocate space off the heap for a new struct.  clear and initialise it with the new handle.  
// If handle is <0 , then the socket is not yet connected, and therefore don't enable the read 
// handler.  If we are not supplying the handle yet, we also cannot setup the write handler.
static session_t * session_new(stream_t *stream, int handle)
{
	assert(stream);
	assert(stream->sverify == STRUCT_VERIFIER);
	
	session_t *session  = (session_t *) calloc(1, sizeof(session_t));
	assert(session);
	
	session->stream = stream;
	session->closing = 0;
	session->close_event = NULL;
	session->newconn_fn = NULL;
	session->connclosed_fn = NULL;
	session->bev = NULL;
	session->buffwait = 2;
	
	// if the stream is setup to use certificates, then this session will need to be also.
	assert(stream->use_ssl == 0 || (stream->use_ssl == 1 && stream->server_ctx));
	if (stream->server_ctx) {
		session->client_ssl = SSL_new(stream->server_ctx);
		assert(session->client_ssl);
	}
	else {
		session->client_ssl = NULL;
	}
	
	// pre-create the events that we will be using for this socket. 
	// only add the read event if a valid handle has been supplied.  If we are initiating a connection, then we dont want the read handler added first.
	if (handle >= 0) {

		// we have a socket handle, now we need to create the evbuffer, and it will handle the socket from now on.
		assert(stream->main_event_base);
		assert(handle >= 0);
		if (session->client_ssl == NULL) {
			// Not using certificates.
			session->bev = bufferevent_socket_new(stream->main_event_base, handle, BEV_OPT_CLOSE_ON_FREE);
		} 
		else {
			// certificates are being used.  Therefore, we accept the socket with an SSL context.
			session->bev = bufferevent_openssl_socket_new(stream->main_event_base, handle, session->client_ssl, BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_CLOSE_ON_FREE);
		}
		assert(session->bev);

		// Need to set the watermark for the minimum data needed (2 bytes).  
		// Once 2 bytes have been read, we will know how much more data we need for the command, so we can then set a new watermark.
		assert(session->buffwait >= 2);
		bufferevent_setwatermark(session->bev, EV_READ, session->buffwait, 0);

		// Need to set the callback routine when new data arrives.
		fprintf(stderr, "Read handler set.\n");
		bufferevent_setcb(session->bev, session_read_handler, NULL, session_buffer_handler, session);
		bufferevent_enable(session->bev, EV_READ|EV_WRITE);
		
		// TODO: If there is an idle callback, then we set it with a timeout.
	}
	else {
		assert(session->bev == NULL);
// 		assert(0);
	}
	
	if (stream->idle_callback_fn) {
		// the user has specificied an idle timeout.  How are we going to handle that.
		assert(0);
	}
	
	// now that we have an initiated (but empty) session, we need to add it to the list.
	assert(stream->sessions);
	assert(stream->max_sessions > 0);
	assert(stream->next_session_slot >= 0);
	assert(stream->next_session_slot < stream->max_sessions);
	
	assert(stream->sessions[stream->next_session_slot] == NULL);
	stream->sessions[stream->next_session_slot] = session;
	session->index = stream->next_session_slot;
	stream->next_session_slot++;

	// Since we will ONLY have empty slots at the end of the array, there should be a slot available, or the array will be full. 
	assert(stream->next_session_slot <= stream->max_sessions);
	if (stream->next_session_slot == stream->max_sessions) {
		
// 		fprintf(stderr, "STREAM: Session Slot Limit Reached. (Current=%d, Adding=%d)\n", stream->max_sessions, SESSION_SLOT_INCR);
		
		// we reached the limit and didn't find an empty slot.  So we add a new slot.
		stream->max_sessions += SESSION_SLOT_INCR;
		assert(stream->next_session_slot > 0);
		assert(stream->max_sessions > stream->next_session_slot);
		stream->sessions = realloc(stream->sessions, stream->max_sessions * sizeof(void *));
		assert(stream->sessions);
		
		// since we've added new slots, we need to make sure they point to nothing.
		for (int i=stream->next_session_slot; i<stream->max_sessions; i++) {
			stream->sessions[i] = NULL;
		}
	}

	assert(stream->next_session_slot < stream->max_sessions);
	// at the end of this, we should have added our new session to an empty slot in the array.  
	// If the array had no empty slots (after the next_session_slot), then it would have increased the size of the array.

	if (stream->newconn_callback_fn) {
		assert(session->usersession == NULL);
		(*stream->newconn_callback_fn)(session, stream->userdata);
	}
	
	return(session);
}


// When the user recieves a callback for a session, they can (and should) attach some userdata to the session. This will be used when RISP processes the stream in its callbacks.
void rispsession_set_userdata(RISPSESSION sessionptr, void *sessiondata)
{
	session_t *session = sessionptr;
	
	assert(session);
	assert(sessiondata);
	
	assert(session->usersession == NULL);
	session->usersession = sessiondata;
}



// This function will add a connection to the stream.  Since the connection is not established, it will try and establish it.  Since we are using events, then it will add the details to a structure.  It will then create a timeout event.  The timeout event should fire and it will attempt to connect once the event system is processing.  If the connection timesout, then it will need to call the connect-fail callback.
int rispstream_connect(RISPSTREAM streamptr, char *host, int port, void *basedata, risp_cb_newconn newconn_fn, risp_cb_connclosed connclosed_fn)
{
	stream_t *stream = streamptr;
	assert(stream);
	assert(stream->sverify == STRUCT_VERIFIER);
	if (stream->sverify == STRUCT_VERIFIER) {

		// if there isn't already a libevent_base already set, then we should do one now.
		if (stream->main_event_base == NULL) { rispstream_init_events(streamptr); }
		
		// create a new session (passing in -1 as a handle, so that it doesn't setup all the events)
		session_t *session = session_new(streamptr, -1);
		assert(session);

		assert(session->usersession == NULL);
		session->usersession = basedata;
			
		session->newconn_fn = newconn_fn;
		session->connclosed_fn = connclosed_fn; 			

		session->buffwait = 2;

		assert(stream->main_event_base);
		assert(session->bev == NULL);
		if (stream->client_ctx == NULL) {
			session->bev = bufferevent_socket_new(stream->main_event_base, -1, BEV_OPT_CLOSE_ON_FREE);
			assert(session->bev);
			
			bufferevent_setcb(session->bev, session_read_handler, NULL, session_buffer_handler, session);
			bufferevent_enable(session->bev, EV_READ|EV_WRITE);
			
			assert(stream->dns_base);
			assert(host);
			assert(port > 0);
			int rc = bufferevent_socket_connect_hostname(session->bev, stream->dns_base, AF_UNSPEC, host, port);
			assert (rc >= 0);

		}
		else {
			// Need to connect with openssl.
			assert(stream->server_ctx == NULL);
			
			assert(session->client_ssl == NULL);
			session->client_ssl = SSL_new(stream->client_ctx);
			assert(session->client_ssl);
			
			assert(session->bev == NULL);
			session->bev = bufferevent_openssl_socket_new(stream->main_event_base, -1, session->client_ssl, BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE);
			assert(session->bev);
	
			bufferevent_setcb(session->bev, session_read_handler, NULL, session_buffer_handler, session);
			bufferevent_enable(session->bev, EV_READ|EV_WRITE);
		
			int rc = bufferevent_socket_connect_hostname(session->bev, stream->dns_base, AF_UNSPEC, host, port);
			assert (rc >= 0);
			if (rc < 0) {
				// warnx("could not connect: %s", evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
				assert(0);
				// is this step a blocking one?
				bufferevent_free(session->bev);
				session->bev = NULL;
			}
		}
		
		// Note that nothing will happen if the event loop is not dispatched.  
	}
}





//--------------------------------------------------------------------------------------------------
// this function is called when a new socket is ready to be accepted. We need to create a new session, 
// and add it to our session list.  We need to pass to the session any pointers to other sub-systems 
// that it will need to have, and then we insert the session into the 'session-circle' somewhere.  
// Finally, we need to add the new session socket to the event base so we can know when data is 
// received..
static void listen_event_handler(
	struct evconnlistener *listener,
	evutil_socket_t fd,
	struct sockaddr *address,
	int socklen,
	void *data
)
{
	assert(listener);
	assert(fd >= 0);
	assert(data != NULL);
	
	stream_t *stream = data;
	assert(stream->sverify == STRUCT_VERIFIER);

	// TODO: at this point, we are not passing on the address information... however, we will want to do so at some point.
	fprintf(stderr, "New connection received.\n");
	
	// Create the session object.
	session_t *session = session_new(stream, fd);
	assert(session);
}


// This default callback is called when a break signal is recieved.  It should trigger a shutdown of all active connections (regardless of protocol used outside of this stream).  It will simply close all connections if there is no outgoing buffer.  If there is an outgoing buffer, it will try and send what is in it before closing, but will put a timeout, and if it cant send within that time, then it will close the socket anyway.
static void default_break_cb(stream_t *stream)
{
	assert(0);
}


// When a certificate is used that requires a passphrase, this will set the callback that will provide the passphrase.  The implementation may want to get the passphrase from the user somehow.
void rispstream_set_passphrase_callback(RISPSTREAM streamptr, risp_cb_passphrase passphrase_fn)
{
	stream_t *stream = streamptr;
	assert(stream);
	assert(passphrase_fn);
	
	assert(stream->passphrase_fn == NULL);
	stream->passphrase_fn = passphrase_fn;
}




// Listen on a particular port (and optionally, interface), and when events occur, call the callback functions.
// If no Interface is provided, it will attempt to listen on all interfaces.
// NOTE: an interface normally means an IP address.
//
// Returns:
//	0 - Everything was successful.
//  1 - Unable to listen on the required socket port or address.
int rispstream_listen(RISPSTREAM streamptr, char *host, int port, risp_cb_newconn newconn_fn, risp_cb_connclosed connclosed_fn)
{
	stream_t *stream = streamptr;
	assert(stream);
	assert(host);
	assert(port > 0);
	
	stream->newconn_callback_fn = newconn_fn;
	stream->connclosed_callback_fn = connclosed_fn;
	
	struct sockaddr_in sin;
	int len;
		
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;	// currently just supporting IPv4
	len = sizeof(sin);

	// The host and port are provided seperately, but the evutil_parse_sockaddr_port function parses a string.
	char interface[4096];
	sprintf(interface, "%s:%d", host, port);
	
	assert(sizeof(struct sockaddr_in) == sizeof(struct sockaddr));
	if (evutil_parse_sockaddr_port(interface, (struct sockaddr *)&sin, &len) != 0) {
		assert(0);
		return(-1);
	}
	else {
		
		assert(stream->listener == NULL);
		assert(stream->main_event_base);
		
		stream->listener = evconnlistener_new_bind(
								stream->main_event_base,
								listen_event_handler,
								stream,
								LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE,
								-1,
								(struct sockaddr*)&sin,
								sizeof(sin)
							);
		assert(stream->listener);
	}	
	
	// Since we exit the function whenever an error condition is detected, if we got this far, then everything should be good.
	return(0);
}


void rispstream_process(RISPSTREAM streamptr)
{
	stream_t *stream = streamptr;
	assert(stream);
	assert(stream->sverify == STRUCT_VERIFIER);
	if (stream->sverify == STRUCT_VERIFIER) {

		//==============================================================================================
		// enter the event loop.  This will continue to run until the shutdown process has closed off 
		// all the active events.
		assert(stream->main_event_base);
		int ret = event_base_loop(stream->main_event_base, 0);
		assert(ret >= 0);
		//==============================================================================================

	}
}





// This tells the stream to stop listening on whatever ports it is listening on.
void rispstream_stop_listen(RISPSTREAM stream)
{
	assert(stream);
	
	// incomplete
	assert(0);
}



// Users can set an initial timeout on connections.  
// If this function is called, then when new connections are received, if no data has been received within that timeout period, it will .
void rispstream_idle_callback(RISPSTREAM streamptr, risp_cb_idle idle_fn)
{
	assert(streamptr);
	assert(idle_fn);
	
	stream_t *stream = streamptr;
	assert(stream->sverify == STRUCT_VERIFIER);
	if (stream->sverify == STRUCT_VERIFIER) {
		stream->idle_callback_fn = idle_fn;
	}
}



// This write handler is only ever set when we are closing the session.  
// This allows us to know when the buffer is empty so we can close it.
static void session_write_handler(struct bufferevent *bev, void *data)
{
	session_t *session = data;
	assert(session != NULL);
	assert(session->bev);
	assert(bev == session->bev);

	stream_t *stream = session->stream;
	assert(stream);
	assert(stream->risp);
	
	// The only time this should fire, is when the session is closing and we want to make sure the outbuffer has been flushed before shutting it down.
	assert(session->closing == 1);

	struct evbuffer *output = bufferevent_get_output(bev);
	assert(output);
	size_t len = evbuffer_get_length(output);
	assert(len >= 0);
	if (len == 0) {
		// Now we can close it.
		session_close(session);
	}
}

// The client calls this to close the session.   If there is data in the buffer, it will try to send it first, and when the connection is actually closed, it will call the callback function.   In other words, this is a non-blocking operation.  If the user wants it to wait till the connection is closed before exiting, then they need to call rispsession_close_wait()
void rispsession_close(RISPSESSION sessionptr)
{
	assert(sessionptr);
	session_t *session = sessionptr;
	
	stream_t *stream = session->stream;
	assert(stream);

	fprintf(stderr, "RISPSESSION: Closing Session\n");
	
	// mark the session as closing.  If we dont close the session now, then it will be closed when the outbuffer is emptied.
	assert(session->closing == 0);
	session->closing = 1;

	// if there is data in the outbuffer, add a write-callback to the buffer, so that we know when the data has been written.  Then we can close it all.
	assert(session->bev);
	
	struct evbuffer *output = bufferevent_get_output(session->bev);
	assert(output);
	size_t len = evbuffer_get_length(output);
	assert(len >= 0);
	if (len > 0) {
		fprintf(stderr, "RISPSESSION: Session is not empty (%lu).  Waiting for empty.\n", len);
		assert(session->buffwait != -1);
		bufferevent_disable(session->bev, EV_READ);
		bufferevent_setcb(session->bev, NULL, session_write_handler, session_buffer_handler, session);
	}
	else {
		fprintf(stderr, "RISPSESSION: Session is empty (%lu).  Closing Now.\n", len);
		bufferevent_disable(session->bev, EV_READ|EV_WRITE);
		
		SSL *ctx = bufferevent_openssl_get_ssl(session->bev);
		assert(ctx);

		/*
		* SSL_RECEIVED_SHUTDOWN tells SSL_shutdown to act as if we had already
		* received a close notify from the other end.  SSL_shutdown will then
		* send the final close notify in reply.  The other end will receive the
		* close notify and send theirs.  By this time, we will have already
		* closed the socket and the other end's real close notify will never be
		* received.  In effect, both sides will think that they have completed a
		* clean shutdown and keep their sessions valid.  This strategy will fail
		* if the socket is not ready for writing, in which case this hack will
		* lead to an unclean shutdown and lost session on the other end.
		*/
		SSL_set_shutdown(ctx, SSL_RECEIVED_SHUTDOWN);
		SSL_shutdown(ctx);
		
		bufferevent_free(session->bev);
		session->bev = NULL;
		
		// Now we can close it.
		session_close(session);
	}
}




// TODO: This function allocates space on the heap, which is not the most efficient way of doing this.  Especially for a fully-determined length.  It should use more efficient buffer manipulation itself.  This will work initially though.
void rispsession_send_noparam(RISPSESSION sessionptr, risp_command_t command)
{
	assert(sessionptr);
	session_t *session = sessionptr;
	assert(session);
	assert(session->bev);

	// make sure there is enough space in the buffer for this transaction.
	risp_length_t bufflen = risp_command_length(command, 0);
	assert(bufflen > 0);
	void *buff = malloc(bufflen);
	assert(buff);

	// add the command to the buffer.
	risp_length_t len = risp_addbuf_noparam(buff, command);
// 	fprintf(stderr, "bufflen:%d, len:%d\n", bufflen, len);
	assert(len == bufflen);
	
	int written = bufferevent_write(session->bev, buff, len);
	assert(written == 0);	/* -1 indicates failure... why would it fail? */
	free(buff);
}




void rispsession_send_int(RISPSESSION sessionptr, risp_command_t command, risp_int_t value)
{
	assert(sessionptr);
	session_t *session = sessionptr;
	assert(session);
	assert(session->bev);

	
	// make sure there is enough space in the buffer for this transaction.
	risp_length_t bufflen = risp_command_length(command, 0);
	assert(bufflen > 0);
	void *buff = malloc(bufflen);
	assert(buff);

	// add the command to the buffer.
	risp_length_t len = risp_addbuf_int(buff, command, value);
	assert(len == bufflen);

	int written = bufferevent_write(session->bev, buff, len);
	assert(written == 0);	/* -1 indicates failure... why would it fail? */
	free(buff);
}

void rispsession_send_str(RISPSESSION sessionptr, risp_command_t command, risp_int_t length, risp_data_t *data)
{
	assert(sessionptr);
	session_t *session = sessionptr;
	assert(session);
	assert(session->bev);

	// make sure there is enough space in the buffer for this transaction.
	risp_length_t bufflen = risp_command_length(command, length);
	assert(bufflen > length);

	void *buff = malloc(bufflen);
	assert(buff);

	// add the command to the buffer.
	risp_length_t len = risp_addbuf_str(buff, command, length, data);
	assert(len == bufflen);

	int written = bufferevent_write(session->bev, buff, len);
	assert(written == 0);	/* -1 indicates failure... why would it fail? */
	free(buff);
}


void rispstream_attach_risp(RISPSTREAM streamptr, RISP risp)
{
	stream_t *stream = streamptr;
	assert(stream);
	assert(risp);

	assert(stream->sverify == STRUCT_VERIFIER);
	if (stream->sverify == STRUCT_VERIFIER) {
		stream->risp = risp;
	}
}


void rispstream_break_on_signal(RISPSTREAM streamptr, int sig, risp_cb_break break_fn)
{
	stream_t *stream = streamptr;
	assert(stream);

	assert(stream->sverify == STRUCT_VERIFIER);
	if (stream->sverify == STRUCT_VERIFIER) {
		stream->break_callback_fn == break_fn;
	}
}


void rispstream_detach_risp(RISPSTREAM streamptr)
{
	stream_t *stream = streamptr;
	assert(stream);

	assert(stream->sverify == STRUCT_VERIFIER);
	if (stream->sverify == STRUCT_VERIFIER) {
		stream->risp = NULL;
	}
}



void rispstream_set_userdata(RISPSTREAM streamptr, void *userdata)
{
	stream_t *stream = streamptr;
	assert(stream);

	assert(stream->sverify == STRUCT_VERIFIER);
	if (stream->sverify == STRUCT_VERIFIER) {
		stream->userdata = userdata;
	}
}


void rispstream_use_ssl(RISPSTREAM streamptr)
{
	stream_t *stream = streamptr;
	assert(stream);

	assert(stream->sverify == STRUCT_VERIFIER);
	if (stream->sverify == STRUCT_VERIFIER) {
		assert(stream->use_ssl == 0);
		stream->use_ssl = 1;
	}
}


// This is a callback function that will be called by OpenSSL when it is trying to use a certificate with a password protected key.
int cert_passphrase_cb(char *buf, int size, int rwflag, void *userdata)
{
	assert(buf);
	assert(userdata);
	
	fprintf(stderr, "Passphrase Callback (size:%d)\n", size);

	
	int len = 0;
	
	stream_t *stream = userdata;
	assert(stream->sverify == STRUCT_VERIFIER);
	if (stream->sverify == STRUCT_VERIFIER) {
		if (stream->passphrase_fn) {
			len = (*stream->passphrase_fn)(stream, size, buf);
		}
	}
	
	assert(len >= 0);
	return(len);
}


// User is adding the required cert data needed for a listening service.  CA file should also contain CA's for client-cert authentication if that is used.
// Returns: 0 - on success.  ca and pkey were loaded successfully.
//          -1 - failure.  either the files didn't exist, were in the wrong format, or didn't match.
int rispstream_add_server_certs(RISPSTREAM streamptr, char *ca_pem_file, char *ca_pkey_file)
{
	stream_t *stream = streamptr;
	assert(stream);
	
	assert(ca_pem_file);
	assert(ca_pkey_file);
	
	assert(stream->server_ctx == NULL);

	/* Initialize the OpenSSL library */
	SSL_load_error_strings();
	SSL_library_init();
	/* We MUST have entropy, or else there's no point to crypto. */
	if (!RAND_poll())
		return -1;

	stream->server_ctx = SSL_CTX_new(SSLv23_server_method());
	assert(stream->server_ctx);

	// if the client certificate has a passphrase (meaning that the private key is encrypted), then a callback routine will be called asking for the passphrase.   If a passphrase hasn't been stored for this stream, then we will need to ask the user for it.
	SSL_CTX_set_default_passwd_cb(stream->server_ctx, cert_passphrase_cb);
	SSL_CTX_set_default_passwd_cb_userdata(stream->server_ctx, stream);

	
	if (! SSL_CTX_use_certificate_chain_file(stream->server_ctx, ca_pem_file) ||
		! SSL_CTX_use_PrivateKey_file(stream->server_ctx, ca_pkey_file, SSL_FILETYPE_PEM)) {
		stream->server_ctx = NULL;
	}
	else {
		SSL_CTX_set_options(stream->server_ctx, SSL_OP_NO_SSLv2);
	}
	
	// return 0 if the context was created, otherwise a 1.
	return stream->server_ctx ? 0 : -1;
}


// User is adding the required cert data needed for connecting.
// Returns: 0 - on success.  ca and pkey were loaded successfully.
//          -1 - failure.  either the files didn't exist, were in the wrong format, or didn't match.
int rispstream_add_client_certs(RISPSTREAM streamptr, char *ca_pem_file, char *ca_pkey_file)
{
	stream_t *stream = streamptr;
	assert(stream);

	assert(ca_pem_file);
	assert(ca_pkey_file);

	assert(stream->client_ctx == NULL);

	/* Initialize the OpenSSL library */
	SSL_load_error_strings();
	SSL_library_init();
	/* We MUST have entropy, or else there's no point to crypto. */
	if (!RAND_poll())
		return -1;

	assert(stream->client_ctx == NULL);
	stream->client_ctx = SSL_CTX_new(SSLv23_client_method());
	assert(stream->client_ctx);

	// if the client certificate has a passphrase (meaning that the private key is encrypted), then a callback routine will be called asking for the passphrase.   If a passphrase hasn't been stored for this stream, then we will need to ask the user for it.
	SSL_CTX_set_default_passwd_cb(stream->client_ctx, cert_passphrase_cb);
	SSL_CTX_set_default_passwd_cb_userdata(stream->client_ctx, stream);

	
	int rc = SSL_CTX_use_certificate_file(stream->client_ctx, ca_pem_file, SSL_FILETYPE_PEM);
	if (rc == 1) {
		rc = SSL_CTX_use_PrivateKey_file(stream->client_ctx, ca_pkey_file, SSL_FILETYPE_PEM);
		if (rc != 1) {
			stream->client_ctx = NULL;
		}
	}
	
	// return 0 if the context was created, otherwise a 1.
	return stream->client_ctx ? 0 : -1;
}


extern struct event_base * rispstream_get_eventbase(RISPSTREAM streamptr)
{
	stream_t *stream = streamptr;
	assert(stream);

	return(stream->main_event_base);
}

