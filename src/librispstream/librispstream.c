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
#include <event2/listener.h>
#include <fcntl.h>
#include <risp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>




// global constants and other things go here.
#define DEFAULT_MAXCONNS	1024
#define DEFAULT_MAXBYTES	0
#define DEFAULT_CHUNKSIZE	(1024*512)

// the number of slots to add to our sessions array every time we need to expand it.  Initial array size will be this size.
#define SESSION_SLOT_INCR 4

#define INVALID_HANDLE -1

// if our buffer gets bigger than this, then we should attempt to shrink it.
#define OPTIMAL_MAX (DEFAULT_CHUNKSIZE*64)

#define STRUCT_VERIFIER 92749473038


// Each connection is treated as a session.  Which also includes buffer for unprocessed data, 
// and a buffer for pending outgoing data.
// When the session object is created, the read/write and any other events should be constructed.  Then, when we activate them, we dont have to keep re-creating them.
typedef struct {
	int handle;
	RISPSTREAM stream;
	
	// The index is used to find this session entry in the array of pointers of all the sessions.  
	// If we are in a service that has thousands of connections opening and closing, it could be 
	// bad performance to iterate through the array looking for a particular session.   So this 
	// index will point to the slot in the array that the pointer to this session exists.   
	// It will only be manipulated when a session is created, when other sessions close, and used 
	// when this session is closed.  
	// NOTE that it will change independantly of this session.
	int index;

	struct {
		unsigned char *buffer;
		unsigned int length;
		unsigned int max;
		struct event *event;
	} in, out;
	
	int closing;
	struct event *close_event;
	struct event *connect_event;

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
	
	struct evconnlistener *listener;
	struct event *stream_cleanup_event;
	struct event *break_event;
//	int listen_handle;
	
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
// Pre-declared functions.  
static void session_write_handler(int hid, short flags, void *data);




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

	// This value is used to determine if a correct STREAM pointer is provided as an argument.
	stream->sverify = STRUCT_VERIFIER;

	if (base == NULL) {
		stream->main_event_base = event_base_new();
		assert(stream->main_event_base);
		
		// this is used to indicate if we created the libevent base internally, or are using an externally managed event base.
		stream->flag_internal_event_base = 1;
	}
	else {
		stream->main_event_base = base;
		stream->flag_internal_event_base = 0;
	}
	
	stream->dns_base = NULL;
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




void rispstream_shutdown(RISPSTREAM streamptr)
{
	assert(streamptr);
	stream_t *stream = streamptr;
	
	assert(0);
	
	
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


// When a session is closed (normally from the other side), we need to do some cleanup.
static void session_close(session_t *session) 
{
	assert(session);

	// the session was also closed from this side, so we can remove the close event.
	if (session->close_event) {
		event_del(session->close_event);
		session->close_event = NULL;
	}
	
	// delete the 'out' event and buffer.  We dont care if there is something in it.
	assert(session->out.event);
	event_del(session->out.event);
	session->out.event = NULL;
	
	if (session->out.buffer) {
		assert(session->out.max > 0);
		free(session->out.buffer); 
		session->out.buffer = NULL;
	}

	session->out.length = 0;
	session->out.max = 0;

	// delete the 'in' event and buffer.  Again we dont care if there is something in it, because it would only have been a partial message.
	assert(session->in.event);
	event_del(session->in.event);
	session->in.event = NULL;
	
	if (session->in.buffer) {
		assert(session->in.max > 0);
		free(session->in.buffer);
		session->in.buffer = NULL;
	}
	session->in.length = 0;
	session->in.max = 0;
	
	assert(session->handle >= 0);
	close(session->handle);
	session->handle = INVALID_HANDLE;

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
	
	// since we are closing a session, we can be sure that the 'next' session slot should definately be greater than zero.  There should be definately at least one session in the array.
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

//--------------------------------------------------------------------------------------------------
// This function is called when we have received a data over a socket we have accepted a connection 
// for.  We read the data from the socket and then process it.
static void session_read_handler(int hid, short flags, void *data)
{
	assert(hid >= 0);
	
	session_t *session = data;
	assert(session != NULL);
	
// 	fprintf(stderr, "session_read_handler. hid=%d, handle=%d\n", hid, session->handle);
	
	// If the handle is invalid, then we shouldn't be processing anything more on this socket.  
	assert(session->handle == hid);
	
	// when the socket is closed, the read-event should have been cleared.
	assert(session->closing == 0);
	
	if (flags & EV_TIMEOUT) {
		// if the timeout occured, then the READ flag should not be set.
		assert((flags & EV_READ) == 0);
	}
	
	if (flags & EV_READ) {

		// make sure we have some available space in our buffer.  We want to at least be able to get a 'CHUNK' worth.
		unsigned int avail = session->in.max - session->in.length;
		if (avail < DEFAULT_CHUNKSIZE) {
			session->in.max += DEFAULT_CHUNKSIZE;
			session->in.buffer = (unsigned char *) realloc(session->in.buffer, session->in.max);
			avail = session->in.max - session->in.length;
		}

		assert(session->in.buffer);
		assert(session->in.length >= 0);
		assert(avail >= DEFAULT_CHUNKSIZE);
		ssize_t res = recv(hid, session->in.buffer + session->in.length, avail, O_NONBLOCK);
		if (res > 0) {
			session->in.length += res;
			assert(session->in.length <= session->in.max);
		}
		else if (res == 0) {
			// Session closed while reading.
			session_close(session);
		}
		else {
			assert(res == -1);
			if (errno != EAGAIN && errno != EWOULDBLOCK) {
				session_close(session);
			}
		}
		
		if ((session->closing == 0) && (session->in.length > 0)) {
			
			assert(session->in.length <= session->in.max);
			assert(session->in.length > 0);
			
			stream_t *stream = session->stream;
			assert(stream);
			assert(stream->risp);
			risp_length_t processed = risp_process(stream->risp, session->usersession, session->in.length, session->in.buffer);
			assert(processed <= session->in.length);
			assert(processed >= 0);
			if (processed < session->in.length) {
				// we didn't process all the data in the buffer.  This means we haven't received it 
				// all yet.  Move the un-processed data to the start of the buffer, and wait for the 
				// rest to arrive (if we processed anything at all).
				if (processed > 0) {
					avail = session->in.length - processed;
					memmove(session->in.buffer, session->in.buffer + processed, avail);
					session->in.length -= processed;
					assert(session->in.length > 0);
				}
			}
			else {
				// everything in the buffer was processed.  So we can mark it as empty.
				session->in.length = 0;
			}
		}

		if (session->closing != 0) {
			// need to close the connection now that all the output has been sent.
			session_close(session);
		}
	}
	
	// Once our 'partial' processing has passed a certain point, we want to clean up the memory that 
	// we have allocated.  This is also to combat situations where people are sending a valid data 
	// stream but deliberately leaving an unfinished command at the end of each packet (completed at 
	// the beginining of the next packet), which would normally end up increasing the amount of 
	// memory used by the session.   This is intended to ensure that doesn't cause more serious 
	// memory issues.
 	if (session->in.max > OPTIMAL_MAX) {
		if (session->in.length < session->in.max) {
			session->in.buffer = (unsigned char *) realloc(session->in.buffer, session->in.length);
			session->in.max = session->in.length;
		}
 	}
}


static void session_create_events(session_t *session)
{
	assert(session);
	stream_t *stream = session->stream;
	assert(stream);
	
	assert(stream->main_event_base);
	assert(session->out.event == NULL);
	assert(session->handle >= 0);
	session->out.event = event_new(stream->main_event_base, session->handle, EV_WRITE, session_write_handler, (void *)session);
	assert(session->out.event);

	// Since we will always be ready to receive data, we should create the read event, making it persistant.   
	// If there is an idle callback, then we set it with a timeout.
	assert(stream->main_event_base);
	assert(session->in.event == NULL);
	assert(session->handle >= 0);
	session->in.event = event_new(stream->main_event_base, session->handle, EV_TIMEOUT | EV_READ | EV_PERSIST, session_read_handler, (void *)session);
	assert(session->in.event);

	struct timeval *timeout = NULL;
	event_add(session->in.event, timeout);
}



static void session_connect_handler(int fd, short int flags, void *arg)
{
	session_t *session = arg;

	assert(fd >= 0);
	assert(flags != 0);
	assert(flags & EV_WRITE);

// 	fprintf(stderr, "connect_handler: fd=%d, handle=%d, sessionptr=%llx\n", fd, session->handle, (long long unsigned) session);
	
	// at this point, we expect the session handle to be -1.  Since we are now connected, we will want to set the proper handle.
	assert(session->handle == -1);
	session->handle = fd;

	// remove the connect handler
	assert(session->connect_event);
	event_free(session->connect_event);
	session->connect_event = NULL;
	
	// since we connected, the regular read and write events shouldn't have been set yet.
	assert(session->out.event == NULL);
	assert(session->in.event == NULL);
	session_create_events(session);
	assert(session->out.event);
	assert(session->in.event);
	
	int error;
	socklen_t foo = sizeof(error);
	getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &foo);
	if (error == ECONNREFUSED) {
		// connect failed...  
// 		fprintf(stderr, "CONNECT FAILED\n");
		if (session->connclosed_fn) {
			(*session->connclosed_fn)(session, session->usersession);
			session_close(session);
		}
	}
	else {
		// session connected.
// 		fprintf(stderr, "CONNECTED\n");

		// since the connection was successful, we want to set the read-event to active.
		assert(session->in.event);
		event_add(session->in.event, NULL);

		if (session->newconn_fn) {
			// a callback was specified so we call it.
			(*session->newconn_fn)(session, session->usersession);
		}
	}
}







//--------------------------------------------------------------------------------------------------
// allocate space off the heap for a new struct.  clear and initialise it with the new handle.  
// If handle is <0 , then the socket is not yet connected, and therefore don't enable the read 
// handler.  Since we are not supplying the handle yet, we also cannot setup the write handler.
static session_t * session_new(stream_t *stream, int handle)
{
	assert(stream);
	assert(stream->sverify == STRUCT_VERIFIER);
	
	session_t *session  = (session_t *) calloc(1, sizeof(session_t));
	assert(session);
	
	session->stream = stream;

	session->in.buffer = NULL;
	session->in.length = 0;
	session->in.max = 0;
	session->out.buffer = NULL;
	session->out.length = 0;
	session->out.max = 0;
	
	session->handle = handle;
	
	session->closing = 0;
	session->close_event = NULL;
	
	session->connect_event = NULL;
	
	session->newconn_fn = NULL;
	session->connclosed_fn = NULL;
	
	// pre-create the events that we will be using for this socket. 
	// only add the read event if a valid handle has been supplied.  If we are initiating a connection, then we dont want the read handler added first.
	if (session->handle >= 0) {
		session_create_events(session);
		assert(session->out.event);
		assert(session->in.event);
	}
	else {
		assert(session->out.event == NULL);
		assert(session->in.event == NULL);
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
int rispstream_connect(RISPSTREAM streamptr, char *host, void *basedata, risp_cb_newconn newconn_fn, risp_cb_connclosed connclosed_fn)
{
	stream_t *stream = streamptr;
	assert(stream);
	assert(stream->sverify == STRUCT_VERIFIER);
	if (stream->sverify == STRUCT_VERIFIER) {

		// if there isn't already a libevent_base already set, then we should do one now.
		if (stream->main_event_base == NULL) { rispstream_init_events(streamptr); }
		
		// TODO: The DNS Lookup (evutil_parse_sockaddr_port) is currently 'blocking'.  We need to use evdns instead 
		// with callbacks so that we can do the DNS lookup without blocking any other events.
		
		// create the socket and connect.
		struct sockaddr saddr;
		int len = sizeof(saddr);
		assert(host);
		if (evutil_parse_sockaddr_port(host, &saddr, &len) != 0) {
			// unable to parse the detail.  What do we need to do?
			assert(0);
		}
		else {
			// create the socket, and set to non-blocking mode.
			int handle = socket(AF_INET,SOCK_STREAM,0);
			assert(handle >= 0);
			evutil_make_socket_nonblocking(handle);

			int result = connect(handle, &saddr, sizeof(saddr));
			assert(result < 0);
			assert(errno == EINPROGRESS);
	
			// create a new session (passing in -1 as a handle, so that it doesn't setup all the events)
			session_t *session = session_new(streamptr, -1);
			assert(session);
			assert(session->handle == -1);

			assert(session->usersession == NULL);
			session->usersession = basedata;
			
			session->newconn_fn = newconn_fn;
			session->connclosed_fn = connclosed_fn; 			
			
			// the session object will be created with the write_event paused, but an active read event.  
			// For the connect, we need to handle the WRITE event.  So we will add our connect_handler to it.  
			// When it is connected, then will clear that event and it wont be needed again.
			assert(stream->main_event_base);
			assert(session->connect_event == NULL);
			
// 			fprintf(stderr, "Setting Connect event.  handle=%d, sessionptr=%llx\n", handle, (long long unsigned) session);
			session->connect_event = event_new(stream->main_event_base, handle, EV_WRITE, session_connect_handler, (void *)session);
			assert(session->connect_event);
			event_add(session->connect_event, NULL);	// TODO: Should we set a timeout on the connect?
		}
	}
}


// Originally we created a new write event each time we needed to.  
// Logic has changed where now it just adds the event to the system, but dooesnt remove it.  
// Therefore cannot rely on checking if the event exists.  Must first know if there was nothing in the buffer.
// NOTE: It is possible for this function to be called before any data is in the buffer.  
static void setWriteEvent(session_t *session) 
{
	assert(session);
	assert(session->out.event != NULL);
	assert(session->handle >= 0);
	
// 	fprintf(stderr, "Setting WRITE event. handle=%d\n", session->handle);
	
	// the event is a one-off event.  If the callback is unable to send all the data in the buffer, 
	// it will add it back in to the queue again.
	
	// Note, we dont do any timeout, so we dont do any throughput throttling.
	
	// Adding the event when it is already pending, will not do anything, but we should avoid doing that if we can.  
	// At this scope though, we cant tell without querying the event system.
	event_add(session->out.event, NULL);
}





// this function is called when we have are ready to send data on a socket.   
static void session_write_handler(int hid, short flags, void *data)
{
	assert(hid >= 0);
	assert(flags & EV_WRITE);
	
	session_t *session = data;
	assert(session);
	
// 	fprintf(stderr, "session_write_handler. hid=%d, handle=%d\n", hid, session->handle);
	
	assert(session->handle == hid);
	assert(session->stream);
	
	// The WRITE event is prepared at the beginning of the sessions.  It is not set for PERSIST, 
	// so it will now be inactive.  If we do not send all the data we need to send, then we need 
	// to add this event back in to the base.
	assert(session->out.event);
	
	// we've requested the event, so we should have data to process.
	assert(session->out.buffer);
	assert(session->out.length > 0);
	assert(session->out.max >= session->out.length);
	assert(session->out.length <= session->out.max);
	
	int res = send(hid, session->out.buffer, session->out.length, 0);
	if (res > 0) {
		// we managed to send some, or maybe all....
		assert(res <= session->out.length);
		if (res == session->out.length) {	
			// we sent all of it.
			session->out.length = 0;
		}
		else {
			// we only sent some of it.
			memmove(session->out.buffer, session->out.buffer + res, session->out.length - res);
			session->out.length -= res;
			assert(session->out.length > 0);
		}
	}
	else if (res == 0) {
		session_close(session);
	}
	else {
		assert(res == -1);
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			session_close(session);
		}
	}
	
	// if we have not sent everything, then we need to set the event.
	if (session->out.length > 0) {
		setWriteEvent(session);
	}
	else {
		if (session->closing > 0) {
			session_close(session);
		}
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
	
	
	// Create the session object.
	session_t *session = session_new(stream, fd);
	assert(session);
}


// This default callback is called when a break signal is recieved.  It should trigger a shutdown of all active connections (regardless of protocol used outside of this stream).  It will simply close all connections if there is no outgoing buffer.  If there is an outgoing buffer, it will try and send what is in it before closing, but will put a timeout, and if it cant send within that time, then it will close the socket anyway.
static void default_break_cb(stream_t *stream)
{
	assert(0);
}






// Listen on a particular port (and optionally, interface), and when event soccur, call the callback functions.
// If no Interface is provided, it will attempt to listen on all interfaces.
// NOTE: an interface normally means an IP address.
//
// Returns:
//	0 - Everything was successful.
//  1 - Unable to listen on the required socket port or address.
int rispstream_listen(RISPSTREAM streamptr, char *interface, risp_cb_newconn newconn_fn, risp_cb_connclosed connclosed_fn)
{
	stream_t *stream = streamptr;
	assert(stream);
	assert(interface);
	
	stream->newconn_callback_fn = newconn_fn;
	stream->connclosed_callback_fn = connclosed_fn;
	
	struct sockaddr_in sin;
	int len;
		
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;	// currently just supporting IPv4
	len = sizeof(sin);
	
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
		event_base_loop(stream->main_event_base, 0);
		//==============================================================================================

	}
}





// This tells the stream to stop listening on whhatever ports it is listening on.
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



static void close_handler(int hid, short flags, void *data)
{
	assert(0);
}

// The client calls this to close the session.   If there is data in the buffer, it will try to send it first, and when the connection is actually closed, it will call the callback function.   In other words, this is a non-blocking operation.  If the user wants it to wait till the connection is closed before exiting, then they need to call rispsession_close_wait()
void rispsession_close(RISPSESSION sessionptr)
{
	assert(sessionptr);
	session_t *session = sessionptr;
	
	stream_t *stream = session->stream;
	assert(stream);

	// mark the session as closing.  If we dont close the session now, then it will be closed when the outbuffer is emptied.
	assert(session->closing == 0);
	session->closing = 1;

	
	assert(session->out.length >= 0);
	if (session->out.length == 0 && session->in.length == 0) {
		// the out and in buffer is empty.  We can clean it up now, and close everything.
		session_close(sessionptr);
	}
	else {
		// there must be data in one of the buffers.
		// if there is no write event pending, then we need to set a timeout event.  This means that the socket might be closed 
		// by the remote end before this event fires, so we need to handle that gracefully too.
		if (session->out.event == NULL) {
			assert(session->out.length == 0);
			
			assert(session->close_event == NULL);
			assert(stream->main_event_base);
			session->close_event = evtimer_new(stream->main_event_base, close_handler, session);
			assert(session->close_event);
			struct timeval cto = {0,100};
			evtimer_add(session->close_event, &cto);
		}
	}
}



// make sure that the buffer is large enough for the specified length.
static void maxbuf_out(session_t *session, risp_length_t length) 
{
	assert(session);
	assert(length > 0);
	
	if (session->out.length + length > session->out.max) {
		session->out.max += (session->out.length + length + 1024);
		session->out.buffer = realloc(session->out.buffer, session->out.max);
	}
}


void rispsession_send_noparam(RISPSESSION sessionptr, risp_command_t command)
{
	assert(sessionptr);
	session_t *session = sessionptr;
	assert(session);

	assert((session->out.max == 0 && session->out.buffer == NULL) || (session->out.max > 0 && session->out.buffer));
	
	// if the out-buffer is empty, we are going to need the write event submitted.  
	// It wont actually do anything with the event until the event-loop processes, 
	// so it is ok to put this at the top of the function before we actually fill the buffer.
	if (session->out.length == 0) { setWriteEvent(session); }
	
	// make sure there is enough space in the buffer for this transaction.
	maxbuf_out(session, risp_command_length(command, 0));
	assert(session->out.max > 0);
	assert(session->out.length >= 0);
	assert(session->out.buffer);

	// add the command to the buffer.
	risp_length_t len = risp_addbuf_noparam(session->out.buffer + session->out.length, command);
	assert(len > 0);
	session->out.length += len;
	assert(session->out.length > 0);
}




void rispsession_send_int(RISPSESSION sessionptr, risp_command_t command, risp_int_t value)
{
	assert(sessionptr);
	session_t *session = sessionptr;
	assert(session);

	assert((session->out.max == 0 && session->out.buffer == NULL) || (session->out.max > 0 && session->out.buffer));

	// if the out-buffer is empty, we are going to need the write event submitted.  
	// It wont actually do anything with the event until the event-loop processes, 
	// so it is ok to put this at the top of the function before we actually fill the buffer.
	if (session->out.length == 0) { setWriteEvent(session); }
	
	// make sure there is enough space in the buffer for this transaction.
	maxbuf_out(session, risp_command_length(command, 0));
	assert(session->out.max > 0);
	assert(session->out.length >= 0);
	assert(session->out.buffer);

	// add the command to the buffer.
	risp_length_t len = risp_addbuf_int(session->out.buffer + session->out.length, command, value);
	assert(len > 0);
	session->out.length += len;
	assert(session->out.length > 0);
}

void rispsession_send_str(RISPSESSION sessionptr, risp_command_t command, risp_int_t length, risp_data_t *data)
{
	assert(sessionptr);
	session_t *session = sessionptr;
	assert(session);

	assert((session->out.max == 0 && session->out.buffer == NULL) || (session->out.max > 0 && session->out.buffer));

	// if the out-buffer is empty, we are going to need the write event submitted.  
	// It wont actually do anything with the event until the event-loop processes, 
	// so it is ok to put this at the top of the function before we actually fill the buffer.
	if (session->out.length == 0) { setWriteEvent(session); }
	
	// make sure there is enough space in the buffer for this transaction.
	risp_length_t clen = risp_command_length(command, length);
	assert(clen > length);
	
	maxbuf_out(session, clen);
	assert(session->out.max >= (session->out.length + clen) );
	assert(session->out.buffer);

	// add the command to the buffer.
	risp_length_t len = risp_addbuf_str(session->out.buffer + session->out.length, command, length, data);
	assert(len > 0);
	session->out.length += len;
	assert(session->out.length > 0);
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

