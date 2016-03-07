//--------------------------------------------------------------------------------------------------
// RISP Chat Server
// Example code that demonstrate how to develop a server that communicates thru a RISP protocol.
//
// Since this example is of a server, we are utilising libevent, and will run as a daemon or a 
// standard process.  For use in docker containers, best practice is to not use daemon mode.
//--------------------------------------------------------------------------------------------------


// includes
#include <assert.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
// #include <netdb.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
// #include <sys/socket.h>
// #include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

// Include the risp library.
#include <risp64.h>

#include "daemon.h"
#include "risp_chat_prot.h"



#define PACKAGE						"risp_chat_server"
#define VERSION						"0.01"


// global constants and other things go here.
#define DEFAULT_MAXCONNS	1024
#define DEFAULT_MAXBYTES	0
#define DEFAULT_CHUNKSIZE	(1024*512)

#define INVALID_HANDLE -1

#define OPTIMAL_MAX (100000)


#define PROTOCOL_VALIDATION "RISP Server"


/* Get a consistent bool type */
#if HAVE_STDBOOL_H
# include <stdbool.h>
#else
  typedef enum {false = 0, true = 1} bool;
#endif




typedef struct {
	int port;
	int maxbytes;
	bool verbose;
	bool daemonize;
	char *username;
	char *pid_file;
	char *interface;
} settings_t;


typedef struct {
	long long msgID;
	int length;
	char *message;
} message_t;

// Keeping things simple for this excersize.  A more robust solution would need to be more scalable.
typedef struct {
	message_t **messages;
	int latest;
} messages_t;


// each connection needs to be tracked and maintained.
typedef struct {
	int handle;
	bool verbose;
	struct event_base *ev_base;
	
	struct {
		unsigned char *buffer;
		unsigned int length;
		unsigned int max;
		struct event *event;
	} in, out;
	
	risp_t *risp;

	// used to indicate that the session is closing even though there is an outgoing buffer that is 
	// being sent.  When the buffer is emptied, then the connection should then be closed.
	int closing;

	// the variables and flags that represent the data received from commands.
	struct {
		char name[256];
		bool authenticated;
		bool echo;
		bool follow;
		bool update;
	} data;
	
	void *next, *prev;
} session_t ;


typedef struct {
	int                handle;			// socket handle
	int                active;			// number of active sessions.
	int                maxconns;		// max number of sessions.
	session_t         *sessions;		// Linked list of session objects.
	struct event_base *ev_base;
	struct event      *event;				
	bool               verbose;
	risp_t            *risp;
	messages_t        *messages;		// pointer to the messages object.
} server_t;





//--------------------------------------------------------------------------------------------------
// Global variables.
struct event_base *main_event_base = NULL;
struct timeval auth_timeout = {10,0};		// timeout if new socket hasn't authenticated.


//--------------------------------------------------------------------------------------------------
// Pre-declared functions.  
static void session_write_handler(int hid, short flags, void *data);




//--------------------------------------------------------------------------------------------------
// Given an address structure, will create a socket handle and set it for non-blocking mode.
int new_socket(struct addrinfo *ai) {
	int sfd = INVALID_HANDLE;
	int flags;
	
	assert(ai != NULL);
	
	// bind the socket, and then set the socket to non-blocking mode.
	if ((sfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) >= 0) {
		if ((flags = fcntl(sfd, F_GETFL, 0)) < 0 || fcntl(sfd, F_SETFL, flags | O_NONBLOCK) < 0) {
			perror("setting O_NONBLOCK");
			close(sfd);
			sfd = INVALID_HANDLE;
		}
	}
	
	return sfd;
}



//--------------------------------------------------------------------------------------------------
// print some info to the user, so that they can know what the parameters do.
void usage(void) {
	printf(PACKAGE " " VERSION "\n");
	printf("-p <num>      TCP port to listen on (default: %d)\n", DEFAULT_PORT);
	printf("-l <ip_addr>  interface to listen on, default is INADDR_ANY\n"
			"-d            run as a daemon\n"
			"-u <username> assume identity of <username> (only when run as root)\n"
			"-v            verbose (print errors/warnings while in event loop)\n"
			"-vv           very verbose (also print client commands/reponses)\n"
			"-h            print this help and exit\n"
			"-P <file>     save PID in <file>, only used with -d option\n"
			);
	
	return;
}







//--------------------------------------------------------------------------------------------------
// Handle the signal.  Any signal we receive can only mean that we need to exit.   This sort of 
// signal should really set an event to trigger a cascading close.   However, currently we havent 
// implemented that.  We just exit abruptly.
static void sig_handler(const int sig) {
    printf("SIGINT handled.\n");
    assert(main_event_base != NULL);
    event_base_loopbreak(main_event_base);
}


//--------------------------------------------------------------------------------------------------
// ignore SIGPIPE signals; we can use errno == EPIPE if we need that information.   We can actually 
// intercept these as part of teh event system, but have not implemented that in order to reduce 
// complexity.
void ignore_sigpipe(void) {
	struct sigaction sa;
	
	sa.sa_handler = SIG_IGN;
	sa.sa_flags = 0;
	if (sigemptyset(&sa.sa_mask) == -1 || sigaction(SIGPIPE, &sa, 0) == -1) {
		perror("failed to ignore SIGPIPE; sigaction");
		exit(EXIT_FAILURE);
	}
}






//--------------------------------------------------------------------------------------------------
// this callback is called if we have an invalid command.  We shouldn't be receiving any invalid 
// commands.
void cmdInvalid(void *base, void *data)
{
	unsigned char *cast;
	cast = (unsigned char *) data;
	printf("Received invalid: [%d, %d, %d]\n", cast[0], cast[1], cast[2]);
	assert(0);
}


//--------------------------------------------------------------------------------------------------
// Do nothing.
void cmdNop(void *base) 
{
}

void session_close(session_t *session)
{
	assert(0);
}




//--------------------------------------------------------------------------------------------------
void send_HelloAck(session_t *session)
{
	// to avoid double handling of the buffer, we will simply increase the existing outbuffer if necessary, and add commands directly to it.
	// 
	
	assert(0);
}

//--------------------------------------------------------------------------------------------------
// This callback function is to be fired when the CMD_HELLO command is received.  
void cmdHello(void *base, risp_length_t length, risp_data_t *data) 
{
	// The base pointer that is passed thru the library doesnt know about the session structure we 
	// are using, so we need to make a cast-pointer for it.
 	session_t *session = (session_t *) base;
	
	// Always a good idea to put lots of asserts in your code.  It helps to 
	// capture developer mistakes that would sometimes be difficult to catch at 
	// a later date.
  	assert(session != NULL);
	
	// we've received a string as well, so we need to validate that as well.
	// This checks that we either have no data at all (which is valid), or that we do have data.  
	// If length is legitimately zero, then the data pointer should be null.
	// If this assert fires, then your COMMAND ID is probably not a valid String ID.
	assert((length > 0 && data) || (length == 0 && data == NULL));
	
	// Check if the session is already authenticated
	assert(session->data.authenticated == 0 || session->data.authenticated == 1);
	if (session->data.authenticated == 1) {
		// session has already been authenticated, and it is illegal to attempt to authenticate again.
		session_close(session);
	}
	else {
		// session was not already authenticated.
		
		// make sure the session is not closing.
		assert(session->closing == 0 || session->closing == 1);
		if (session->closing == 0) {

			int valid_len = strlen(PROTOCOL_VALIDATION);
			if (valid_len != length) {
				// the lengths of the string did not match.  Closing the session.
				session_close(session);
			}
			else {
				// the string lengths are the same.  Thats good, makes comparison easy.
				if (strncmp(PROTOCOL_VALIDATION, (char *) data, valid_len) != 0) {
					// strings dont match.   Closing teh session.
					session_close(session);
				}
				else {
					// the strings matched!!  Mark the session as valid so that we can accept 
					// additional commands.
					
					// Indicate that session is now authenticated.
					assert(session->data.authenticated == 0);
					session->data.authenticated = 1;

					// since this authentication should happen before any other data is given, we 
					// should check that everything else is in a init state.
					assert(session->data.name[0] == '\0');
					
					// We reply with a HELLO_ACK
					send_HelloAck(session);
				}
			}
		}
	}
}



//--------------------------------------------------------------------------------------------------
// Before processing commands received for a session, first need to check that the session is in a 
// state where we should be processing requests (authenticated, not in a closing state, etc).   
// If this command is run on a session that is not authenticated, then it will initiate a close.  
// 
// ONLY CALL THIS FUNCTION IF YOU EXPECT THE SESSION TO BE AUTHENTICATED AND EXPECT IT WILL BE 
// CLOSED IF NOT.
static bool checkAuth(session_t *session) 
{
	bool ok = false;
	
	// Always a good idea to put lots of asserts in your code.  It helps to 
	// capture developer mistakes that would sometimes be difficult to catch at 
	// a later date.
  	assert(session);
	
	// Check if the session is already authenticated
	assert(session->data.authenticated == true || session->data.authenticated == false);
	if (session->data.authenticated == false) {
		// session has not been authenticated, and it is illegal to attempt to operations without 
		// authenticating first..
		session_close(session);
		assert(ok == false);
	}
	else {
		// session was authenticated.
		
		// make sure the session is not closing.
		assert(session->closing == 0 || session->closing == 1);
		if (session->closing > 0) {
			// session is closing.  Could mean developer is using the protocol incorrectly, or invalid data.
			// assert if in debug mode, otherwise, do nothing.
			assert(0);
			assert(ok == false);
		}
		else {
			ok = true;
		}
	}

	return(ok);
}


//--------------------------------------------------------------------------------------------------
// This callback function is called when the CMD_GOODBYE command is received.  It will close the 
// session.
void cmdGoodbye(void *base) 
{
	session_t *session = (session_t *) base;
	assert(session);

	printf("Received GOODBYE from [%d]\n", session->handle);
	
	session_close(session);
}



//--------------------------------------------------------------------------------------------------
// This callback function is to be fired when the CMD_ECHO command is received.  This will turn on 
// the functionality (that is off by default) that echo's commands back to the client that sent the 
// message.  By default clients dont receive the commands they send.
void cmdEcho(void *base) 
{
	// The base pointer that is passed thru the library doesnt know about the session structure we 
	// are using, so we need to make a cast-pointer for it.
	session_t *session = (session_t *) base;
	assert(session);

	printf("Received ECHO from [%d]\n", session->handle);

	if (checkAuth(session) == true) {
		// session is not closing.
		session->data.echo = true;
	}
}



//--------------------------------------------------------------------------------------------------
// This callback function is to be fired when the CMD_NOECHO command is received.  This will put the 
// session in a mode where it does NOT echo the messages received back to the client that sent the 
// message.  This turns off the echo functionality.
void cmdNoEcho(void *base) 
{
	// The base pointer that is passed thru the library doesnt know about the session structure we 
	// are using, so we need to make a cast-pointer for it.
 	session_t *session = (session_t *) base;
	assert(session);
	
	printf("Received NO_ECHO from [%d]\n", session->handle);
	
	if (checkAuth(session) == true) {
		// remove the echo flag.
		session->data.echo = false;
	}
}



//--------------------------------------------------------------------------------------------------
// This callback function is to be fired when the CMD_FOLLOW command is received.  This will put the 
// session in a mode where it automatically sends the details of a message to the client.
void cmdFollow(void *base) 
{
	// The base pointer that is passed thru the library doesnt know about the session structure we 
	// are using, so we need to make a cast-pointer for it.
 	session_t *session = (session_t *) base;
	assert(session);
		
	printf("Received FOLLOW from [%d]\n", session->handle);
	
	if (checkAuth(session) == true) {
		// set the 'follow'  flags.
		session->data.follow = true;
		session->data.update = true;
	}
}



//--------------------------------------------------------------------------------------------------
// Puts the session in NoFollow mode (the default).  When new messages are received from other 
// clients, it will not send the details to the client, but will send a message updating the 
// LATEST_ID.
void cmdNoFollow(void *base) 
{
	// The base pointer that is passed thru the library doesnt know about the session structure we 
	// are using, so we need to make a cast-pointer for it.
	session_t *session = (session_t *) base;
	assert(session);
	
	printf("Received NO_FOLLOW from [%d]\n", session->handle);
	
	if (checkAuth(session) == true) {
		// remove the follow flag.
		session->data.follow = false;
	}
}


//--------------------------------------------------------------------------------------------------
// Puts session in a mode where the client is not notified when other messages are ready to send.  
// Used in situations where the client is not concerned about receiving messages, or would rather 
// poll for it.
void cmdNoUpdate(void *base) 
{
	// The base pointer that is passed thru the library doesnt know about the session structure we 
	// are using, so we need to make a cast-pointer for it.
	session_t *session = (session_t *) base;
	assert(session);
	
	printf("Received NO_UPDATE from [%d]\n", session->handle);
	
	if (checkAuth(session) == true) {
		// remove the update flag.
		session->data.follow = false;
		session->data.update = false;
	}
}





// client is asking to know the latest msg ID that is available.
void cmdGetLatestMsgID(void *base, risp_int_t value)
{
	// The base pointer that is passed thru the library doesnt know about the session structure we 
	// are using, so we need to make a cast-pointer for it.
	session_t *session = (session_t *) base;
	assert(session);
	
	printf("Received CMD_GET_LATEST_MSG_ID(%ld) from [%d]\n", value, session->handle);
	
	if (checkAuth(session) == true) {
		assert(0);
	}
}



void cmdSendMsg(void *base, risp_int_t value)
{
	// The base pointer that is passed thru the library doesnt know about the session structure we 
	// are using, so we need to make a cast-pointer for it.
	session_t *session = (session_t *) base;
	assert(session);
	
	printf("Received CMD_SEND_MSG(%ld) from [%d]\n", value, session->handle);
	
	if (checkAuth(session) == true) {
		assert(0);
	}
}



void cmdSendSince(void *base, risp_int_t value)
{
	// The base pointer that is passed thru the library doesnt know about the session structure we 
	// are using, so we need to make a cast-pointer for it.
	session_t *session = (session_t *) base;
	assert(session);
	
	printf("Received CMD_SEND_SINCE(%ld) from [%d]\n", value, session->handle);
	
	if (checkAuth(session) == true) {
		assert(0);
	}
}








// the name is stored so that when it relays a message, it can indicate who it was from.
void cmdName(void *base, risp_length_t length, risp_data_t *data) 
{
	// At every opportunity, we need to make sure that our data is legit.
	assert(base != NULL);
	assert(length >= 0);
	assert(data != NULL);
	
	// the protocol allows a name up to 255 chars in length. 
	assert(length < 256);

	// The base pointer that is passed thru the library doesnt know about the session structure we 
	// are using, so we need to make a cast-pointer for it.
 	session_t *session = (session_t *) base;
  	assert(session);
	
	printf("Received NAME from [%d]\n", session->handle);
	
	if (checkAuth(session) == true) {
		// copy the string that was provides from the stream (which is guaranteed to be complete)
		assert(length < 256);
		memcpy(session->data.name, data, length);
		session->data.name[length] = '\0';	// null-terminate it to make it easier to manipulate.
	}
}


void cmdMessage(void *base, risp_length_t length, risp_data_t *data) 
{
	session_t *session = (session_t *) base;
	
	// At every opportunity, we need to make sure that our data is legit.
	assert(base != NULL);
	assert(length >= 0);
	assert(data != NULL);
	
	// the protocol allows a message up to 64k chars in length. 
	assert(length < 65536);

	if (checkAuth(session) == true) {

		// need to relay the message to each client that is connected (other than this one, unless it has echo enabled).
		assert(0);
	}
}



void cmdIllegal(void *base)
{
	// we have received a command that we should not be receiving (ie, one that should only be received by the client, not the the server).
	assert(0);
	
	
	session_t *session = (session_t *) base;
	session_close(session);
}




//--------------------------------------------------------------------------------------------------
// allocate space off the heap for a new struct.  clear and initialise it with the new handle.
session_t * session_new(void)
{
	session_t *session  = (session_t *) malloc(sizeof(session_t));
	assert(session);
		
	session->risp = NULL;

	session->next = NULL;
	session->prev = NULL;

	session->in.buffer = NULL;
	session->in.length = 0;
	session->in.max = 0;
	session->in.event = NULL;
	session->out.buffer = NULL;
	session->out.length = 0;
	session->out.max = 0;
	session->out.event = NULL;
	
	session->handle = INVALID_HANDLE;
	
	session->data.name[0] = 0;
	session->data.echo = 0;
	session->data.follow = 0;
	session->data.update = 0;
	session->data.authenticated = 0;
	
	session->closing = 0;
	
	return(session);
}




//--------------------------------------------------------------------------------------------------
// this function is called when we have received a new socket.   We need to create a new session, 
// and add it to our session list.  We need to pass to the session any pointers to other sub-systems 
// that it will need to have, and then we insert the session into the 'session-circle' somewhere.  
// Finally, we need to add the new session to the event base.
static void session_read_handler(int hid, short flags, void *data)
{
	assert(hid >= 0);
	
	session_t *session = (session_t *) data;
	assert(session != NULL);
	
	assert(session->handle == hid);
	assert(session->ev_base != NULL);
	
	if (flags & EV_TIMEOUT) {
		// the socket has not received activity within the timeout period.  If we havent 
		// authenticated by now, then we need to close the socket.  
		assert(0);
		session_close(session);
		
		// if the timeout occured, then the READ flag should not be set.
		assert((flags & EV_READ) == 0);
	}
	
	
	if (flags & EV_READ) {
	
		unsigned int avail = session->in.max - session->in.length;
		if (avail < DEFAULT_CHUNKSIZE) {
			session->in.max += DEFAULT_CHUNKSIZE;
			session->in.buffer = (unsigned char *) realloc(session->in.buffer, session->in.max);
			avail = session->in.max - session->in.length;
		}
 		assert(avail >= DEFAULT_CHUNKSIZE);
	
		int res = read(hid, session->in.buffer + session->in.length, avail);
		if (res > 0) {
			session->in.length += res;
			assert(session->in.length <= session->in.max);

			// if we pulled out the max we had avail in our buffer, that means we can pull out more at a time.
			if (res == avail) {
				session->in.max += DEFAULT_CHUNKSIZE;
				session->in.buffer = (unsigned char *) realloc(session->in.buffer, session->in.max);
			}

		}
		else if (res == 0) {
			session_close(session);
			printf("Session[%d] closed while reading.\n", hid);
		}
		else {
			assert(res == -1);
			if (errno != EAGAIN && errno != EWOULDBLOCK) {
				session_close(session);
				printf("Session[%d] closed while reading- because of error: %d\n", hid, errno);
			}
		}
		
		if ((session->closing == 0) && (session->in.length > 0)) {
			
			assert(session->risp != NULL);
			assert(session->in.length <= session->in.max);
			assert(session->in.length > 0);
			
			res = risp_process(session->risp, session, session->in.length, session->in.buffer);
			assert(res <= session->in.length);
			assert(res >= 0);
			if (res < session->in.length) {
				// to ensure that we dont run out of memory, the partial system is not suitable when large volumes of data is being sent.
				avail = session->in.length - res;
				memmove(session->in.buffer, session->in.buffer + res, avail);
				session->in.length -= res;
			}
			else {
				session->in.length = 0;
			}
		}
		else {
			// need to close the connection now that all the output has been sent.
			assert(0);
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
			printf("shrunk inbuffer [len=%d, max=%d]\n", session->in.length, session->in.max);
			session->in.max = session->in.length;
		}
 	}
}


void setWriteEvent(session_t *session) 
{
	assert(session);
	assert(session->ev_base);
	assert(session->out.event == NULL);
	assert(session->handle >= 0);
	
	// the event is a one-off event.  If the callback is unable to send all the data in the buffer, 
	// it will add it back in to the queue again.
	session->out.event = event_new(session->ev_base, session->handle, EV_WRITE, session_write_handler, (void *)session);
	assert(session->out.event);
	event_add(session->out.event, 0);
}


// this function is called when we have received a new socket.   We need to 
// create a new session, and add it to our session list.  We need to pass to the session 
// any pointers to other sub-systems that it will need to have, and then we 
// insert the session into the 'session-circle' somewhere.  Finally, we need to add 
// the new session to the event base.
static void session_write_handler(int hid, short flags, void *data)
{
	assert(hid >= 0);
	assert(flags & EV_WRITE);
	
	session_t *session = (session_t *) data;
	assert(session);
	
	assert(session->handle == hid);
	assert(session->ev_base);
	
	// we've requested the event, so we should have data to process.
	assert(session->out.buffer != NULL);
	assert(session->out.length > 0);
	assert(session->out.max > 0);
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
		printf("Session[%d] closed while writing.\n", hid);
	}
	else {
		assert(res == -1);
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			session_close(session);
			printf("Session[%d] closed while writing - because of error: %d\n", hid, errno);
		}
	}
	
	// if we have not sent everything, then we dont need create a new event.
	if (session->out.length == 0) {
		setWriteEvent(session);
	}
	
// 	if (session->out_partial > OPTIMAL_PARTIAL) {
		//////
// 	}
}




void save_pid(const pid_t pid, const char *pid_file) {
	FILE *fp;
	
	assert(pid_file != NULL);
	assert(pid > 1);
	
	if ((fp = fopen(pid_file, "w")) == NULL) {
		fprintf(stderr, "Could not open the pid file %s for writing\n", pid_file);
		return;
	}
	
	fprintf(fp,"%ld\n", (long)pid);
	if (fclose(fp) == -1) {
		fprintf(stderr, "Could not close the pid file %s.\n", pid_file);
		return;
	}
}

void remove_pidfile(const char *pid_file) {
  assert(pid_file != NULL);
  
  if (unlink(pid_file) != 0) {
		fprintf(stderr, "Could not remove the pid file %s.\n", pid_file);
  }
}



// lose root privileges if we have them
int drop_privs(char *username)
{
	struct passwd *pw;
	
	assert(username != NULL);
	assert(username[0] != '\0');
  
	if (getuid() == 0 || geteuid() == 0) {
		if (username == 0 || *username == '\0') {
			fprintf(stderr, "can't run as root without the -u switch\n");
			return 1;
		}
		if ((pw = getpwnam(username)) == 0) {
			fprintf(stderr, "can't find the user %s to switch to\n", username);
			return 1;
		}
		if (setgid(pw->pw_gid) < 0 || setuid(pw->pw_uid) < 0) {
			fprintf(stderr, "failed to assume identity of user %s\n", username);
			return 1;
		}
	}
	return(0);
}





//--------------------------------------------------------------------------------------------------
// Initialise and return a server struct that we will use to control the sessions that we are 
// connected to.   We will bind the listening port on the socket.
//
//	** Will we ever need to listen on more than one port?  How will we add that to the system?   
//	   Currently, wont bother with it, but will include a 'next' pointer so that we can have a list 
//	   of listeners.  The problem will be with our list of sessions.  All the servers would need to 
//	   share the sessions list, and various other shared resources.  This could be a little 
//	   cumbersome, but possible.
//
//
server_t *server_new(int port, char *address)
{
	assert(port > 0);
	assert(address == NULL || (address != NULL && address[0] != '\0'));
	
	struct addrinfo hints;
	memset(&hints, 0, sizeof (hints));

	hints.ai_flags = AI_PASSIVE|AI_ADDRCONFIG;
	hints.ai_family = AF_INET;	// currently just supporting IPv4
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_socktype = SOCK_STREAM;

	char port_buf[NI_MAXSERV];
	struct addrinfo *ai;
	snprintf(port_buf, NI_MAXSERV, "%d", port);
	int error = getaddrinfo(address, port_buf, &hints, &ai);
	if (error != 0) {
		if (error != EAI_SYSTEM)
			fprintf(stderr, "getaddrinfo(): %s\n", gai_strerror(error));
		else
			perror("getaddrinfo()");
		return(NULL);
	}

	int sfd = INVALID_HANDLE;

	struct addrinfo *next;
	for (next= ai; next; next=next->ai_next) {
	
		assert(sfd == INVALID_HANDLE);
	
		// create the new socket.  if that fails, free the memory we've already allocated, and return NULL.
		sfd = new_socket(next);
		if (sfd == INVALID_HANDLE) {
			freeaddrinfo(ai);
			return(NULL);
		}

		int flags =1;
		struct linger ling = {0, 0};
		setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, (void *)&flags, sizeof(flags));
		setsockopt(sfd, SOL_SOCKET, SO_KEEPALIVE, (void *)&flags, sizeof(flags));
		setsockopt(sfd, SOL_SOCKET, SO_LINGER, (void *)&ling, sizeof(ling));
// 		setsockopt(sfd, IPPROTO_TCP, TCP_NODELAY, (void *)&flags, sizeof(flags));

		if (bind(sfd, next->ai_addr, next->ai_addrlen) == -1) {
			if (errno != EADDRINUSE) {
				perror("bind()");
				close(sfd);
				freeaddrinfo(ai);
				return(NULL);
			}
            
			close(sfd);
			sfd = INVALID_HANDLE;
			continue;
		} else {
			if (listen(sfd, 1024) == -1) {
				perror("listen()");
				close(sfd);
				freeaddrinfo(ai);
				return(NULL);
			}
		}
	}
    
	freeaddrinfo(ai);

	server_t *server = (server_t *) calloc(1, sizeof(server_t));
	assert(server != NULL);
	
	server->handle = sfd;
	server->risp = NULL;
	server->verbose = false;
	server->sessions = NULL;
	server->ev_base = NULL;
	server->messages = NULL;

	return(server);
}


//----------------------------------------------------------------------------------------------------------------------------------------
// this function is called when we have received a new socket.   We need to create a new session, and add it to our session list.  We need 
// to pass to the session any pointers to other sub-systems that it will need to have, and then we insert the session into the 
// 'session-circle' somewhere.  Finally, we need to add the new session socket to the event base so we can know when data is received..
static void server_event_handler(int hid, short flags, void *data)
{
	
	assert(hid >= 0);
	assert(data != NULL);
	
	server_t *server = (server_t *) data;
	assert(server->handle == hid);

	struct sockaddr_storage addr;
	socklen_t addrlen = sizeof(addr);
	int sfd = accept(hid, (struct sockaddr *)&addr, &addrlen);
	if (sfd == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
				/* these are transient, so don't log anything */
		} else if (errno == EMFILE) {
			if (server->verbose > 0)
					fprintf(stderr, "Too many open connections\n");
// 			accept_new_conns(false);
		} else {
			perror("accept()");
		}
	}
	
	// mark socket as non-blocking.  Since we are using events, this is not necessary.  Including it 
	// because it can assist if things have changed between the time the event was fired, and the 
	// callback attempts to pull the data.
	if ((flags = fcntl(sfd, F_GETFL, 0)) < 0 || fcntl(sfd, F_SETFL, flags | O_NONBLOCK) < 0) {
		perror("setting O_NONBLOCK");
		close(sfd);
	}

	printf("New Connection [%d]\n", sfd);

	// Create the session object.
	printf("Creating a new session\n");
	session_t *session = session_new();
	assert(session);
	
	// we should definately have a socket handle at this point.
	assert(sfd >= 0);
	session->handle = sfd;
	
	session->verbose = server->verbose;

	// set the event base.
	assert(server->ev_base);
	session->ev_base = server->ev_base;
	
	// For this particular protocol, we use a single RISP processor, as the protocol is the same 
	// under all contexts.
	assert(server->risp != NULL);
	session->risp = server->risp;

	// The sessions are kept in a linked list.  Each session has a 'next' and 'prev' pointer.  
	// These are cast as void pointers, so you need to be quite specific in your usage of them.
	// We have a pointer to the head of the list in the server object.

	// This session will end up at the top of the list, so it will have a NULL 'prev' pointer, and 
	// the 'next' will point to what is currently the head.
	session->prev = NULL;
	session->next = server->sessions;

	// if we already have a session at the head of the list, we need to make sure it points back to 
	// this new one.
	if (server->sessions) {
		session_t *tmp = server->sessions;
		assert(tmp->prev == NULL);
		tmp->prev = session;
	}
	
	
	// setup the event handling...  Create the persistent event, and activate it.
	// we set it with a ten-second timeou
	assert(session->in.event == NULL);
	assert(session->ev_base);
	session->in.event = event_new(session->ev_base, session->handle, EV_TIMEOUT | EV_READ | EV_PERSIST, session_read_handler, (void *)session);
	event_add(session->in.event, &auth_timeout);
}



//--------------------------------------------------------------------------------------------------
// This function is called as a callback from the event system whenever a new socket connection has 
// been made against the listener socket.
void server_add_eventbase(server_t *server, struct event_base *evbase)
{
	assert(server != NULL);
	assert(evbase != NULL);
	
	// the server socket should already be listening for incoming connections.+
	assert(server->handle >= 0);
	
	// the event_base should not have been set yet.  We'll add it now.  There is no reason for this 
	// function to be called again.
	assert(server->ev_base == NULL);
	server->ev_base = evbase;

	// set the event so that when a new connection comes in on the listening socket, it will call 
	// the callback function, server_event_handler().
	assert(server->event == NULL);
	server->event = event_new(server->ev_base, server->handle, (EV_READ | EV_PERSIST), server_event_handler, (void *)server);
	assert(server->event);
	event_add(server->event, NULL);
}



settings_t * settings_new(void)
{
	settings_t *ptr;
	ptr = (settings_t *) malloc(sizeof(settings_t));
	assert(ptr != NULL);

	ptr->port = DEFAULT_PORT;
	ptr->verbose = false;
	ptr->daemonize = false;
	ptr->username = NULL;
	ptr->pid_file = NULL;
	ptr->interface = NULL;

	return(ptr);
}


void settings_cleanup(settings_t *ptr) 
{
	assert(ptr != NULL);
	free(ptr);
}



static messages_t * messages_new(void)
{
	messages_t *messages = calloc(1, sizeof(messages_t));
	assert(messages->messages == NULL);
	assert(messages->latest == 0);
	
	return(messages);
}



//-----------------------------------------------------------------------------
// Main... process command line parameters, and then setup our listening 
// sockets and event loop.
int main(int argc, char **argv) 
{
	
	// handle SIGINT 
	signal(SIGINT, sig_handler);
	
	// init settings
	settings_t *settings = settings_new();
	assert(settings != NULL);

	// set stderr non-buffering (for running under, say, daemontools)
	setbuf(stderr, NULL);

	// process arguments 
	/// Need to check the options in here, there're possibly ones that we dont need.
	int c;
	while ((c = getopt(argc, argv, "p:hrvd:u:P:l:")) != -1) {
		switch (c) {
			case 'p':
				settings->port = atoi(optarg);
				assert(settings->port > 0);
				break;
			case 'h':
				usage();
				exit(EXIT_SUCCESS);
			case 'v':
				settings->verbose++;
				break;
			case 'd':
				assert(settings->daemonize == false);
				settings->daemonize = true;
				break;
			case 'u':
				assert(settings->username == NULL);
				settings->username = optarg;
				assert(settings->username != NULL);
				assert(settings->username[0] != '\0');
				break;
			case 'P':
				assert(settings->pid_file == NULL);
				settings->pid_file = optarg;
				assert(settings->pid_file != NULL);
				assert(settings->pid_file[0] != '\0');
				break;
			case 'l':
				assert(settings->interface == NULL);
				settings->interface = strdup(optarg);
				assert(settings->interface != NULL);
				assert(settings->interface[0] != '\0');
				break;
				
			default:
				fprintf(stderr, "Illegal argument \"%c\"\n", c);
				return 1;
		}
	}

	if (settings->verbose) printf("Finished processing command-line args\n");

	// if we are supplied with a username, drop privs to it.  This will only 
	// work if we are running as root, and is really only needed when running as 
	// a daemon.
	if (settings->username != NULL) {
		if (settings->verbose) printf("Dropping privs and changing username: '%s'\n", settings->username);
		if (drop_privs(settings->username) != 0) {
			usage();
			exit(EXIT_FAILURE);
		}
	}

	// daemonize if requested
	// if we want to ensure our ability to dump core, don't chdir to /
	if (settings->daemonize) {
		int res;
		if (settings->verbose) printf("Daemonising\n");
		res = daemon(0, settings->verbose);
		if (res == -1) {
			fprintf(stderr, "failed to daemon() in order to daemonize\n");
			exit(EXIT_FAILURE);
		}
	}

	// initialize main thread libevent instance
	if (settings->verbose) printf("Initialising the event system.\n");
	main_event_base = event_base_new();

	// SIGPIPE interrupts will occur if the socket on the other end is closed before we have finished reading the data that was buffered 
	// for it.  This is necessary for instances where a client connects, sends some commands, and then closes the connection before we 
	// have a chance to process the data.
	if (settings->verbose) printf("Ignoring SIGPIPE interrupts\n");
	ignore_sigpipe();
    
	// save the PID in if we're a daemon, do this after thread_init due to a 
	// file descriptor handling bug somewhere in libevent
	if (settings->daemonize && settings->pid_file) {
		if (settings->verbose) printf("Saving PID file: %s\n", settings->pid_file);
		save_pid(getpid(), settings->pid_file);
	}
       
	// create and init the 'server' structure.
	if (settings->verbose) printf("Starting server listener on port %d.\n", settings->port);
	server_t *server = server_new(settings->port, settings->interface);
	if (server == NULL) {
		if (settings->verbose) printf("Failed to listen on port %d\n", settings->port);
		fprintf(stderr, "Failed to listen on port %d\n", settings->port);
		exit(EXIT_FAILURE);
	}
	assert(server);
	server->verbose = settings->verbose;
	
	assert(server);
	assert(server->messages == NULL);
	server->messages = messages_new();
	assert(server->messages);
	
	// add the server to the event base
	assert(main_event_base != NULL);
	server_add_eventbase(server, main_event_base);

	// Initialise the risp system.
	risp_t *risp = risp_init(NULL);
	assert(risp);
	risp_add_invalid(risp, cmdInvalid);
	risp_add_command(risp, CMD_NOP, 				&cmdNop);
	risp_add_command(risp, CMD_HELLO,				&cmdHello);
	risp_add_command(risp, CMD_GOODBYE,				&cmdGoodbye);
	risp_add_command(risp, CMD_ECHO,				&cmdEcho);
	risp_add_command(risp, CMD_NOECHO,				&cmdNoEcho);
	risp_add_command(risp, CMD_FOLLOW,				&cmdFollow);
	risp_add_command(risp, CMD_NOFOLLOW,			&cmdNoFollow);
	risp_add_command(risp, CMD_NOUPDATE,			&cmdNoUpdate);
	risp_add_command(risp, CMD_GET_LATEST_MDG_ID,	&cmdGetLatestMsgID);
	risp_add_command(risp, CMD_SEND_MSG,			&cmdSendMsg);
	risp_add_command(risp, CMD_SEND_SINCE,			&cmdSendSince);
	risp_add_command(risp, CMD_NAME,				&cmdName);
	risp_add_command(risp, CMD_MESSAGE,				&cmdMessage);
	
	// there are some commands that are illegal to be received from the client.  If we receive them, 
	// then we should close the session
	risp_add_command(risp, CMD_HELLO_ACK,			&cmdIllegal);
	risp_add_command(risp, CMD_MSG_ID,				&cmdIllegal);
	risp_add_command(risp, CMD_LATEST_MSG_ID,		&cmdIllegal);
	
	assert(server->risp == NULL);
	server->risp = risp;

	//==============================================================================================
	// enter the event loop.  This will continue to run until the shutdown process has closed off 
	// all the active events.
	if (settings->verbose) printf("Starting Event Loop\n\n");
	event_base_loop(main_event_base, 0);
	//==============================================================================================
    
	// cleanup risp library.
	assert(risp);
	risp_shutdown(risp);
	risp = NULL;
    
	// cleanup 'server', which should cleanup all the 'sessions'
    
	if (settings->verbose) printf("\n\nExiting.\n");
    
	// remove the PID file if we're a daemon
	if (settings->daemonize && settings->pid_file != NULL) {
		if (settings->verbose) printf("Removing pid file: %s\n", settings->pid_file);
		remove_pidfile(settings->pid_file);
	}

	assert(settings);
	settings_cleanup(settings);
	settings = NULL;

	return 0;
}

