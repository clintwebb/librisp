//-----------------------------------------------------------------------------
// RISP Server
// Example code that demonstrate how to develop a server that communicates thru 
// a RISP protocol.
//-----------------------------------------------------------------------------


// includes
#include <assert.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <netdb.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <risp.h>

#include "daemon.h"
#include "risp_server_prot.h"



#define PACKAGE						"risp_server"
#define VERSION						"1.0"


// global constants and other things go here.
#define DEFAULT_MAXCONNS	1024
#define DEFAULT_MAXBYTES	0
#define DEFAULT_CHUNKSIZE	(1024*512)

#define INVALID_HANDLE -1

#define OPTIMAL_MAX (1024 * 1024)


/* Get a consistent bool type */
#if HAVE_STDBOOL_H
# include <stdbool.h>
#else
  typedef enum {false = 0, true = 1} bool;
#endif




typedef struct {
	int port;
	int maxconns;
	int maxbytes;
	bool verbose;
  bool daemonize;
  char *username;
  char *pid_file;
  char *interface;
} settings_t;

typedef struct {
	unsigned int out_bytes;
	unsigned int in_bytes;
	unsigned int commands;
	unsigned int operations;
	unsigned int maxbuf;
	unsigned int meml;
	unsigned int cycles;
	unsigned int undone;
} stats_t;

typedef struct {
	int handle;
	struct event event;
	bool active;
	bool verbose;
	
	unsigned char *in_buffer, *out_buffer;
	unsigned int in_buffer_len, out_buffer_len;
	unsigned int in_buffer_max, out_buffer_max;
	
	stats_t *stats;
	risp_t  *risp;
	
	// the variables and flags that represent the data received from commands.
	char url[256];
	int ttl;
	
	void *next, *prev;
} node_t ;


typedef struct {
	int                handle;			// socket handle
	int                active;			// number of active nodes.
	int                maxconns;		// max number of nodes.
	node_t           **nodes;				// array of node objects.
  struct event       event;				
  bool               verbose;
  stats_t           *stats;
	risp_t            *risp;
  void              *next;
} server_t;



typedef struct {
	struct event       clockevent;
//	struct event_base *base;
	server_t          *server;
	stats_t           *stats;
} timeout_t;






//-----------------------------------------------------------------------------
// Global variables.
struct event_base *main_event_base = NULL;



//-----------------------------------------------------------------------------
// Since we will be limiting the number of connections we have, we will want to 
// make sure that the required number of file handles are avaialable.  For a 
// 'server', the default number of file handles per process might not be 
// 'enough, and this function will attempt to increase them, if necessary.
void set_maxconns(int maxconns) 
{
	struct rlimit rlim;
	
	assert(maxconns > 5);

	if (getrlimit(RLIMIT_NOFILE, &rlim) != 0) {
		fprintf(stderr, "failed to getrlimit number of files\n");
		exit(1);
	} else {
	
		// we need to allocate twice as many handles because we may be receiving data from a file for each node.
		if (rlim.rlim_cur < maxconns)
			rlim.rlim_cur = (2 * maxconns) + 3;
			
		if (rlim.rlim_max < rlim.rlim_cur)
			rlim.rlim_max = rlim.rlim_cur;
		if (setrlimit(RLIMIT_NOFILE, &rlim) != 0) {
			fprintf(stderr, "failed to set rlimit for open files. Try running as root or requesting smaller maxconns value.\n");
			exit(1);
		}
	}
}

//-----------------------------------------------------------------------------
// Given an address structure, will create a socket handle and set it for 
// non-blocking mode.
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



//-----------------------------------------------------------------------------
// print some info to the user, so that they can know what the parameters do.
void usage(void) {
	printf(PACKAGE " " VERSION "\n");
	printf("-p <num>      TCP port to listen on (default: %d)\n", DEFAULT_PORT);
	printf("-l <ip_addr>  interface to listen on, default is INDRR_ANY\n"
					"-d            run as a daemon\n"
					"-u <username> assume identity of <username> (only when run as root)\n"
					"-k <num>      bandwidth limit.\n"
					"-c <num>      max simultaneous connections, default is 1024\n"
					"-v            verbose (print errors/warnings while in event loop)\n"
					"-vv           very verbose (also print client commands/reponses)\n"
					"-h            print this help and exit\n"
					"-P <file>     save PID in <file>, only used with -d option\n"
					);
	
	return;
}







//-----------------------------------------------------------------------------
// Handle the signal.  Any signal we receive can only mean that we need to exit.
static void sig_handler(const int sig) {
    printf("SIGINT handled.\n");
    assert(main_event_base != NULL);
    event_base_loopbreak(main_event_base);
}


//-----------------------------------------------------------------------------
// ignore SIGPIPE signals; we can use errno == EPIPE if we need that information
void ignore_sigpipe(void) {
	struct sigaction sa;
	
	sa.sa_handler = SIG_IGN;
	sa.sa_flags = 0;
	if (sigemptyset(&sa.sa_mask) == -1 || sigaction(SIGPIPE, &sa, 0) == -1) {
			perror("failed to ignore SIGPIPE; sigaction");
			exit(EXIT_FAILURE);
	}
}





void cmdNop(void *base) 
{
	node_t *ptr = (node_t *) base;
	ptr->stats->commands ++;
}

void cmdInvalid(void *base, void *data)
{
	// this callback is called if we have an invalid command.  We shouldn't be receiving any invalid commands.
	unsigned char *cast;
	cast = (unsigned char *) data;
	printf("Received invalid: [%d, %d, %d]\n", cast[0], cast[1], cast[2]);
	assert(0);
}

// This callback function is to be fired when the CMD_CLEAR command is 
// received.  It should clear off any data received and stored in variables 
// and flags.  In otherwords, after this is executed, the node structure 
// should be in a predictable state.
void cmdClear(void *base) 
{
	// The base pointer that is passed thru the library doesnt know about the 
	// node structure we are using, so we need to make a cast-pointer for it.
	node_t *ptr = (node_t *) base;
	
	// Always a good idea to put lots of asserts in your code.  It helps to 
	// capture developer mistakes that would sometimes be difficult to catch at 
	// a later date.
 	assert(ptr != NULL);
	
	// Now we clear off our protocol specific variables and flags.
	ptr->url[0] = '\0';
	ptr->ttl = 0;
	
 	assert(ptr->stats != NULL);
	ptr->stats->commands ++;
}


// This callback function is called when the CMD_EXECUTE command is received.  
// It should look at the data received so far, and figure out what operation 
// needs to be done on that data.  Since this is a simulation, and our 
// protocol doesn't really do anything useful, we will not really do much in 
// this example.   
void cmdExecute(void *base) 
{
	node_t *ptr = (node_t *) base;
 	assert(ptr != NULL);
	
 	assert(ptr->stats != NULL);
	ptr->stats->operations ++;
	ptr->stats->commands ++;

	// All we can do really in this exercise is to print out the values that we have.
//  	printf("Execute!  (url: '%s', ttl: %d)\n", ptr->url, ptr->ttl);
}

// This callback function is fired when we receive the CMD_URL command.  We 
// dont need to actually do anything productive with this, other than storing 
// the information into some internal variable.
void cmdURL(void *base, risp_length_t length, risp_char_t *data) 
{
	node_t *ptr = (node_t *) base;
	
	// At every opportunity, we need to make sure that our data is legit.
	assert(base != NULL);
	assert(length >= 0);
	assert(data != NULL);
	assert(length < 256);

	// copy the string that was provides from the stream (which is guaranteed to 
	// be complete)
	memcpy(ptr->url, data, length);
	ptr->url[length] = '\0';

	assert(ptr->stats != NULL);
	ptr->stats->commands ++;
}

void cmdTtl(void *base, risp_int_t value) 
{
	node_t *ptr = (node_t *) base;
	assert(base != NULL);
	assert(value >= 0 && value < 256);
	
	ptr->ttl = value;
		
	assert(ptr->stats != NULL);
	ptr->stats->commands ++;
}





// used to clear a previously valid node.
void node_clear(node_t *node)
{
	assert(node != NULL);
	
	if (node->active == true) {
		assert(node->event.ev_base != NULL);
		event_del(&node->event);
	}
	
	node->handle = INVALID_HANDLE;
	memset(&node->event, 0, sizeof(node->event));
	node->active = false;
	
	assert(node->out_buffer_max >= node->out_buffer_len);
	assert(node->in_buffer_max >= node->in_buffer_len);
	assert((node->in_buffer == NULL && node->in_buffer_len == 0) || (node->in_buffer != NULL && node->in_buffer_len >= 0));
	assert((node->out_buffer == NULL && node->out_buffer_len == 0) || (node->out_buffer != NULL && node->out_buffer_len >= 0));
		
	if (node->in_buffer != NULL) { free(node->in_buffer); }
	if (node->out_buffer != NULL) { free(node->out_buffer); }
	
	node->in_buffer = NULL;
	node->in_buffer_len = 0;
	node->in_buffer_max = 0;
	
	node->out_buffer = NULL;
	node->out_buffer_len = 0;
	node->out_buffer_max = 0;
}



// used to initialise an invalid node structure.  The values currently in the 
// structure are unknown.   We will assign a handle, because the only time we 
// ever need to initiate a newly created struct is when we have received a 
// socket, and the
void node_init(node_t *node)
{
	assert(node != NULL);
	node_clear(node);
	node->active = false;
}


// allocate space off the heap for a new struct.  clear and initialise it with the new handle.
node_t * node_new(void)
{
	node_t *node;
	
	node = (node_t *) malloc(sizeof(node_t));
	assert(node);
		
	node->stats = NULL;
	node->risp = NULL;

	node->next = NULL;
	node->prev = NULL;

	node->in_buffer = NULL;
	node->out_buffer = NULL;
	node->in_buffer_len = 0;
	node->out_buffer_len = 0;
	node->in_buffer_max = 0;
	node->out_buffer_max = 0;

	node_init(node);
	return(node);
}




// this function is called when we have received a new socket.   We need to 
// create a new node, and add it to our node list.  We need to pass to the node 
// any pointers to other sub-systems that it will need to have, and then we 
// insert the node into the 'node-circle' somewhere.  Finally, we need to add 
// the new node to the event base.
static void node_event_handler(int hid, short flags, void *data)
{
	node_t *node;
	unsigned int avail;
	int res;
	
	assert(hid >= 0);
	
  node = (node_t *) data;
  
  assert(node != NULL);
	assert(node->handle == hid);
	assert(node->stats != NULL);
	assert(node->active == true);
	assert(node->event.ev_base != NULL);
	
	assert(node->in_buffer_len <= node->in_buffer_max);
	assert(node->out_buffer_len <= node->out_buffer_max);
	assert((node->in_buffer == NULL && node->in_buffer_len == 0 && node->in_buffer_max == 0) || (node->in_buffer != NULL && node->in_buffer_len >= 0 && node->in_buffer_max > 0));
	assert((node->out_buffer == NULL && node->out_buffer_len == 0 && node->out_buffer_max == 0) || (node->out_buffer != NULL && node->out_buffer_len >= 0 && node->out_buffer_max > 0));

	if (flags & EV_READ) {
	
		avail = node->in_buffer_max - node->in_buffer_len;
		if (avail < DEFAULT_CHUNKSIZE) {
			node->stats->meml ++;
			node->in_buffer_max += DEFAULT_CHUNKSIZE;
			node->stats->maxbuf += DEFAULT_CHUNKSIZE;
			node->in_buffer = (unsigned char *) realloc(node->in_buffer, node->in_buffer_max);
			avail = node->in_buffer_max - node->in_buffer_len;
		}
		assert(avail >= DEFAULT_CHUNKSIZE);
	
		res = read(hid, node->in_buffer + node->in_buffer_len, avail);
		if (res > 0) {
			node->stats->in_bytes += res;
			node->in_buffer_len += res;
			assert(node->in_buffer_len <= node->in_buffer_max);
		}
		else if (res == 0) {
			node_clear(node);
			assert(node->active == false);
			printf("Node[%d] closed while reading.\n", hid);
		}
		else {
			assert(res == -1);
			if (errno != EAGAIN && errno != EWOULDBLOCK) {
				node_clear(node);
				assert(node->active == false);
				printf("Node[%d] closed while reading- because of error: %d\n", hid, errno);
			}
		}
		
		if (node->active && node->in_buffer_len > 0) {
			
			assert(node->risp != NULL);
			assert(node->in_buffer_len <= node->in_buffer_max);
			assert(node->in_buffer_len > 0);
			
			node->stats->cycles ++;			
			res = risp_process(node->risp, node, node->in_buffer_len, node->in_buffer);
 			assert(res <= node->in_buffer_len);
 			assert(res >= 0);
			if (res < node->in_buffer_len) {
			
				// our biggest (sample) command is a maximum of 256+2+1 bytes.  SO we should only ever have a partial left over of less than that.  If we have more left over than that... then we either have corrupted data, or 
				assert((node->in_buffer_len - res) <= (256+2+1));
				
				
				node->stats->undone += (node->in_buffer_len - res);
			
				// to ensure that we dont run out of memory, the partial system is not suitable when large volumes of data is being sent.
				avail = node->in_buffer_len - res;
				memmove(node->in_buffer, node->in_buffer + res, avail);
				node->in_buffer_len -= res;
			}
			else {
				node->in_buffer_len = 0;
			}
		}
	}
		
	if (flags & EV_WRITE && node->active) {		
		
		// we've requested the event, so we should have data to process.
		assert(node->out_buffer != NULL);
		assert(node->out_buffer_len > 0);
		assert(node->out_buffer_max > 0);
		assert(node->out_buffer_len <= node->out_buffer_max);
		
		res = send(hid, node->out_buffer, node->out_buffer_len, 0);
		if (res > 0) {
			// we managed to send some, or maybe all....
			assert(res <= node->out_buffer_len);
			if (res == node->out_buffer_len) {	
				// we sent all of it.
				node->out_buffer_len = 0;
			}
			else {
				// we only sent some of it.
				memmove(node->out_buffer, node->out_buffer + res, node->out_buffer_len - res);
				node->out_buffer_len -= res;
				assert(node->out_buffer_len > 0);
			}
		}
		else if (res == 0) {
			node_clear(node);
			assert(node->active == false);
			printf("Node[%d] closed while writing.\n", hid);
		}
		else {
			assert(res == -1);
			if (errno != EAGAIN && errno != EWOULDBLOCK) {
				node_clear(node);
				assert(node->active == false);
				printf("Node[%d] closed while writing - because of error: %d\n", hid, errno);
			}
		}
		
		// if we have sent everything, then we dont need to wait for a WRITE event anymore, so we need to re-establish the events.
		if (node->active && node->out_buffer_len == 0) {
			if (event_del(&node->event) != -1) {
				event_set(&node->event, hid, EV_READ | EV_PERSIST, node_event_handler, (void *)node);
				event_base_set(node->event.ev_base, &node->event);
				event_add(&node->event, 0);
			}		
		}
	}		
	
	
	// Once our 'partial' processing has passed a certain point, we want to clean up the memory that we have allocated.  This is also to combat situations where people are sending a valid data stream but deliberately leaving an unfinished command at the end of each packet (completed at the beginining of the next packet), which would normally end up increasing the amount of memory used by the node.   This is intended to ensure that doesn't cause more serious memory issues.
 	if (node->in_buffer_max > OPTIMAL_MAX) {
		
		if (node->in_buffer_len < node->in_buffer_max) {
			node->stats->maxbuf -= (node->in_buffer_max - node->in_buffer_len);
			node->in_buffer = (unsigned char *) realloc(node->in_buffer, node->in_buffer_len);
			printf("shrunk inbuffer [len=%d, max=%d]\n", node->in_buffer_len, node->in_buffer_max);
			node->in_buffer_max = node->in_buffer_len;
		}
 	}
	
// 	if (node->out_partial > OPTIMAL_PARTIAL) {
		//////
// 	}
	
 	///// If the in_buffer_max and out_buffer_max are larger than our optimum, then we should shrink the buffer if we have a chance.
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





//-----------------------------------------------------------------------------
// Initialise and return a server struct that we will use to control the nodes 
// that we are connected to.   We will bind the listening port on the socket.
//
//	** Will we ever need to listen on more than one port?  How will we add that 
//	   to the system?   Currently, wont bother with it, but will include a 
//	   'next' pointer so that we can have a list of listeners.  The problem 
//	   will be with our list of nodes.  All the servers would need to share 
//	   the nodes list, and various other shared resources.  This could be a 
//	   little cumbersome, but possible.
//
//
server_t *server_new(int port, int maxconns, char *address)
{
	server_t *ptr = NULL;
	int i;
  struct linger ling = {0, 0};
	struct addrinfo *ai;
	struct addrinfo *next;
	struct addrinfo hints;
	char port_buf[NI_MAXSERV];
	int error;
	int sfd;
	int flags =1;
	
	assert(port > 0);
	assert(maxconns > 5);
	assert(address == NULL || (address != NULL && address[0] != '\0'));
	
	memset(&hints, 0, sizeof (hints));
	hints.ai_flags = AI_PASSIVE|AI_ADDRCONFIG;
	hints.ai_family = AF_UNSPEC;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_socktype = SOCK_STREAM;

	snprintf(port_buf, NI_MAXSERV, "%d", port);
  error = getaddrinfo(address, port_buf, &hints, &ai);
	if (error != 0) {
		if (error != EAI_SYSTEM)
			fprintf(stderr, "getaddrinfo(): %s\n", gai_strerror(error));
		else
			perror("getaddrinfo()");
		return(NULL);
	}

	sfd	= 0;

	for (next= ai; next; next= next->ai_next) {
	
		assert(sfd == 0);
	
		// create the new socket.  if that fails, free the memory we've already allocated, and return NULL.
		sfd = new_socket(next);
		if (sfd == INVALID_HANDLE) {
			freeaddrinfo(ai);
			return(NULL);
		}

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

	ptr = (server_t *) malloc(sizeof(server_t));
	assert(ptr != NULL);
	
	ptr->handle = sfd;
	ptr->stats = NULL;
	ptr->risp = NULL;
	ptr->verbose = false;
	ptr->next = NULL;
	
	// We will create an array of empty pointers for our nodes.
	ptr->maxconns = maxconns;
	ptr->nodes = (node_t **) malloc(sizeof(node_t *) * maxconns);
	for (i=0; i<maxconns; i++) {
		ptr->nodes[i] = NULL;
	}
		
	return(ptr);
}


// this function is called when we have received a new socket.   We need to 
// create a new node, and add it to our node list.  We need to pass to the node 
// any pointers to other sub-systems that it will need to have, and then we 
// insert the node into the 'node-circle' somewhere.  Finally, we need to add 
// the new node to the event base.
static void server_event_handler(int hid, short flags, void *data)
{
	server_t *server;
	socklen_t addrlen;
	struct sockaddr_storage addr;
	int sfd;
	node_t *node = NULL;
	
	assert(hid >= 0);
	assert(data != NULL);
	
	
  server = (server_t *) data;
	assert(server->handle == hid);

	addrlen = sizeof(addr);
	if ((sfd = accept(hid, (struct sockaddr *)&addr, &addrlen)) == -1) {
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
	
	// mark socket as non-blocking
	if ((flags = fcntl(sfd, F_GETFL, 0)) < 0 || fcntl(sfd, F_SETFL, flags | O_NONBLOCK) < 0) {
			perror("setting O_NONBLOCK");
			close(sfd);
	}

	printf("New Connection [%d]\n", sfd);


	assert(node == NULL);
	if (server->nodes[sfd] == NULL) {
		printf("Creating a new node\n");
		node = node_new();
		server->nodes[sfd] = node;
		node->handle = sfd;
		node->verbose = server->verbose;
		
		assert(node->active == false);
		node->active = true;
		
		assert(server->stats != NULL);
		node->stats = server->stats;
		
		assert(server->risp != NULL);
		node->risp = server->risp;
	}
	else {
	
		node = server->nodes[sfd];
		if (node->active == false) {
			printf("Re-using an existing node\n");

			node->handle = sfd;
			node->active = true;
			
			// clear our base out... just to be sure.
			cmdClear(node);
		}
		else {
			assert(node->handle != sfd);
			assert(0);
		}
	}
	
	assert(server->event.ev_base != NULL);
	
	// setup the event handling...
	event_set(&node->event, sfd, EV_READ | EV_PERSIST, node_event_handler, (void *)node);
	event_base_set(server->event.ev_base, &node->event);
	event_add(&node->event, 0);
}



//-----------------------------------------------------------------------------
// This function is called as a callback from the event system whenever a new 
// socket connection has been made against the listener socket.
void server_add_event(server_t *server, struct event_base *evbase)
{
	assert(server != NULL);
	assert(evbase != NULL);
	
	assert(server->handle >= 0);

  event_set(&server->event, server->handle, (EV_READ | EV_PERSIST), server_event_handler, (void *)server);
  event_base_set(evbase, &server->event);
	if (event_add(&server->event, NULL) == -1) {
		perror("event_add");
	}
}



settings_t * settings_new(void)
{
	settings_t *ptr;
	ptr = (settings_t *) malloc(sizeof(settings_t));
	assert(ptr != NULL);

	ptr->port = DEFAULT_PORT;
	ptr->maxconns = DEFAULT_MAXCONNS;
	ptr->maxbytes = DEFAULT_MAXBYTES;
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



timeout_t *timeout_new(void)
{
	timeout_t *ptr;
	ptr = (timeout_t *) malloc(sizeof(timeout_t));
	assert(ptr != NULL);
	return(ptr);
}


static void timeout_handler(const int fd, const short which, void *arg) {
	struct timeval t = {.tv_sec = 1, .tv_usec = 0};
	timeout_t *ptr;
	
	ptr  = (timeout_t *) arg;

	assert(ptr != NULL);
	assert(ptr->clockevent.ev_base != NULL);

	// reset the timer to go off again in 1 second.
  evtimer_del(&ptr->clockevent);
	evtimer_set(&ptr->clockevent, timeout_handler, arg);
	event_base_set(ptr->clockevent.ev_base, &ptr->clockevent);
	evtimer_add(&ptr->clockevent, &t);
	
 	assert(fd == INVALID_HANDLE);
	assert(ptr->server != NULL);

	assert(ptr->stats != NULL);
	
	if (ptr->stats->in_bytes || ptr->stats->out_bytes || ptr->stats->commands || ptr->stats->operations) {
		printf("Bytes [%u/%u], Commands [%u], Operations[%u], Max[%u/%u], Cycles[%u], Undone[%u]\n", ptr->stats->in_bytes, ptr->stats->out_bytes, ptr->stats->commands, ptr->stats->operations, ptr->stats->meml, ptr->stats->maxbuf, ptr->stats->cycles, ptr->stats->undone);
		ptr->stats->in_bytes = 0;
		ptr->stats->out_bytes = 0;
		ptr->stats->commands = 0;
		ptr->stats->operations = 0;
		ptr->stats->meml = 0;
		ptr->stats->cycles = 0;
		ptr->stats->undone = 0;
	}
}



void timeout_init(timeout_t *ptr, struct event_base *base) 
{
	struct timeval t = {.tv_sec = 1, .tv_usec = 0};
	assert(ptr != NULL);
	assert(ptr->clockevent.ev_base == NULL);
	
	evtimer_set(&ptr->clockevent, timeout_handler, (void *) ptr);
	event_base_set(ptr->clockevent.ev_base, &ptr->clockevent);
	evtimer_add(&ptr->clockevent, &t);
	assert(ptr->clockevent.ev_base != NULL);
}




//-----------------------------------------------------------------------------
// Main... process command line parameters, and then setup our listening 
// sockets and event loop.
int main(int argc, char **argv) 
{
  int c;
	settings_t     *settings = NULL;
	server_t       *server   = NULL;
	timeout_t      *timeout  = NULL;
  stats_t        *stats    = NULL;
  risp_t         *risp     = NULL;


	// handle SIGINT 
	signal(SIGINT, sig_handler);
	
	// init settings
	settings = settings_new();
	assert(settings != NULL);

	// set stderr non-buffering (for running under, say, daemontools)
	setbuf(stderr, NULL);


	// process arguments 
	/// Need to check the options in here, there're possibly ones that we dont need.
	while ((c = getopt(argc, argv, "p:k:c:hrvd:u:P:l:")) != -1) {
		switch (c) {
			case 'p':
				settings->port = atoi(optarg);
				assert(settings->port > 0);
				break;
			case 'k':
        settings->maxbytes = ((size_t)atoi(optarg)) * 1024;
        break;
    	case 'c':
        settings->maxconns = atoi(optarg);
        assert(settings->maxconns > 0);
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

	// If needed, increase rlimits to allow as many connections as needed.
	if (settings->verbose) printf("Settings Max connections: %d\n", settings->maxconns);
	assert(settings->maxconns > 0);
 	set_maxconns(settings->maxconns);

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
	main_event_base = event_init();


	if (settings->verbose) printf("Ignoring SIGPIPE interrupts\n");
	ignore_sigpipe();
    
	// save the PID in if we're a daemon, do this after thread_init due to a 
	// file descriptor handling bug somewhere in libevent
	if (settings->daemonize && settings->pid_file) {
		if (settings->verbose) printf("Saving Pid file: %s\n", settings->pid_file);
		save_pid(getpid(), settings->pid_file);
	}
       
	// create and init the 'server' structure.
	if (settings->verbose) printf("Starting server listener on port %d.\n", settings->port);
	server = server_new(settings->port, settings->maxconns, settings->interface);
	if (server == NULL) {
		fprintf(stderr, "Failed to listen on port %d\n", settings->port);
		exit(EXIT_FAILURE);
	}
	assert(server != NULL);
	server->verbose = settings->verbose;
	
	
	
	// add the server to the event base
	assert(main_event_base != NULL);
	server_add_event(server, main_event_base);



	// initialise clock event.  The clock event is used to keep up our node 
	// network.  If we dont have enough connections, we will need to make some 
	// requests.  
	// create the timeout structure, and the timeout event.   This is used to 
	// perform certain things spread over time.   Such as indexing the 
	// 'complete' paths that we have, and ensuring that the 'chunks' parts are 
	// valid.
	if (settings->verbose) printf("Setting up Timeout event.\n");
	timeout = timeout_new();
	assert(timeout != NULL);
	assert(main_event_base != NULL);
	if (settings->verbose) printf("Initialising timeout.\n");
	timeout_init(timeout, main_event_base);
	timeout->server = server;

	stats = (stats_t *) malloc(sizeof(stats_t));
	stats->out_bytes = 0;
	stats->in_bytes = 0;
	stats->commands = 0;
	stats->operations = 0;
	stats->maxbuf = 0;
	stats->meml = 0;

	server->stats = stats;
	timeout->stats = stats;

	// Initialise the risp system.
	risp = risp_init();
	assert(risp != NULL);
	risp_add_invalid(risp, cmdInvalid);
	risp_add_command(risp, CMD_CLEAR, 	&cmdClear);
	risp_add_command(risp, CMD_EXECUTE, &cmdExecute);
	risp_add_command(risp, CMD_TTL,     &cmdTtl);
	risp_add_command(risp, CMD_URL, 		&cmdURL);
	
	assert(server->risp == NULL);
	server->risp = risp;


  // enter the event loop.
  if (settings->verbose) printf("Starting Event Loop\n\n");
	event_base_loop(main_event_base, 0);
    
  // cleanup risp library.
	risp_shutdown(risp);
  risp = NULL;
    
	// cleanup 'server', which should cleanup all the 'nodes'
    
  if (settings->verbose) printf("\n\nExiting.\n");
    
	// remove the PID file if we're a daemon
	if (settings->daemonize && settings->pid_file != NULL) {
		if (settings->verbose) printf("Removing pid file: %s\n", settings->pid_file);
		remove_pidfile(settings->pid_file);
	}

	assert(settings != NULL);
	settings_cleanup(settings);
	settings = NULL;

	return 0;
}


