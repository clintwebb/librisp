//--------------------------------------------------------------------------------------------------
// RISP Chat Server
// Example code that demonstrate how to develop a server that communicates thru a RISP protocol.
//
// Since this example is of a server, we are utilising libevent, and will run as a daemon or a 
// standard process.  For use in docker containers, best practice is to not use daemon mode.

/*
    Copyright (C) 2016  Clinton Webb
    
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser Public License for more details.

    You should have received a copy of the GNU Lesser Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

//--------------------------------------------------------------------------------------------------


// includes
#include <assert.h>			// assert
#include <getopt.h>
#include <signal.h>
#include <stdio.h>			// perror, printf
#include <stdlib.h>
#include <string.h>			// memmove, strlen
#include <unistd.h>			// getopt

// Include the rispstream library.
#include <rispstream.h>

#include "risp_chat_prot.h"



#define PACKAGE						"risp_chat_server"
#define VERSION						"1.00"



#define PROTOCOL_VALIDATION "RISP Server"


/* Get a consistent bool type */
#if HAVE_STDBOOL_H
# include <stdbool.h>
#else
  typedef enum {false = 0, true = 1} bool;
#endif



// Stored information about each message.  
typedef struct {
	long long msgID;
	unsigned char *name;
	int length;
	unsigned char *message;
} message_t;



// Each connection needs to be tracked and maintained.  This structure is faily self-contained.  
// However, when interaction is needed between sessions, then the control needs to be done from the 'sessions' structure.
typedef struct {
	
	// used for debugging and output.  Not really functionally required.  
	// It is just a way of identifying the different sessions that may be active at the same time in any verbose output.
	int id;
	
	int verify;
	
	// this object is used to handle the session since it is being managed by librispstream.  
	// NOTE: If this is NULL, then it indicates this session structure is not in use.
	RISPSESSION session_ptr;
	
	// the variables and flags that represent the data received from commands.
	struct {
		char name[256+1];
		bool authenticated;
		bool echo;
		bool follow;
		bool update;
	} data;
	
	// pointer to the maindata object that holds the main information that is used between sessions.
	// void because we dont have a structure for that yet.
	void *maindata;
} session_t ;


// This structure is used to track the sessions and is passed between the main app and the 
// librispstream callbacks.
//
// Since we make use of callbacks, we need a general method to parse information between the 
// different sub-systems.  One method is to just use global variables.  However, to keep them 
// alltogether in an object whose reference can be passed back and forth, we put all that info 
// in a single instantiated structure.  Then we can pass a pointer around.
//
// The reason why we need to keep track of the sessions at this level, is that we need to 
// recieve information from one session and pass it to other connected sessions.  If the 
// sessions themselves didn't need to interact, then we wouldn't need this complication.
typedef struct {
	struct {
		session_t **list;	// array
		int max;
	} sessions;
	
	struct {
		message_t **list;
		int latest;
	} messages;

} maindata_t;  // see maindata_init()



//--------------------------------------------------------------------------------------------------
// Global variables.





//--------------------------------------------------------------------------------------------------
// print some info to the user, so that they can know what the parameters do.
void usage(void) {
	printf(PACKAGE " " VERSION "\n");
	printf(	"   --port <num>\n"
			"   --interface <ip_addr>\n"
			"   --client-ca <file>\n"
			"   --cert <file>\n"
			"   --key <file>\n"
			"   --verbose\n"
			"   --help\n"
			);
	
	return;
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



// This function is called when we want to close an existing session, it is not a callback.   
void session_close(session_t *session)
{
	assert(session);
	
	assert(session->id >= 0);
	printf("Closing session[%d].\n", session->id);

	// Need to tell rispstream to shutdown the session (NOTE: This will not happen until the current round of processing is complete).
	assert(session->session_ptr);
	rispsession_close(session->session_ptr);
	
	// Now a callback function will be called when it actually closes the connection.
}







//--------------------------------------------------------------------------------------------------
void send_HelloAck(session_t *session)
{
	assert(session);
	assert(session->session_ptr);

	// add the command to the buffer.
	rispsession_send_noparam(session->session_ptr, CMD_HELLO_ACK);
}




//--------------------------------------------------------------------------------------------------
// This callback function is to be fired when the CMD_HELLO command is received.  
void cmdHello(void *base, risp_length_t length, risp_data_t *data) 
{
	// The base pointer that is passed thru the library doesnt know about the session structure we 
	// are using, so we need to make a cast-pointer for it.
 	session_t *session = (session_t *) base;
	assert(session->verify == 123456789);
	
	assert(session->id >= 0);
	printf("Session[%d]: Received HELLO\n", session->id);
	
	// Always a good idea to put lots of asserts in your code.  It helps to capture developer 
	// mistakes that would sometimes be difficult to catch at a later date.
  	assert(session);
	
	// we've received a string as well, so we need to validate that as well.
	// This checks that we either have no data at all (which is valid), or that we do have data.  
	// If length is legitimately zero, then the data pointer should be null.
	// If this assert fires, then your COMMAND ID is probably not a valid String ID.
	assert((length > 0 && data) || (length == 0 && data == NULL));
	
	// Check if the session is already authenticated
	assert(session->data.authenticated == 0 || session->data.authenticated == 1);
	if (session->data.authenticated == 1) {
		// session has already been authenticated, and it is illegal to attempt to authenticate again.
		printf("Session[%d] was already authenticated. Closing.\n", session->id);
		session_close(session);
	}
	else {
		// session was not already authenticated.
		

		int valid_len = strlen(PROTOCOL_VALIDATION);
		if (valid_len != length) {
			// the lengths of the string did not match.  Closing the session.
			session_close(session);
		}
		else {
			// the string lengths are the same.  Thats good, makes comparison easy.
			if (strncmp(PROTOCOL_VALIDATION, (char *) data, valid_len) != 0) {
				// strings dont match.   Closing the session.
				session_close(session);
			}
			else {
				// the strings matched!!  Mark the session as valid so that we can accept 
				// additional commands.
				
				// Indicate that session is now authenticated.
				assert(session->data.authenticated == 0);
				session->data.authenticated = 1;

				// since this authentication should happen before any other data is given, we 
				// should check that everything else is in an init state.
				assert(session->data.name[0] == '\0');

				printf("Session[%d] Established.\n", session->id);
				
				// We reply with a HELLO_ACK
				send_HelloAck(session);
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
	assert(session->id >= 0);
	
	// Check if the session is already authenticated
	assert(session->data.authenticated == true || session->data.authenticated == false);
	if (session->data.authenticated == false) {
		// session has not been authenticated, and it is illegal to attempt to operations without 
		// authenticating first..
		fprintf(stderr, "Closing connection.  Not Authenticated.\n");
		session_close(session);
		assert(ok == false);
	}
	else {
		// session was authenticated.
		ok = true;
	}

	return(ok);
}


//--------------------------------------------------------------------------------------------------
// This callback function is called when the CMD_GOODBYE command is received.  It will close the 
// session.
// NOTE: Since we are processing commands, and it is possible that more data processing is possible, 
//       we cannot simply close the connection and all the buffers, etc.  We should not change in 
//       any way the buffer that is being processed.
void cmdGoodbye(void *base) 
{
	session_t *session = (session_t *) base;
	assert(session);

	assert(session->id >= 0);
	printf("Session [%d]: Received GOODBYE\n", session->id);

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
	assert(session->id >= 0);
	printf("Session [%d]: Received ECHO\n", session->id);

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
	
	assert(session->id >= 0);
	printf("Session [%d]: Received NO_ECHO\n", session->id);
	
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
		
	assert(session->id >= 0);
	printf("Session [%d]: Received FOLLOW\n", session->id);
	
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
	
	assert(session->id >= 0);
	printf("Session [%d]: Received NO_FOLLOW\n", session->id);
	
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

	assert(session->id >= 0);
	printf("Session [%d]: Received NO_UPDATE\n", session->id);
	
	if (checkAuth(session) == true) {
		// remove the update flag.
		session->data.follow = false;
		session->data.update = false;
	}
}





// client is asking to know the latest msg ID that is available.
void cmdGetLatestMsgID(void *base)
{
	// The base pointer that is passed thru the library doesnt know about the session structure we 
	// are using, so we need to make a cast-pointer for it.
	session_t *session = (session_t *) base;
	assert(session);
	assert(session->id >= 0);
	printf("Session [%d]: Received CMD_GET_LATEST_MSG_ID\n", session->id);
	
	if (checkAuth(session) == true) {
		// this code is not currently completed.
		
		maindata_t *maindata = session->maindata;
		assert(maindata);

		// the list should either be empty, or have something in it.
		assert((maindata->messages.list == NULL && maindata->messages.latest == 0) || (maindata->messages.list && maindata->messages.latest > 0));

		printf("Session[%d]: Sending Latest Message ID: %lld\n", session->id, (long long) maindata->messages.latest);

		assert(session->session_ptr);
		rispsession_send_int(session->session_ptr, CMD_LATEST_MSG_ID, maindata->messages.latest);
	}
}


// Return the message associated with a message ID.
unsigned char * message_get_msg(maindata_t *maindata, long long msgID) 
{
	assert(maindata);
	assert(msgID > 0);
	
	assert(msgID <= maindata->messages.latest);
	if (msgID > maindata->messages.latest) {
		return(NULL);
	}
	else {
		assert(maindata->messages.list);
		message_t *msg = maindata->messages.list[msgID - 1];
		assert(msg);
		assert(msg->msgID == msgID);
		assert(msg->message);
		
		return(msg->message);
	}
}


// Return the name associated with a message ID.
unsigned char * message_get_name(maindata_t *maindata, long long msgID) 
{
	assert(maindata);
	assert(msgID > 0);
	
	assert(msgID <= maindata->messages.latest);
	if (msgID > maindata->messages.latest) {
		return(NULL);
	} else {
		assert(maindata->messages.list);
		message_t *msg = maindata->messages.list[msgID - 1];
		assert(msg);
		assert(msg->msgID == msgID);
		assert(msg->message);
		
		return(msg->name);
	}
}



void cmdSendMsg(void *base, risp_int_t value)
{
	// The base pointer that is passed thru the library doesnt know about the session structure we 
	// are using, so we need to make a cast-pointer for it.
	session_t *session = (session_t *) base;
	assert(session);
	
	assert(sizeof(value) >= sizeof(long long));
	assert(session->id >= 0);
	printf("Session [%d]: Received CMD_SEND_MSG(%ld)\n", session->id, value);
	
	if (checkAuth(session) == true) {
		// this code is not currently completed.
		
		maindata_t *maindata = session->maindata;
		assert(maindata);

		assert(maindata->messages.list);
		assert(maindata->messages.latest >= 0);
		
		
		// when we added the message to the messages array, it copied the message and ensured it w
		// as null termined, so we can now get a pointer to it.
		unsigned char *message = message_get_msg(maindata, value);
		if (message) {
			unsigned char *name = message_get_name(maindata, value);
			
			//   Response:
			//		CMD_MSG_ID(integer)
			//		CMD_NAME(string)	- If name is supplied.
			//		CMD_MESSAGE(string)

			printf("Session[%d]: By request, Sending message(%lld).\n", session->id, (long long) value);
			assert(session->session_ptr);
			rispsession_send_int(session->session_ptr, CMD_MSG_ID, value);
			if (name) { rispsession_send_str(session->session_ptr, CMD_NAME, strlen((const char *) name), name); }
			rispsession_send_str(session->session_ptr, CMD_MESSAGE, strlen((const char *) message), message);
		}
	}
}



void cmdSendSince(void *base, risp_int_t value)
{
	// The base pointer that is passed thru the library doesnt know about the session structure we 
	// are using, so we need to make a cast-pointer for it.
	session_t *session = (session_t *) base;
	assert(session);
	assert(session->id >= 0);
	printf("Session[%d]: Received CMD_SEND_SINCE(%ld)\n", session->id, value);
	
	if (checkAuth(session) == true) {
		// this code is not currently completed.
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
	assert(session->id >= 0);
	printf("Session[%d] Received NAME\n", session->id);
	
	if (checkAuth(session) == true) {
		// copy the string that was provides from the stream (which is guaranteed to be complete)
		assert(length < 256);
		memcpy(session->data.name, data, length);
		session->data.name[length] = '\0';	// null-terminate it to make it easier to manipulate.
		printf("Session[%d]: Setting Name to '%s'\n", session->id, session->data.name);
	}
}

long long message_new(maindata_t *maindata, const char *name, int msg_len, const char *message)
{
	long long msgID = 0;

	assert(maindata);
	assert(name);
	assert(msg_len > 0);
	assert(message);

	assert((maindata->messages.latest == 0 && maindata->messages.list == NULL) || (maindata->messages.latest > 0 && maindata->messages.list));
	
	msgID = maindata->messages.latest + 1;
	assert(msgID > 0);
	maindata->messages.list = realloc(maindata->messages.list, sizeof(message_t *) * msgID);
	assert(maindata->messages.list);

	message_t *msg = malloc(sizeof(message_t));
	msg->msgID = msgID;
	msg->name = (unsigned char *) strdup(name);
	msg->length = msg_len;
	msg->message = malloc(msg_len+1);
	memcpy(msg->message, message, msg_len);
	msg->message[msg_len] = 0;		// null terminate it just in case it is a valid string, and makes it easier to output debug, etc.

	maindata->messages.list[maindata->messages.latest] = msg;
	maindata->messages.latest ++;
	assert(maindata->messages.latest == msgID);
	
	assert(msgID > 0);
	return(msgID);
}


void relay_msg(session_t *relay, int msgID, unsigned char *name, int length, unsigned char *data) 
{
	assert(relay);
	assert(msgID >= 0);
	assert(length > 0);
	assert(data);
	// name can be NULL, so we have nothing to assert on that (although it should be less than 256 bytes).
	
	if (relay->id >= 0 && relay->data.authenticated == true) {
		if (relay->data.follow == true) { 
			printf("Sending FULL message(%d) to session[%d]\n", msgID, relay->id);
			rispsession_send_int(relay->session_ptr, CMD_MSG_ID, msgID);
			if (name) {
				rispsession_send_str(relay->session_ptr, CMD_NAME, strlen((char *)name), name);
			}
			rispsession_send_str(relay->session_ptr, CMD_MESSAGE, length, data);
		}
		else if (relay->data.update == true) { 
			printf("Sending ID message(%d) to session[%d].\n", msgID, relay->id);
			rispsession_send_int(relay->session_ptr, CMD_LATEST_MSG_ID, msgID); 
		}
		else {
			printf("NOT Sending message(%d) to session[%d].\n", msgID, relay->id);
		}
	}
}



/*
	0x9000  MESSAGE  (Bi-directional)
    
        When sent from a client, will take that parameter, and pass it (along with the msg ID and 
        name) to the other clients, depending on their FOLLOW or UPDATE modes.

        When sent from server to client, indicates that a message was received at the server, and 
        relayed to the client.  Will also be accompanied by a MSG_ID and a NAME command before the 
        MESSAGE.
        
        The MSG_ID can be used to update the ID of the latest message.  

        If the server is sending multiple messages from the same Name, it will only send Name once, 
        followed by the multiple messages.  Only when messages are being sent from different names, 
        will those entries also be included.
    
*/
void cmdMessage(void *base, risp_length_t length, risp_data_t *data) 
{
	session_t *session = (session_t *) base;
	
	// At every opportunity, we need to make sure that our data is legit.
	assert(base != NULL);
	assert(length >= 0);
	assert(data != NULL);
	
	// the protocol allows a message up to 64k chars in length.  If it is greater than that, then we ignore it.
	assert(length < 65536);
	if (length < 65536) {

		if (checkAuth(session) == true) {

			/// need to relay the message to each client that is connected and in follow mode (other than this 
			/// one, unless it has echo enabled).
			
			maindata_t *maindata = session->maindata;
			assert(maindata);
			
			// store the message in our messages store.
			long long msgID = message_new(maindata, session->data.name, length, (char *) data);
			assert(msgID > 0);

			// when we added the message to the messages array, it copied the message and ensured it was null 
			// termined, so we can now get a pointer to it.
			unsigned char *message = message_get_msg(maindata, msgID);
			unsigned char *name = message_get_name(maindata, msgID);
			
			printf("Session[%d]: Received Message '%s'\n", session->id, message); 

			//   Response for sessions in NOFOLLOW mode.
			//		CMD_LATEST_MSG_ID(integer)
			//
			//   Response for sessions in FOLLOW mode.
			//		CMD_MSG_ID(integer)
			//		CMD_NAME(string)	- If name is supplied.
			//		CMD_MESSAGE(string)

			// the sessions are referenced in an array. 
			assert(maindata);
			assert(maindata->sessions.list);
			assert(maindata->sessions.max > 0);
			for (int i=0; i<maindata->sessions.max; i++) {
				session_t *relay = maindata->sessions.list[i];
				if (relay) {
					if (relay->session_ptr) {
						relay_msg(relay, msgID, name, length, data);
					}
				}
			}
		}
	}
}


void cmdIllegal(void *base)
{
	// we have received a command that we should not be receiving (ie, one that should only be received by the client, not the the server).
	assert(0);
	
	
	session_t *session = (session_t *) base;
	session_close(session);
}









// This function is called when rispstream has detected a Ctrl-C interrupt.
void break_cb(RISPSTREAM stream, void *data) 
{
	assert(stream);
	
	// first we want to tell rispstream to stop listening.
	rispstream_stop_listen(stream);
	
	// Tell all connections to shutdown.  
	// We can only do this by adding a command to the outgoing queue for each one.  
	// We can do this easy by preparing a RISP message, and then telling rispstream to send it.  
	// It handles it all after that.  
	// Then we wait for each connection to shutdown.
	assert(0);
	
	// However, we dont want to wait forever.  So we set a timeout (in seconds) for each connection.  If the connection has not closed on its own within that time, then rispstream will close it, so that everything can exit.
	assert(0);
	
	// NOTE: When rispstream is no longer listening on any sockets, and has no connections, the event system will exit and the stream will no longer be functional and the main application should exit (or at least continue.)
	
}


// TODO: Should change this logic to re-use sessions.
session_t * session_new(maindata_t *maindata, RISPSESSION streamsession)
{
	assert(maindata);
	assert(streamsession);

	// allocate space for the object, and clear it too.
	session_t *session = calloc(1, sizeof(session_t));
	assert(session);
	
	int index;
	int found = -1;
	for (index=0; found < 0 && index < maindata->sessions.max; index++) {
		if(maindata->sessions.list[index] == NULL) {
			found = index;
		}
	}

	if (found < 0) {
		maindata->sessions.list = realloc(maindata->sessions.list, sizeof(session_t *) * (maindata->sessions.max + 1));
		found = maindata->sessions.max;
		maindata->sessions.max ++;
	}
	
	maindata->sessions.list[found] = session;

	session->id = maindata->sessions.max;
	session->verify = 123456789;
	session->maindata = maindata;
	session->session_ptr = streamsession;
	
	// Set the defaults
	session->data.name[0] = 0;
	session->data.authenticated = false;
	session->data.echo = false;
	session->data.follow = true;
	session->data.update = true;
	
	return(session);
}



// callback function whenever a new connection is established.  This should setup any local session tracking that we need to do.
void newconn_cb(RISPSESSION streamsession, void *dataptr) 
{
	assert(streamsession);
	
	assert(dataptr);
	maindata_t *maindata = dataptr;
	assert(maindata);

	fprintf(stderr, "Newconn\n");
	
	// this will create the session and manage it however we need to manage it.
	session_t *session = session_new(maindata, streamsession);
	assert(session);

	rispsession_set_userdata(streamsession, session);
}


void session_free(session_t *session)
{
	assert(session);
	
	// there is really nothing to free in the session other than itself.
	free(session);
}



// This callback is received whenever a session is closed.  The RISP session itself will be destroyed right after this callback exits.
void connclosed_cb(RISPSESSION streamsession, void *dataptr)
{
	assert(streamsession);
	assert(dataptr);
	
	maindata_t *maindata = dataptr;
	assert(maindata);
	
	// we need to go through the list in maindata, to find this particular session.  When we have found it, we remove it.
	assert(maindata->sessions.list);
	assert(maindata->sessions.max > 0);
	int index;
	short found = 0; 
	for (index=0; index < maindata->sessions.max; index++) {
		if (maindata->sessions.list[index]) {
			if (maindata->sessions.list[index]->session_ptr == streamsession) {
				// free the resources used by the session, and the session object itself.
				session_free(maindata->sessions.list[index]);
				
				// clear the entry in the list.
				maindata->sessions.list[index] = NULL;
				
				// we found the one we were looking for, so mark it, and exit the loop.
				found = 1;
				index = maindata->sessions.max;
			}
		} 
	}

	// we should have found one in that list.
	assert(found == 1);
}


maindata_t * maindata_init(void)
{
	maindata_t *data = calloc(1, sizeof(maindata_t));
	assert(data);

	data->sessions.list = NULL;
	data->sessions.max = 0;

	data->messages.list = NULL;
	data->messages.latest = 0;
	
	return(data);
}


//-----------------------------------------------------------------------------
// Main... process command line parameters, and then setup our listening 
// sockets and event loop.
int main(int argc, char **argv) 
{
	char *interface = "0.0.0.0";
	char *cafile = NULL;
	char *certfile = NULL;
	char *keyfile = NULL;
	int port = DEFAULT_PORT;
	bool verbose = false;

	// set stderr non-buffering (for running under, say, daemontools)
	setbuf(stderr, NULL);

	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{"interface", required_argument, 0,  'l' },
			{"port",      required_argument, 0,  'p' },
			{"client-ca", required_argument, 0,  'c' },
			{"cert",      required_argument, 0,  's' },
			{"key",       required_argument, 0,  'k' },
			{"help",      no_argument,       0,  'h' },
			{"verbose",   no_argument,       0,  'v' },
			{0,           0,                 0,  0 }
		};

		int c = getopt_long(argc, argv,
			"l:" /* listening interface (IP) */
			"p:" /* port to listen on */
			"c:" /* Client Certificate Chain */
			"s:" /* Server Certificate */
			"k:" /* Private Key file for Server Certificate */
			"h"  /* help... show usage info */
			"v"  /* verbosity */
			, long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
			case 0:
				printf("Unknown option %s", long_options[option_index].name);
				if (optarg)
					printf(" with arg %s", optarg);
				printf("\n");
				break;
			case 'h':
				usage();
				exit(EXIT_SUCCESS);
			case 'v':
				verbose++;
				break;
			case 'p':
				assert(optarg);
				port = atoi(optarg);
				assert(port > 0);
				break;
			case 'l':
				interface = optarg;
				assert(interface);
				break;
			case 'c':
				assert(cafile == NULL);
				cafile = optarg;
				assert(cafile);
				break;
			case 's':
				assert(certfile == NULL);
				certfile = optarg;
				assert(certfile);
			case 'k':
				assert(keyfile == NULL);
				keyfile = optarg;
				assert(keyfile);
				break;
			default:
				fprintf(stderr, "Illegal argument \"%c\"\n", c);
				return 1;
		}
	}

	if (verbose > 1) { printf("Interface: %s\n", interface); }
	if (verbose > 1) { printf("Listening Port: %d\n", port); }
	if (verbose > 1) { printf("CA File: %s\n", cafile); }
	if (verbose > 1) { printf("Cert File: %s\n", certfile); }
	if (verbose > 1) { printf("Key File: %s\n", keyfile); }

	if (verbose) fprintf(stderr, "Finished processing command-line args\n");

	// initialise the rispstream.  We dont pass any parameters in, we build up functionality after.
	RISPSTREAM stream = rispstream_init(NULL);
	assert(stream);

	// Initialise the risp system.
	RISP risp = risp_init();
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
	
	// there are some commands that are illegal to be received from the client.  
	// If we receive them, then we should close the session
	risp_add_command(risp, CMD_HELLO_ACK,			&cmdIllegal);
	risp_add_command(risp, CMD_MSG_ID,				&cmdIllegal);
	risp_add_command(risp, CMD_LATEST_MSG_ID,		&cmdIllegal);

	// attach our RISP object (which has all the commands added) to the stream.  
	// It will use this object to decode the stream of data as it arrives.
	assert(stream && risp);
	rispstream_attach_risp(stream, risp);

	// create the object that will be tracking the sessions and the data that needs to flow 
	// between them, and let the stream sub-system know.
	maindata_t *data = maindata_init();
	assert(data);
	rispstream_set_userdata(stream, data);

	// if the user has specified to use certificates, then they needed to be loaded into the 
	// rispstream instance.  Once certificates are applied, all client connections must also
	// be secure.
	if (cafile && keyfile) {
		if (verbose > 1) { fprintf(stderr, "Loading Certificate and Private Keys\n"); }
		int result = rispstream_add_server_certs(stream, cafile, keyfile);
		if (result != 0) {
			fprintf(stderr, "Unable to load Certificate and Private Key files.\n");
			exit(1);
		}
		assert(result == 0);
		if (verbose) { printf("Certificate files loaded.\n"); }
	}
	
	// When the user presses Ctrl-C, we want the service to exit (cleanly).  
	// We can tell rispstream to handle that (since the stream will be handling libevent).  
	// When a user presses Ctrl-C, rispstream will detect, and will execute a callback routine.  
	// In this case, our callback routine is break_cb().
	assert(stream);
	rispstream_break_on_signal(stream, SIGINT, break_cb);
    
	// Now we want to tell rispstream to listen on a socket for new connections.  
	// When a new connection comes in, a callback function is called.  
	// The callback function will return with a pointer to a base data object.  
	// That object will be passed to the risp callback routines when commands are received.  
	// It essentially allows you to have some data specific to that session.
	assert(stream);
	rispstream_listen(stream, interface, port, newconn_cb, connclosed_cb);

	// Now that the listen socket and event is created, we need to process the streams that result.  
	// This function will continue to run until one of the callbacks tells rispstream to shutdown.   
	// This is a blocking function.
	rispstream_process(stream);
	
	//--------
	// Shutting Down.
	// When the above function exits, it means we are shutting down.
	
	// Since rispstream did not create the risp object, we should detach it, to make it clear that risp is being cleaned up elsewhere.  
	// If it was still attached when rispstream_shutdown() is called, it will generate an assert.
	rispstream_detach_risp(stream);
	
	// shutdown rispstream.. it should be fairly empty and idle at this point though.
	rispstream_shutdown(stream);
	stream = NULL;
	
	// cleanup risp library.
	assert(risp);
	risp_shutdown(risp);
	risp = NULL;
    
	if (verbose) fprintf(stderr, "\n\nExiting.\n");

	return 0;
}


