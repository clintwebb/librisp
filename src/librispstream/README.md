# librispstream

This library is intended to make it easier for developers to create servers and clients that use a RISP protocol by providing all the plumbing for sending and receiving over a socket.  This means a developer only then needs to write the code to have the actual commands that needs to be sent and received.

Essentially you can tell the library to listen on a port, gives it an initialised RISP object, and it will then wait for connections on that port, and process the RISP stream that comes over it.

Various call-back routines can be used, for example, a callback can be executed when a new connection comes in.

The library utilises libevent to handle the notification that data is available to process.  If the developer wants to do other things, they can initialise the event system and add it to our library, but if they dont, then the lib will initiate its own libevent and run the main loop directly.

