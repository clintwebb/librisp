//-----------------------------------------------------------------------------
//   librispstream
//   -------
//   library to handle the low-level operations of a RISP based data stream.
//
//   Copyright (C) 2016  Clinton Webb

/*
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser Public License for more details.

    You should have received a copy of the GNU Lesser Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/
//-----------------------------------------------------------------------------

#ifndef __LIBRISPSTREAM_H
#define __LIBRISPSTREAM_H


/*
 * Version 1.0
*/

#include <event.h>
#include <stdint.h>
#include <risp.h>


#if (RISP_VERSION < 0x00040000)
  #error "RISP Library version must be at least 4.00 or greater"
#endif

///////////////////////////////////////////
// RISP_STREAM instance handle.   
typedef void * RISPSTREAM;
typedef void * RISPSESSION;


// Callback types
typedef void (*risp_cb_idle)(RISPSTREAM, void *);
typedef void (*risp_cb_break)(RISPSTREAM, void *); 

typedef void (*risp_cb_newconn)(RISPSESSION, void *);
typedef void (*risp_cb_connclosed)(RISPSESSION, void *);
typedef void (*risp_cb_timeout)(RISPSESSION, void *);

///////////////////////////////////////////
// declare the public functions.

// init and shutdown.
extern RISPSTREAM rispstream_init(struct event_base *base);
extern void rispstream_init_events(RISPSTREAM streamptr);
extern void rispstream_shutdown(RISPSTREAM stream);
extern int  rispstream_listen(RISPSTREAM stream, char *interface, risp_cb_newconn newconn_fn, risp_cb_connclosed connclosed_fn);
extern int  rispstream_connect(RISPSTREAM stream, char *host, void *basedata, risp_cb_newconn newconn_fn, risp_cb_connclosed connclosed_fn);
extern void rispstream_process(RISPSTREAM stream);
extern void rispstream_stop_listen(RISPSTREAM stream);
extern void rispstream_attach_risp(RISPSTREAM stream, RISP risp);
extern void rispstream_detach_risp(RISPSTREAM stream);
extern void rispstream_idle_callback(RISPSTREAM streamptr, risp_cb_idle idle_fn);
extern void rispstream_break_on_signal(RISPSTREAM stream, int sig, risp_cb_break break_fn);

extern void rispstream_set_userdata(RISPSTREAM stream, void *data);
extern void *rispstream_get_userdata(RISPSTREAM stream);



///////////////////////////////////////////
// Session Functions.  
extern void rispsession_close(RISPSESSION sessionptr);

extern void rispsession_set_userdata(RISPSESSION sessionptr, void *sessiondata);
extern void * rispsession_get_userdata(RISPSESSION sessionptr);

extern void rispsession_send_noparam(RISPSESSION sessionptr, risp_command_t command);
extern void rispsession_send_int(RISPSESSION sessionptr, risp_command_t command, risp_int_t value);
extern void rispsession_send_str(RISPSESSION sessionptr, risp_command_t command, risp_int_t length, risp_data_t *data);

// send raw data (that is presumably already a RISP command, or set of them).
extern void rispsession_send_raw(RISPSESSION sessionptr, risp_int_t length, risp_data_t *data);


#endif
