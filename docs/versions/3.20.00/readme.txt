Release 3.20.00 is primarily geared towards providing support for handling large messages (by storing the stream in temporary files instead of in memory).
Development work is starting 2016.07.02, and is expected to be released within 90 days.

Includes:
 * risp_t - This work was to remove the exposed structure from the header file, putting it in the C code instead.  It is replaced by a RISP_PTR instead, which is just a pointer.
 * manpages - Man pages created for each function and logical construct introduced with this library.
