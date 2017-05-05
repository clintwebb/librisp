This release is mostly about utilising the builtin buffers in libevent called bufferevents and evbuffers.

This will allow us to more easily integrate SSL encrypted sessions using industry standard secure socket connections and certificates.

Includes:
 feature-version - risp_version() to ensure that we have a recent enough library installed on the system.
 feature-bufferevents - the main crux of this release.


