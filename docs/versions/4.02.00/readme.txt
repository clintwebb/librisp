This release is mostly about utilising the builtin buffers in libevent called bufferevents and evbuffers.

This will allow us to more easily integrate SSL encrypted sessions using industry standard secure socket connections and certificates.

Includes:
 feature-version - risp_version() to ensure that we have a recent enough library installed on the system.
 feature-bufferevents - the main crux of this release.

History:
 2017.05.05 - Merged in 'feature-version' because development of 'feature-bufferevents' requires it.
 2017.05.31 - Merged in 'feature-bufferevents'.  This is needed for the secure-stream work that is the primary focus of this release.
 2017.06.02 - Updated 'feature-bufferevents' which has some bugfixes.


