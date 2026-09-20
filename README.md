GCM Library
===========

This library implements the Galois Counter Mode (GCM) authenticated encryption
algorithm.  It relies on the libaes library to perform AES encryption.

Throughout the text, there are references to GCM and to gcm-revised-spec.  Both
describe the same algorithm, though the latter specifies performance
improvements and test vectors not found in the former.  References to those are:

* [GCM](https://csrc.nist.gov/pubs/sp/800/38/d/final)
* [gcm-revised-spec](https://hive.packetizer.com/users/packetizer/papers/cryptography/encryption/gcm-revised-spec.pdf)

The "gcm-revised-spec" spec was originally at [this location](http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf), but
the link now redirects. Additional locations include [this one](https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf), which is an
archive of the NIST site.
