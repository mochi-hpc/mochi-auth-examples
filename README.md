Mochi Auth Examples
===================

This repository aims to provide example codes for developing multi-user
data services with Mochi. These example rely on [munge](https://dun.github.io/munge/)
for clients to authenticate themselves with the server.

Building and running the code examples
--------------------------------------

The code in this repository can be built as follows.

1. Follow the tutorial [here](https://mochi.readthedocs.io/en/latest/installing.html)
   to install [spack](https://spack.io) and the repository of Mochi packages.
2. Clone this repository.
3. Create a spack environment using the [spack.yaml](spack.yaml) file in this repository, as follows.
   ```
   $ spack env create mochi-auth-env spack.yaml
   $ spack activate mochi-auth-env
   $ spack install
   ```
4. Use cmake to build the code in this repository, as follows.
   ```
   $ mkdir build
   $ cd build
   $ cmake ..
   $ make
   ```

Each C (.c) and  C++ (.cpp) source file in the [src](src) folder corresponds to a program.
Programs go in pairs of a client and a server. They are prefixed with the API used,
`margo_` for C programs and `thallium_` for C++ programs.

To run an example, first make sure you have two terminals with the spack environment
activated. Run the server program first in one of the terminals, passing a protocol
such as "tcp" as its argument. The server should print out its address. Copy this address,
then run the corresponding client program in another terminal, passing the copied address
as argument.

Notes on Munge
--------------

Munge is is an authentication service for creating and validating credentials.
If your cluster runs uses [Slurm](https://slurm.schedmd.com/documentation.html),
it likely has a munge daemon running on all of its compute nodes. The daemon
runs under the `munge` user, which is not priviledged.
Programs that need to encode and decode credentials communicate locally with this daemon
via a named socket, usually `/var/run/munge/munge.socket.2`. Note how our [spack.yaml](spack.yaml)
file specifies the `localstatedir=/var` option for munge. If you find that on your
cluster, Munge's socket is located elsewhere, this is where this path should be changed.

For development on a machine where you have sudo priviledges, Munge is usually
available as a package, and easy to setup. For instance on Ubuntu, `sudo apt install munge`
should not only install Munge, but also create the `munge` user and group and should also
make the `munge` daemon start on startup. For more information on how to install and setup
Munge, please refer to its [documentation](https://dun.github.io/munge/).
While the munge spack package provides the `munged` program in its `sbin` folder, we
recommend relying on a system-provided package to replicate the correct setup, which relies
on a `munge` user to run this daemon.

Simple authentication example
-----------------------------

**C files for this example:**
- [src/margo_simple_auth_client.c](src/margo_simple_auth_client.c)
- [src/margo_simple_auth_server.c](src/margo_simple_auth_server.c)
- [src/margo_simple_auth_types.h](src/margo_simple_auth_types.h)

In this example, we define an `authenticate` RPC that will be used to authenticate a user.
The client program uses `munge_encode` to create a credential string without any extra payload.
This credential string will simply carry the user's `uid` and `gid` in an encrypted way.
This credential is sent to the server in the arguments of the `authenticate` RPC, and the server
uses `munge_decode` to decode it, retrieving the sender's `uid` and `gid`. The credential is
unique, that is, another call to `munge_encode` will produce a new credential, hence if
a third party were to spy on the communication and retrieve the credential string, it would
not be able to use it to pretend to be the original sender.

From this example, it may be tempting to incorporate the same logic in all RPC, i.e.
add a "credential" field to all the RPCs and invoke `munge_encode` and `munge_decode`
on every RPC. This however would have a cost, as the munge daemon would need to be contacted
in every RPC by the client and by the server.

Instead, the next example relies on [OpenSSL](https://www.openssl.org/) to use a
Message Authentication Code (MAC) and avoid relying on Munge after a first authentication RPC.


Authentication and MAC example
------------------------------

**C files for this example:**
- [src/margo_auth_mac_client.c](src/margo_auth_mac_client.c)
- [src/margo_auth_mac_server.c](src/margo_auth_mac_server.c)
- [src/margo_auth_mac_types.h](src/margo_auth_mac_types.h)

In this example, Munge is used only as a first step, in an `authenticate` RPC, for the client
to send a key to the server. This key is encrypted as a payload to `munge_encode`, and decoded
on the server. The server stores the information about the client, namely its `uid` and its `key`.
This example only stores the information about one client. We won't bother storing more as this
examples has limitations that will be addressed in the next example.

Associated with the client's `uid` is also a sequence number (`seq_no`), which starts at 0.
Any subsequent RPC after authentication will not rely on Munge. Instead, the client uses its
key and OpenSSL's HMAC to compute a hash of the pair `(uid, seq_no)`. It sends both the
the pair and the hash as a header to its RPC arguments.

Upon receiving an RPC, the server looks at the clear `uid`, finds the corresponding client
in its hash (there is only one client stored in this example), check that the sequence number
matches, and uses the client's key to compute the same hash of the pair `(uid, seq_no)`. If
the hash matches what the client sent, it must be that the client had the correct key, and
the server can trust that it is who it claims to be.

It is easy to see that this example is limited to one client process per user. If multiple
processes with the same `uid` were to try to interact with a server, they should not only share
the same key (dangerous), but they should also coordinate to send RPCs with correct sequence
numbers. The next example solves this problem by using sessions.


Using sessions
--------------

**C files for this example:**
- [src/margo_auth_mac_session_client.c](src/margo_auth_mac_session_client.c)
- [src/margo_auth_mac_session_server.c](src/margo_auth_mac_session_server.c)
- [src/margo_auth_mac_session_types.h](src/margo_auth_mac_session_types.h)

In this example, upon receiving an `authenticate` RPC, the server generates a random session ID
that it sends back to the client. The client uses this session ID instead of its UID in subsequent
RPCs to sign the RPC.

This example is still made to work with only one client and one server (the client maintains a single
session and the server maintains information about a single client). It would be easy to assume that
it now just a matter of adding a hash table of opened sessions on each side, but there are still a number
of problems.

First, this architecture does not prevent replaying an RPC on another server. Imagine a client
sending an `authenticate` RPC to server A. If this RPC is intercepted by a malicious actor, this
actor could send the same payload to server B and open a session with it. We need server B to be able
to recognize that the payload was intended for server A.

Second, we have no mechanism for sessions to expire. This mechanism is important if we have long-running
services and many clients, as we wouldn't want the number of sessions stored in the server to grow
indefinitely.

The next example fixes these two problems and provides a complete solution for multi-user Mochi services.


Complete solution
-----------------

**C files for this example:**
- [src/margo_auth_complete_client.c](src/margo_auth_complete_client.c)
- [src/margo_auth_complete_server.c](src/margo_auth_complete_server.c)
- [src/margo_auth_complete_types.h](src/margo_auth_complete_types.h)

This example puts together everything discussed above. The client relies on a `connection_t`
object that encapsulates a server's address, a key, a session ID, and a sequence number. This
connection object is initialized by an authenticate RPC, and is later used to send RPCs to a
server.

The server keeps a hash of `session_t` instances, which represent sessions opened by clients.
These sessions can be retrieved in RPCs by their session ID, and contain informations about the
clients, including their UID. The sessions also have a `last_used` value storing a timestamp
of their last use, ready to be used to implement session expiration.

Some improvements to this example remain possible. In practice, the MAC could be computed
based on more than just the session ID for a given RPC. Including some arguments of the
RPC can be a way to ensure that content of the RPC is not tempered with in a man-in-the-middle
attack for example.


Acknowledgment
--------------

We thank MUNGE author [Chris Dunlap](https://github.com/dun) for his valuable feedback on earlier
versions of these examples.
