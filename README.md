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
