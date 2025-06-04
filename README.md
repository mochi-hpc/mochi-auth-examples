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
3. Create a spack environment using the [spack.yaml] file in this repository, as follows.
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

Each C (.c) and  C++ (.cpp) source file in the [src] folder corresponds to a program.
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
via a named socket, usually `/var/run/munge/munge.socket.2`. Note how our [spack.yaml]
file specifies the `localstatedir=/var` option for munge. If you find that on your
cluster, Munge's socket is located elsewhere, this is where this path should be changed.

For development on a machine where you have sudo priviledges, Munge is usually
available as a package, and easy to setup. For instance on Ubuntu, `sudo apt install munge`
should not only install Munge, but also create the `munge` user and group and should also
make the `munge` daemon start on startup. For more information on how to install and setup
Munge, please refer to [its documentation](https://dun.github.io/munge/).
While the munge spack package provides the `munged` program in its `sbin` folder, we
recommend relying on a system-provided package to replicate the correct setup, which relies
on a `munge` user to run this daemon.

Simple authentication example
-----------------------------

- [src/margo_simple_auth_client.c]
- [src/margo_simple_auth_server.c]
- [src/margo_simple_auth_types.h]
