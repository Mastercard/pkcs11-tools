#!/usr/bin/env sh

# pull submodule stuff
git submodule update --init .gnulib
git submodule update --init include/oasis-pkcs11

# invoke gnulib
.gnulib/gnulib-tool --import --dir=. --lib=libgnu --source-base=gl --m4-base=m4 --doc-base=doc --tests-base=tests --aux-dir=. --no-conditional-dependencies --no-libtool --macro-prefix=gl byteswap gethostname getline getopt-gnu malloc-gnu calloc-gnu realloc-gnu regex strcase termios time sysexits

# create configure scripts
autoreconf -vfi

