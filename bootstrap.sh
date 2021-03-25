#!/usr/bin/env sh

# Copyright (c) 2021 Mastercard

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#   http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

########################################################################
# bootstrap.sh: used to bootstrap project once cloned from git
#               or during FreeBSD package build
########################################################################

# no tolerance to errors
set -e

cleanup() {
    if [ -n ${oldpath} ]; then
	cd ${oldpath}
    fi
}

trap cleanup EXIT

oldpath=$PWD
cd ${oldpath}

# detect if we are in a git repo
if [ -d .git ]; then
    # pull submodule stuff
    git submodule foreach --recursive git submodule update --init
    #    git submodule update --init .gnulib
    #    git submodule update --init include/oasis-pkcs11
else
    # if not a git repo, then two possibilities:
    # 1) we are building a FreeBSD port, in which case
    #    BUILD_PORT is set
    # 2) we are not, in which case we choke and die
    #
    if [ -z ${BUILD_PORT} ]; then
	echo "***Error: $0 is not invoked from a git repository."
	exit 1
    fi
fi

# invoke gnulib
.gnulib/gnulib-tool --import --dir=. --lib=libgnu --source-base=gl --m4-base=m4 --doc-base=doc --tests-base=tests --aux-dir=. --no-conditional-dependencies --no-libtool --macro-prefix=gl byteswap gethostname getline getopt-gnu malloc-gnu calloc-gnu realloc-gnu regex strcase termios time sysexits

# create configure scripts
autoreconf -vfi

cat <<EOF
========================================================================
Bootstrap complete. 
Execute './configure' and 'make' to build the project.

EOF
