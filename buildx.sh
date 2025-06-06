#!/usr/bin/env bash
#
# Copyright (c) 2025 Mastercard

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#   http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
set -e

cleanup() {
  echo "Caught SIGINT. Exiting..."
  exit 1
}

trap cleanup SIGINT  # Handle SIGINT (CTRL-C)

PACKAGE="pkcs11-tools"
GITHUB_REPO="https://github.com/Mastercard/pkcs11-tools"
GITHUB_REPO_COMMIT="HEAD"
SUPPORTED_ARCHS="amd64 arm64"
SUPPORTED_DISTROS="ol7 ol8 ol9 deb12 ubuntu2004 ubuntu2204 ubuntu2404 amzn2023 alpine321"

# Declare an associative array, needed by docker buildx --platform option
declare -A rev_arch_map
rev_arch_map["x86_64"]="amd64"
rev_arch_map["aarch64"]="arm64"

#
# Usage information
#
function usage() {
    echo "Build package(s) for multiple distros and architectures using Docker buildx."
    echo ""
    echo "Usage: $0 [-r URL] [-v] [-j N] [-c COMMIT] [-p FILE] [--config-args ARGS] (distro[/arch]|all[/all]) [...]"
    echo "Supported distros: $SUPPORTED_DISTROS"
    echo "Supported archs: $SUPPORTED_ARCHS"
    echo ""
    echo "Options:"
    echo "  --repo URL, -r URL           Repository URL (default: $GITHUB_REPO)"
    echo "  --commit COMMIT, -c COMMIT   Commit hash, tag or branch to build (default: $GITHUB_REPO_COMMIT)"
    echo "  --verbose, -v                Increase verbosity (can be specified multiple times)"
    echo "  --no-cache, -n               Do not use docker build cache"
    echo "  --max-procs N, -j N          Maximum number of concurrent build processes (default: all available CPUs)"
    echo "  --proxyrootca FILE, -x FILE  Root CA file to use for the build"
    echo "  --config-args ARGS           Additional arguments to pass to the configure script"
    echo "  --help, -h                   Show this help message"
    echo ""
    exit 1
}

#
# Get the current directory
#
function get_current_dir() {
    current_dir="$(pwd)"
    echo "${current_dir}"
}

#
# Get the directory of the script
#
function get_script_dir() {
    script_dir="$(cd "$(dirname "$0")" && pwd)"
    echo "${script_dir}"
}

#
# Generate a random container name
#
function gen_random_container_name() {
    random_docker_name=$(head -c 16 /dev/urandom | base64 | tr -dc 'a-z0-9' | head -c 12)
    echo -n "container-$PACKAGE-$random_docker_name"
}

#
# Get the current git tag or commit hash if current commit is not tagged
#
function get_git_tag_or_hash() {
    # Get the current tag if it exists, otherwise get the short commit hash
    git describe --tags --abbrev=0 2>/dev/null || git rev-parse --short HEAD
}

#
# Copy the root CA file to the script directory (which is the context)
#
function copy_root_ca() {
    local rootca="$1"
    local script_dir=$(get_script_dir)

    # Check if the file exists
    if [ -f "$rootca" ]; then
        cp "$rootca" "$script_dir/proxyrootca.crt"
        echo "Root CA file copied to $script_dir/proxyrootca.crt"
    else
        echo "Root CA file not found: $rootca"
        exit 1
    fi
}

#
# Build the tarball for the given distro and arch
#
# $1 - package
# $2 - distro
# $3 - arch
# $4 - verbose: 0 or 1
# $5 - no cache: 0 or 1
# $6 - repo_url (default: $GITHUB_REPO)
# $7 - repo_branch (default: "main")
# $8 - repo_commit (default: "HEAD")

function create_build() {
    set -e                      # Exit on error, repeated here to ensure it's set in the subshell

    local package="$1"
    local distro="$2"
    local arch="$3"
    local verbose="$4"
    local no_cache="$5"
    local repo_url="$6"
    local repo_commit="$7"
    local proxyrootca="$8"
    local config_args="$9"

    local verbosearg="--quiet"

    if [ "$verbose" -eq 1 ]; then
        verbosearg="--progress=auto"
    elif [ "$verbose" -eq 2 ]; then
        verbosearg="--progress=plain"
    fi

    local no_cachearg=""
    if [ "$no_cache" -eq 1 ]; then
        no_cachearg="--no-cache"
    fi

    # TODO: keep this outside of this function, should be a global variable
    declare -A arch_map
    arch_map["amd64"]="x86_64"
    arch_map["arm64"]="aarch64"

    local platformarch="${arch_map[$arch]:-$arch}"

    echo "Building artifacts for $distro on arch $arch (platform: $platformarch)..."
    
    local containername=$(gen_random_container_name)
    docker buildx build $verbosearg $no_cachearg \
        --platform linux/$platformarch \
        --build-arg REPO_URL=$repo_url \
        --build-arg REPO_COMMIT_OR_TAG=$repo_commit \
        --build-arg PROXY_ROOT_CA=$proxyrootca \
        --build-arg CONFIG_ARGS="$config_args" \
        -t $package-build-$distro-$arch \
        -f $(get_script_dir)/buildx/Dockerfile.$distro \
        $(get_script_dir)
    
    local artifacts=$(docker run --platform linux/$platformarch --name $containername $package-build-$distro-$arch)
    for artifact in $artifacts; do
        docker cp --quiet $containername:$artifact $(get_current_dir)/
    done
    docker rm -f $containername > /dev/null 2>&1
    echo "Done with for $distro on $arch, produced artifacts:"
    for artifact in $artifacts; do
        echo "  $(get_current_dir)/$(basename $artifact)"
    done
}

# main function.

#
# Parse the arguments and execute the builds
#
function parse_and_build() {
    local package="$PACKAGE"
    local repo_url="$GITHUB_REPO"
    local repo_commit="HEAD"
    local verbose=0
    local no_cache=0
    local args=()
    local numprocs=$(nproc)
    local proxyrootca=""
    local config_args=""

    # Parse optional arguments
    while [[ "$1" == --* || "$1" == -* ]]; do
        case "$1" in
	    --package|-p)
		shift
		package="$1"
		;;
            --repo|-r)
                shift
                repo_url="$1"
                ;;
            --commit|-c)
                shift
                repo_commit="$1"
                ;;
            --verbose|-v)
                if [ "$verbose" -lt 2 ]; then
                    verbose=$(($verbose + 1))
                fi
                ;;
            -vv)
                verbose=2
                ;;
            --no-cache|-n)
                no_cache=1
                ;;
            --max-procs|-j)
                shift
                numprocs="$1"
                # Validate the number of processes:
                # - Must be a positive integer
                # - Must be less than or equal to the number of CPUs
                if ! [[ "$numprocs" =~ ^[0-9]+$ ]] || [ "$numprocs" -le 0 ] || [ "$numprocs" -gt "$(nproc)" ]; then
                    echo "Invalid number of processes: $numprocs"
                    usage
                fi
                ;;
            --proxyrootca|-x)
                shift
                proxyrootca="$1"
                ;;
            --config-args)
                shift
                config_args="$1"
                ;;
            --help|-h)
                usage
                ;;
            *)
                echo "Unknown option: $1"
                usage
                ;;
        esac
        shift
    done

    # proxy root CA must be treated from here
    # if proxyrootca is unset, create a dummy file
    # if proxyrootca is set, copy the root CA file to the script directory
    if [ -z "$proxyrootca" ]; then
        echo -n >$(get_script_dir)/proxyrootca.crt
    else
        copy_root_ca "$proxyrootca"
    fi
    proxyrootca="proxyrootca.crt"

    # If config_args is unset, set it to a dummy value
    if [ -z "$config_args" ]; then
        config_args="DUMMY=dummy"
    fi

    # Collect remaining arguments
    local args=("$@")

    local build_args=()

    for arg in "${args[@]}"; do
        if [[ "$arg" == "all/all" ]]; then
            for distro in $SUPPORTED_DISTROS; do
                for arch in $SUPPORTED_ARCHS; do
                    build_args+=("$package $distro $arch $verbose $no_cache $repo_url $repo_commit $proxyrootca $config_args")
                done
            done
        elif [[ "$arg" == "all" ]]; then
            local host_arch=$(uname -m)
            for distro in $SUPPORTED_DISTROS; do
                build_args+=("$package $distro $host_arch $verbose $no_cache $repo_url $repo_commit $proxyrootca $config_args")
            done
        elif [[ "$arg" == */* ]]; then
            IFS='/' read -r distro arch_list <<< "$arg"
            if [[ "$arch_list" == "all" ]]; then
                for arch in $SUPPORTED_ARCHS; do
                    build_args+=("$package $distro $arch $verbose $no_cache $repo_url $repo_commit $proxyrootca $config_args")
                done
            else
                IFS=',' read -ra archs <<< "$arch_list"
                for arch in "${archs[@]}"; do
                    build_args+=("$package $distro $arch $verbose $no_cache $repo_url $repo_commit $proxyrootca $config_args")
                done
            fi
        else
            IFS=',' read -ra distros <<< "$arg"
            local host_arch=${rev_arch_map[$(uname -m)]:-$(uname -m)}
            for distro in "${distros[@]}"; do
                build_args+=("$package $distro $host_arch $verbose $no_cache $repo_url $repo_commit $proxyrootca $config_args")
            done
        fi
    done

    export -f create_build
    export -f get_current_dir
    export -f get_script_dir
    export -f gen_random_container_name

    # Run builds in parallel, limiting to the number of jobs specified by the user
    printf "%s\n" "${build_args[@]}" | xargs -P $numprocs -I {} bash -c 'create_build {}'
}

#
# Main logic
#
if [[ "$#" -lt 1 ]]; then
    usage
fi

parse_and_build "$@"

# EOF
