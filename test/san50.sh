#!/bin/bash

# Copyright (c) 2018 Mastercard

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#   http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

./p11req -l /usr/lib/x86_64-linux-gnu/nss/libsoftokn3.so -m sql:. -i testsan3 -k 2048 -h sha1 -d '/CN=mysantest50' \
-e DNS:sanentry-csr-1 \
-e DNS:sanentry-csr-2 \
-e DNS:sanentry-csr-3 \
-e DNS:sanentry-csr-4 \
-e DNS:sanentry-csr-5 \
-e DNS:sanentry-csr-6 \
-e DNS:sanentry-csr-7 \
-e DNS:sanentry-csr-8 \
-e DNS:sanentry-csr-9 \
-e DNS:sanentry-csr-10 \
-e DNS:sanentry-csr-11 \
-e DNS:sanentry-csr-12 \
-e DNS:sanentry-csr-13 \
-e DNS:sanentry-csr-14 \
-e DNS:sanentry-csr-15 \
-e DNS:sanentry-csr-16 \
-e DNS:sanentry-csr-17 \
-e DNS:sanentry-csr-18 \
-e DNS:sanentry-csr-19 \
-e DNS:sanentry-csr-20 \
-e DNS:sanentry-csr-21 \
-e DNS:sanentry-csr-22 \
-e DNS:sanentry-csr-23 \
-e DNS:sanentry-csr-24 \
-e DNS:sanentry-csr-25 \
-e DNS:sanentry-csr-26 \
-e DNS:sanentry-csr-27 \
-e DNS:sanentry-csr-28 \
-e DNS:sanentry-csr-29 \
-e DNS:sanentry-csr-30 \
-e DNS:sanentry-csr-31 \
-e DNS:sanentry-csr-32 \
-e DNS:sanentry-csr-33 \
-e DNS:sanentry-csr-34 \
-e DNS:sanentry-csr-35 \
-e DNS:sanentry-csr-36 \
-e DNS:sanentry-csr-37 \
-e DNS:sanentry-csr-38 \
-e DNS:sanentry-csr-39 \
-e DNS:sanentry-csr-40 \
-e DNS:sanentry-csr-41 \
-e DNS:sanentry-csr-42 \
-e DNS:sanentry-csr-43 \
-e DNS:sanentry-csr-44 \
-e DNS:sanentry-csr-45 \
-e DNS:sanentry-csr-46 \
-e DNS:sanentry-csr-47 \
-e DNS:sanentry-csr-48 \
-e DNS:sanentry-csr-49 \
-e DNS:sanentry-csr-50
