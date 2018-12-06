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

./p11req -l /usr/lib/x86_64-linux-gnu/nss/libsoftokn3.so -m sql:. -i testsan2 -k 2048 -h sha1 -d '/CN=mysantest' \
-e DNS:sanentry-csr1 \
-e DNS:sanentry-csr2 \
-e DNS:sanentry-csr3

