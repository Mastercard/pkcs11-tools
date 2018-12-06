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

./with_nss ../bin/p11req -i t001-rsa-2048 -d /CN=toto
./with_nss ../bin/p11req -i t001-rsa-2048 -d /CN=toto -X
./with_nss ../bin/p11req -i t001-rsa-2048 -d /CN=toto -e email:toto@toto.com
./with_nss ../bin/p11req -i t001-rsa-2048 -d /CN=toto -X -e email:toto@toto.com
./with_nss ../bin/p11req -i test-ecsda-prime256v1 -d /CN=toto
./with_nss ../bin/p11req -i test-ecsda-prime256v1 -d /CN=toto -X
./with_nss ../bin/p11req -i test-ecsda-prime256v1 -d /CN=toto -e email:toto@toto.com
./with_nss ../bin/p11req -i test-ecsda-prime256v1 -d /CN=toto -X -e email:toto@toto.com
./with_nss ../bin/p11req -i t002-dsa-1024 -d /CN=toto
./with_nss ../bin/p11req -i t002-dsa-1024 -d /CN=toto -X
./with_nss ../bin/p11req -i t002-dsa-1024 -d /CN=toto -e email:toto@toto.com
./with_nss ../bin/p11req -i t002-dsa-1024 -d /CN=toto -X -e email:toto@toto.com
./with_nss ../bin/p11req -i t003-dsa-2048 -d /CN=toto
./with_nss ../bin/p11req -i t003-dsa-2048 -d /CN=toto -X
./with_nss ../bin/p11req -i t003-dsa-2048 -d /CN=toto -e email:toto@toto.com
./with_nss ../bin/p11req -i t003-dsa-2048 -d /CN=toto -X -e email:toto@toto.com
