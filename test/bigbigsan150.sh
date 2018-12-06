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

./p11req -l /usr/lib/x86_64-linux-gnu/nss/libsoftokn3.so -m sql:. -i bigbigsan150 -k 2048 -h sha1 -d '/CN=bigbigsan-150/OU=KMS TS/O=MasterCard Worldwide/C=BE' \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-1.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-2.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-3.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-4.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-5.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-6.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-7.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-8.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-9.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-10.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-11.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-12.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-13.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-14.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-15.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-16.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-17.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-18.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-19.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-20.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-21.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-22.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-23.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-24.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-25.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-26.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-27.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-28.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-29.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-30.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-31.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-32.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-33.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-34.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-35.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-36.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-37.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-38.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-39.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-40.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-41.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-42.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-43.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-44.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-45.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-46.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-47.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-48.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-49.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-50.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-51.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-52.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-53.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-54.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-55.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-56.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-57.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-58.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-59.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-60.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-61.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-62.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-63.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-64.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-65.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-66.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-67.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-68.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-69.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-70.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-71.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-72.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-73.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-74.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-75.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-76.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-77.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-78.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-79.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-80.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-81.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-82.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-83.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-84.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-85.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-86.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-87.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-88.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-89.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-90.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-91.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-92.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-93.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-94.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-95.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-96.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-97.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-98.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-99.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-100.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-101.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-102.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-103.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-104.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-105.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-106.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-107.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-108.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-109.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-110.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-111.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-112.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-113.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-114.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-115.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-116.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-117.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-118.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-119.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-120.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-121.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-122.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-123.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-124.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-125.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-126.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-127.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-128.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-129.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-130.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-131.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-132.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-133.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-134.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-135.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-136.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-137.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-138.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-139.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-140.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-141.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-142.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-143.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-144.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-145.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-146.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-147.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-148.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-149.test.com \
-e DNS:sanentry-csr-very-very-very-very-very-very-long-entry-150.test.com \
-s 1 -p changeit


