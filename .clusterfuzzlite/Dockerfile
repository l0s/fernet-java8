#   Copyright 2022 Carlos Macasaet
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       https://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

FROM gcr.io/oss-fuzz-base/base-builder-jvm:v1
RUN apt-get update \
  && apt-get install -y make autoconf automake libtool maven shellcheck
COPY . $SRC/.clusterfuzzlite
WORKDIR .clusterfuzzlite
COPY .clusterfuzzlite/build.sh $SRC/
COPY .clusterfuzzlite/default.options $SRC/
COPY .clusterfuzzlite/fuzz_target.m4 $SRC/
COPY .clusterfuzzlite/fernet-fuzzer $SRC/.clusterfuzzlite/fernet-fuzzer/
