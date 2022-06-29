#!/bin/sh

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

set -eu

this_dir=$(dirname "$0")
CLASSPATH=xCLASSPATH

OIFS="$IFS"
IFS=:
for element in $CLASSPATH; do
  test -r "$element"
done
IFS="$OIFS"
test -x "${this_dir}/jazzer_driver"
test -r "${this_dir}/jazzer_agent_deploy.jar"

# Magic comment, do not remove:
# LLVMFuzzerTestOneInput
# It's required by ClusterFuzzLite test_all.py
# https://github.com/google/oss-fuzz/blob/1d588e62cdc119f676316fbcab13cc331c7fb08c/infra/base-images/base-runner/test_all.py#L95
# It's how the framework identifies that this file is a fuzz target

export LD_LIBRARY_PATH=xLD_LIBRARY_PATH
export ASAN_OPTIONS="${ASAN_OPTIONS}:symbolize=1:external_symbolizer_path=${this_dir}/llvm-symbolizer:detect_leaks=0"
"${this_dir}/jazzer_driver" \
  --agent_path="${this_dir}/jazzer_agent_deploy.jar" \
  --cp="${CLASSPATH}" \
  --target_class=TokenEncryptDecryptFuzzer \
  --jvm_args="-Xmx2048m:-Djava.awt.headless=true" \
  "$@"
