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

# Build the project to fuzz and extract the version
mvn --batch-mode \
  -Dmaven.test.skip=true \
  -DskipTests \
  --projects fernet-java8 \
  --also-make \
  install
artifact_version=$(mvn --file fernet-java8/pom.xml \
  org.apache.maven.plugins:maven-help-plugin:3.2.0:evaluate \
  -Dexpression=project.version -q -DforceStdout)
cp "fernet-java8/target/fernet-java8-${artifact_version}.jar" \
  "${OUT}/fernet-java8.jar"

# Build the fuzzers

mvn --file fernet-fuzzer/pom.xml \
  --batch-mode \
  -Dfernet.version="$artifact_version" \
  -DskipTests \
  package
cp fernet-fuzzer/target/fernet-fuzzer-*.jar "${OUT}/fernet-fuzzer.jar"

RUNTIME_CLASSPATH="\${this_dir}/fernet-java8.jar:\${this_dir}/fernet-fuzzer.jar"

fuzzers="TokenEncryptDecryptFuzzer TokenDecryptFuzzer"
echo "$fuzzers" | tr ' ' '\n' | while read -r fuzzer
do
  cp "${SRC}/default.options" "${OUT}/${fuzzer}.options"

  m4 -D xCLASSPATH="$RUNTIME_CLASSPATH" \
    -D xLD_LIBRARY_PATH="$JVM_LD_LIBRARY_PATH" \
    "${SRC}/fuzz_target.m4" > "${OUT}/${fuzzer}"
  shellcheck "${OUT}/${fuzzer}"
  chmod +x "${OUT}/${fuzzer}"
done
