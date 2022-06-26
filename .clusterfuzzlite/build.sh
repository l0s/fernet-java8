#!/bin/sh

set -e
set -u
set -x

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

RUNTIME_CLASSPATH="${OUT}/fernet-java8.jar:${OUT}/fernet-fuzzer.jar"

# if there are more fuzzers, turn this into a loop

cp /src/default.options "${OUT}/TokenEncryptDecryptFuzzer.options"

# TODO use m4 template
# TODO shellcheck generated file
cat << EOF > "${OUT}/TokenEncryptDecryptFuzzer"
#!/bin/sh

set -e
set -x

# Magic comment, do not remove:
# LLVMFuzzerTestOneInput
# It's required by ClusterFuzzLine test_all.py
# https://github.com/google/oss-fuzz/blob/1d588e62cdc119f676316fbcab13cc331c7fb08c/infra/base-images/base-runner/test_all.py#L95
# It's how the framework identifies that this file is a fuzz target

this_dir=\$(dirname "\$0")
export LD_LIBRARY_PATH=${JVM_LD_LIBRARY_PATH}
export ASAN_OPTIONS="\${ASAN_OPTIONS}:symbolize=1:external_symbolizer_path=\${this_dir}/llvm-symbolizer:detect_leaks=0"
"\${this_dir}/jazzer_driver" \
  --agent_path="\${this_dir}/jazzer_agent_deploy.jar" \
  --cp="${RUNTIME_CLASSPATH}" \
  --target_class=TokenEncryptDecryptFuzzer \
  --jvm_args="-Xmx2048m:-Djava.awt.headless=true" \
  $@
EOF
chmod +x "${OUT}/TokenEncryptDecryptFuzzer"
