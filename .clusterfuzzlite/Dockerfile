FROM gcr.io/oss-fuzz-base/base-builder-jvm:v1
RUN apt-get update \
  && apt-get install -y make autoconf automake libtool maven
COPY . $SRC/.clusterfuzzlite
WORKDIR .clusterfuzzlite
COPY .clusterfuzzlite/build.sh $SRC/
COPY .clusterfuzzlite/default.options $SRC/
COPY .clusterfuzzlite/fernet-fuzzer $SRC/.clusterfuzzlite/fernet-fuzzer/
