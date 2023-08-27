set -ex

image=$1 # e.g. quay.io/cilium/cilium:v1.14.0
target=$2 # e.g. /usr/bin/cilium-agent

rm -fr ./tmp
mkdir ./tmp
cp ./pause_wrapper ./tmp
cd ./tmp
cat > Dockerfile <<EOF
FROM $image.orig
RUN mv $target $target.orig
COPY ./pause_wrapper $target
EOF
docker inspect $image &>/dev/null || docker pull $image
docker tag $image $image.orig
docker rmi $image
docker build -t $image .
