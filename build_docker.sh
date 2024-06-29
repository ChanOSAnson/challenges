#!/bin/bash

### Process variables ###
# Default variables
IMAGE_NAME="cz4067-challenge"
CHALLENGE_FOLDER=$IMAGE_NAME
DOMAIN="http://localhost"
PORT=3100
TEST="ci"
PRIVILEGE=0
EXPLOIT_NEED_MANUAL=0 # 1 means challenge can only be solved with human; 0 means solvable with just a script

# Utility Functions
usage() { # Function: Print a help message.
    echo "Usage: $0 [ -i IMAGE_NAME ] [ -d DOMAIN ] [ -p PORT ] [ -t TEST ] [ -f CHALLENGE_FOLDER ] [ -b BINARY_NAME ] [ -s PYSCRIPT_NAME ] [ -m ] [ -P ]" 1>&2
}
exit_abnormal() { # Function: Exit with error.
    usage
    exit 1
}

# Parse Arguments
while getopts "i:p:d:t:f:b:s:mP" opt; do
    case ${opt} in
    i) IMAGE_NAME="${OPTARG}" ;;
    p) PORT="${OPTARG}" ;;
    d) DOMAIN="${OPTARG}" ;;
    t) TEST="${OPTARG}" ;;
    f) CHALLENGE_FOLDER="${OPTARG}" ;;
    m) EXPLOIT_NEED_MANUAL=1 ;;
    P) PRIVILEGE=1 ;;
    b) BINARY_NAME="${OPTARG}" ;;
    s) PYSCRIPT_NAME="${OPTARG}" ;;
    \?)
        echo "Error: Invalid option -$OPTARG" 1>&2
        exit_abnormal
        ;;
    :)
        echo "Error: Option -$OPTARG requires an argument" 1>&2
        exit_abnormal
        ;;
    esac
done

HOST="$DOMAIN:$PORT"
BUILD_OPTIONS=""
# echo $BINARY_NAME
if [ -v BINARY_NAME ]; then
    BUILD_OPTIONS="$BUILD_OPTIONS --build-arg binary=$BINARY_NAME"
fi

if [ -v PYSCRIPT_NAME ]; then
    BUILD_OPTIONS="$BUILD_OPTIONS --build-arg pyfile=$PYSCRIPT_NAME"
fi

echo "=== Parameters supplied in this script ==="
echo "IMAGE_NAME: ${IMAGE_NAME}"
echo "HOST: ${HOST}"
echo "CHALLENGE_FOLDER: ${CHALLENGE_FOLDER}"
echo "TEST: ${TEST}"
echo "EXPLOIT_NEED_MANUAL: ${EXPLOIT_NEED_MANUAL}"
echo "CUSTOMISED OPTIONS TO DOCKER: ${BUILD_OPTIONS}"
echo ""

### Build and run container ###
echo "========= Build and run container ========"

echo $(docker container ls --all --filter=ancestor="fyp2023/$IMAGE_NAME" --format "{{.ID}}") | xargs docker rm -f
docker rmi "fyp2023/${IMAGE_NAME}"
docker build -t "fyp2023/${IMAGE_NAME}" --build-arg port=${PORT} ${BUILD_OPTIONS} ./${CHALLENGE_FOLDER}/deploy
if [ $PRIVILEGE = 1 ]; then
    docker run --name ${IMAGE_NAME} -d -p $PORT:$PORT --privileged --rm -it fyp2023/${IMAGE_NAME}
else
    docker run --name ${IMAGE_NAME} -d -p $PORT:$PORT --rm -it fyp2023/${IMAGE_NAME}
fi

if [ $? = 0 ]; then
    num=1
else
    num=0
fi
echo ""

### Run Test ###
echo "================ Run test ================"
if [ "$EXPLOIT_NEED_MANUAL" = 0 ]; then
    sleep 5 # Wait Docker container to be ready
    output=$(cd "${CHALLENGE_FOLDER}/solution" && python3 "./solution.py" $DOMAIN $PORT)
    num=$(echo "$output" | grep -c "CZ4067")
    echo "Test completed"
fi
echo ""

### Clean up test ###
if [ "$TEST" != "ci" ]; then
    echo "============= Clean up test =============="
    echo "Test only: delete Docker container"
    echo $(docker container ls --all --filter=ancestor="fyp2023/$IMAGE_NAME" --format "{{.ID}}") | xargs docker rm -f
    echo ""
fi

### Evaluate results ###
echo "============ Build/ test result =========="
if [ "$num" = 1 ]; then
    echo "Test passed, build successful"
    exit 0
else
    echo "Test failed with exit code $num"
    echo "$output"
    exit 1
fi
