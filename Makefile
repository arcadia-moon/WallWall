ROOT_PATH := ${PWD}
BUILD_DIR := ${ROOT_PATH}/build
HEADER_DIR := ${ROOT_PATH}/header
SOURCE_DIR := ${ROOT_PATH}/source

all : wallwall

wallwall: main.o packet.o
	g++ -g -o ${BUILD_DIR}/wallwall ${BUILD_DIR}/main.o ${BUILD_DIR}/packet.o -lnetfilter_queue

main.o: makeBuildFolder
	g++ -g -c -o ${BUILD_DIR}/main.o ${SOURCE_DIR}/main.cpp

packet.o: makeBuildFolder
	g++ -g -c -o ${BUILD_DIR}/packet.o ${SOURCE_DIR}/protocol/packet.cpp

makeBuildFolder:
	mkdir -p ${BUILD_DIR}

clean:
	rm -f ${BUILD_DIR}/*

