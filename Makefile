ROOT_PATH := ${PWD}
BUILD_DIR := ${ROOT_PATH}/build
HEADER_DIR := ${ROOT_PATH}/header
SOURCE_DIR := ${ROOT_PATH}/source

all : wallwall

wallwall: main.o packet.o parser.http.o extension.string.o extension.ifstream.o
	g++ -g -o ${BUILD_DIR}/wallwall ${BUILD_DIR}/main.o ${BUILD_DIR}/packet.o ${BUILD_DIR}/parser/http.o ${BUILD_DIR}/extension/string.o ${BUILD_DIR}/extension/ifstream.o -std=c++11 -lnetfilter_queue

main.o: makeBuildFolder
	g++ -g -c -o ${BUILD_DIR}/main.o ${SOURCE_DIR}/main.cpp

packet.o: makeBuildFolder
	g++ -g -c -o ${BUILD_DIR}/packet.o ${SOURCE_DIR}/protocol/packet.cpp

parser.http.o: makeBuildFolder makeBuildParserFolder
	g++ -g -c -o ${BUILD_DIR}/parser/http.o ${SOURCE_DIR}/parser/http.cpp

extension.string.o: makeBuildFolder makeBuildExtensionFolder
	g++ -g -c -o ${BUILD_DIR}/extension/string.o ${SOURCE_DIR}/extension/string.cpp

extension.ifstream.o: makeBuildFolder makeBuildExtensionFolder
	g++ -g -c -o ${BUILD_DIR}/extension/ifstream.o ${SOURCE_DIR}/extension/ifstream.cpp

makeBuildFolder:
	mkdir -p ${BUILD_DIR}

makeBuildParserFolder:
	mkdir -p ${BUILD_DIR}/parser

makeBuildExtensionFolder:
	mkdir -p ${BUILD_DIR}/extension

clean:
	rm -f ${BUILD_DIR}/*

