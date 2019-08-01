# WallWall
DSM Summer Camp Filewall 

## Pre Running Setting

### use netfilter queue
```
$ sudo iptables -F
$ sudo iptables -A OUTPUT -j NFQUEUE --queue-num 0
$ sudo iptables -A INPUT -j NFQUEUE --queue-num 0
```
### json lib build
```
$ make json
```
## build
```
$ make
```
## build clean
```
$ make clean
```
## run
```
$ sudo ./build/wallwall 0
```
## Management Rules File Path
```
$ ./build/rules.txt
```