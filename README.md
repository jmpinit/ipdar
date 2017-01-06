# ipdar

Utility which publishes live ARP info via ZMQ.

Written to watch for new hosts on a network, but maybe useful for other things.

## Dependencies

* ZMQ (`brew install zeromq` or `sudo apt-get install libzmq-dev`)
* LibPCAP (`brew install pcap` or `sudo apt-get install libpcap-dev`)

## Building

`make ipdar`

## Example

1. `make example`
2. `./ipdar en0 tcp://127.0.0.1:1337; ./example tcp://127.0.0.1:1337`
