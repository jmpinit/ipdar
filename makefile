ipdar: ipdar.c
	gcc -o ipdar $< -lzmq -lpcap

example: example-client.c
	gcc -o example $< -lzmq -lpcap
