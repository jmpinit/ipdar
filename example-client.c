#include <zmq.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>

#include "zhelpers.h"

#define forever for(;;)

int main (int argc, char *argv []) {
  if (argc != 2) {
    fprintf(stderr, "usage: example-client <zmq address>\n");
    exit(1);
  }

  char *zmqAddress = argv[1];

  void *context = zmq_ctx_new();
  void *subscriber = zmq_socket(context, ZMQ_SUB);
  int rc = zmq_connect(subscriber, zmqAddress);
  assert(rc == 0);
  zmq_setsockopt(subscriber, ZMQ_SUBSCRIBE, "", 0);

  forever {
    char *tmac = s_recv(subscriber);
    char *tip = s_recv(subscriber);
    char *smac = s_recv(subscriber);
    char *sip = s_recv(subscriber);

    printf("[%s] %s -> [%s] %s\n", smac, sip, tmac, tip);

    free(tmac);
    free(tip);
    free(smac);
    free(sip);
  }

  zmq_close(subscriber);
  zmq_term(context);

  return 0;
}