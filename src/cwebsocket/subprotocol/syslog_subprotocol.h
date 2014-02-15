#ifndef SYSLOG_SUBPROTOCOL_H_
#define SYSLOG_SUBPROTOCOL_H_

#include "../common.h"
#include "../client.h"

#ifdef __cplusplus
extern "C" {
#endif

cwebsocket_subprotocol* cwebsocket_subprotocol_syslog_new();

#ifdef __cplusplus
}
#endif

#endif
