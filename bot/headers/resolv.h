#pragma once

#ifndef RESOLV_H
#define RESOLV_H

char* resolv(const char* domain);
char *resolv_with_retry(const char *domain);

#endif // RESOLV_H
