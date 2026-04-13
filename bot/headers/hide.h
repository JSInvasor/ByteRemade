#pragma once

#ifndef HIDE_H
#define HIDE_H

#include <sys/types.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <fcntl.h>

void hide(int argc, char** argv);

#endif // HIDE_H
