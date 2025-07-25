#pragma once

#include <stdbool.h>
#include <stdio.h> 

void usage();

typedef struct {
    char* dev_;
} Param;

extern Param param;

bool parse(Param* param, int argc, char* argv[]);