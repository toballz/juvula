// args.h
#ifndef ARGS_H
#define ARGS_H

#include <string>

struct Args {
    std::string mode;
    std::string file;
    std::string dir;
    std::string key;
    bool help = false;
};

#endif // ARGS_H