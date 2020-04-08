#ifndef LOGGER_H_
#define LOGGER_H_

#include <stdio.h>

class Logger {

public:
    void info(const char* pattern) {
        printf("\033[37;43m[INFO]\033[0m ");
        printf(pattern);
        printf("\n");
    }

    void info(const char* pattern, int x) {
        printf("\033[37;43m[INFO]\033[0m ");
        printf(pattern, x);
        printf("\n");
    }

    void info(const char* pattern, const char* s, int x) {
        printf("\033[37;43m[INFO]\033[0m ");
        printf(pattern, s, x);
        printf("\n");
    }

    void error(const char* pattern) {
        printf("\033[37;41m[ERROR]\033[0m ");
        printf(pattern);
        printf("\n");
    }

    void error(const char* pattern, int x) {
        printf("\033[37;41m[ERROR]\033[0m ");
        printf(pattern, x);
        printf("\n");
    }

    void error(const char* pattern, const char* s) {
        printf("\033[37;41m[ERROR]\033[0m ");
        printf(pattern, s);
        printf("\n");
    }
};

#endif