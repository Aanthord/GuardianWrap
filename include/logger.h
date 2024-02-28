#ifndef LOGGER_H
#define LOGGER_H

#include <stdint.h> // For uint8_t

void init_logger();
void log_message(const char *message);
void close_logger();

#endif // LOGGER_H

