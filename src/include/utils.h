#ifndef UTILS_H
#define UTILS_H

// Function declarations for utility functions
char* bytes_to_hex(const uint8_t* bytes, size_t len);
void register_signal_handlers(void (*handler)(int));

#endif // UTILS_H
