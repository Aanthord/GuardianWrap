#ifndef IMMUTABLE_LOGGER_H
#define IMMUTABLE_LOGGER_H

// This inclusion guard prevents the header from being processed
// multiple times, which is essential for preventing redefinition errors

// Declaration of the immutable_append function
// This function is designed to append data to an immutable log file.
// It ensures that once data is written, it cannot be modified or deleted,
// adhering to the principles of immutability for log data.
void immutable_append(const char *data);

#endif // IMMUTABLE_LOGGER_H
// End of the inclusion guard

