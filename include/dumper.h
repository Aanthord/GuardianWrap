#ifndef DUMPER_H
#define DUMPER_H

// Standard guard against multiple inclusions
// Prevents redefinition errors during compilation

// Declaration of the function to collect and record stack dumps
// This function is implemented in dumper.c and can be called from
// other parts of the program to capture the current stack trace
void collect_stack_dump();

#endif // DUMPER_H
// End of the standard inclusion guard

