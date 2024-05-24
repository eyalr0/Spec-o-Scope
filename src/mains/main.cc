#include "experiments.h"
#include "util.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {
#ifdef WASM
    initialize_custom();
#endif
    if (argc >= 2) {
        for (auto current : experiments) {
            if (strcmp(current.experiment_name, argv[1]) == 0) {
                return current.experiment_func(argc, argv);
            }
        }
    }
#ifdef WASM
    // Hardwire amplification test.
    return experiments[0].experiment_func(argc, argv);
#endif

    printf("Usage: %s [experiment]\n\n", argv[0]);
    // TODO: print the descriptions in the same alignment.
    for (auto current : experiments) {
        printf("%*s\t\t%s\n\n", 30, current.experiment_name, current.description);
    }
    return 0;
}