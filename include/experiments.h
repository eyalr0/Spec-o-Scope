#pragma once

/*
    This file contains the various main functions of our experiments.
*/

typedef int (*experiment_function_func_type)(int argc, char *argv[]);

int test_aes_break(int argc, char *argv[]);
int test_aes_break2(int argc, char *argv[]);
int paper_experiments(int argc, char *argv[]);
int test_prime_scope(int argc, char *argv[]);
int test_fetch(int argc, char *argv[]);

typedef struct {
    const char *experiment_name;
    experiment_function_func_type experiment_func;
    const char *description;
} experiment_descriptor;

static experiment_descriptor experiments[] = {
    { "test_aes_break", test_aes_break, "Test AES breaking." },
    { "test_aes_break2", test_aes_break2, "Test AES breaking 2." },
    { "paper_experiments", paper_experiments, "Paper Experiments" },
    { "test_prime_scope", test_prime_scope, "Test Prime+Scope." },
    { "test_fetch", test_fetch, "Test fetching rdtsc" },
};
