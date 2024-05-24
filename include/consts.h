#pragma once

// Note: em++ also defines PAGE_SIZE, to the wasm page size which is 65536.
// As a compromise, I settled on PAGE_SIZE_
#define PAGE_SIZE_ (4096)

// Cache properties.
#define CACHE_LINE_SIZE (64)
#define DOUBLE_CACHE_LINE_SIZE (128)

#define L1D_CACHE_ASSOCIATIVITY (8)
#define L1D_SETS (64)
#define L1D_CACHE_SIZE (CACHE_LINE_SIZE * L1D_CACHE_ASSOCIATIVITY * L1D_SETS)
#define L1D_STRIDE (CACHE_LINE_SIZE * L1D_SETS)

#define L2_CACHE_ASSOCIATIVITY (4)
#define L2_SETS (1024)
#define L2_CACHE_SIZE (CACHE_LINE_SIZE * L2_CACHE_ASSOCIATIVITY * L2_SETS)
#define L2_STRIDE (CACHE_LINE_SIZE * L2_SETS)

#define LLC_CACHE_ASSOCIATIVITY (12)
#define LLC_SETS_PER_SLICE (1024)
#define LLC_SLICES (8)
#define LLC_SETS (LLC_SLICES * LLC_SETS_PER_SLICE)
#define LLC_CACHE_SIZE (CACHE_LINE_SIZE * LLC_CACHE_ASSOCIATIVITY * LLC_SETS)



#define RDTSC_THRESHOLD (120)

// ASCII colors
//Regular text
#define RED "\e[0;31m"
#define GRN "\e[0;32m"
#define GRY "\e[30;1m"
//Reset
#define RST "\e[0m"