#ifndef HOARE_INTERVAL_H
#define HOARE_INTERVAL_H

#include <stdint.h>
#include <stdbool.h>

#define WASM_PAGE_BYTES 65536

typedef struct {
    int64_t lower;
    int64_t upper;
} Interval;

Interval interval_add(Interval a, Interval b);
Interval interval_sub(Interval a, Interval b);
Interval interval_join(Interval a, Interval b);
bool interval_is_safe_deref(Interval ptr, int64_t offset, uint32_t allocated_pages);

#endif /* HOARE_INTERVAL_H */
