#include "hoare_interval.h"

Interval interval_add(Interval a, Interval b) {
    Interval res;
    res.lower = a.lower + b.lower;
    res.upper = a.upper + b.upper;
    return res;
}

Interval interval_sub(Interval a, Interval b) {
    Interval res;
    res.lower = a.lower - b.upper;
    res.upper = a.upper - b.lower;
    return res;
}

Interval interval_join(Interval a, Interval b) {
    Interval res;
    res.lower = a.lower < b.lower ? a.lower : b.lower;
    res.upper = a.upper > b.upper ? a.upper : b.upper;
    return res;
}

bool interval_is_safe_deref(Interval ptr, int64_t offset, uint32_t allocated_pages) {
    int64_t eff_low = ptr.lower + offset;
    int64_t eff_high = ptr.upper + offset;
    int64_t max_bytes = (int64_t)allocated_pages * WASM_PAGE_BYTES;

    if (eff_low < 0) return false;
    if (eff_high + 4 > max_bytes) return false;
    return true;
}
