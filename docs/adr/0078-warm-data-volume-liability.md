# 0078: Account for complete warm data-volume liability

Date: 2026-11-02
Status: source candidate; native validation pending

A paused guest retains its entire writable data device as well as its logical root.
Charging only the root to warm policy understates the space that guest may consume.
Physical allocation and copy-on-write sharing do not reduce this liability.

Add `data_disk_gb` to warm resource budgets and charges. Omitted budgets remain zero,
so existing root-only policies retain their behavior and grant no data-volume budget.
Every unclaimed record charges its complete volume size, including creating, paused,
failed and cleanup-in-progress records. Checked addition rejects aggregate overflow.
A durable claim changes the warm classification without releasing the namespace or
physical reservation. Cleanup releases the liability only when the record is removed.

Use the sum of logical roots and data volumes against measured pool free space,
then preserve the existing absolute and percentage floors once for that shared pool.
The root headroom field continues to report that shared floor; data headroom is zero.
Existing sample freshness, memory headroom, bounded refill and desired decrease remain
in force. Catalog status and host/pool metrics expose the separate data charge and budget.

This accounting change does not enable another template profile, admit volume-bearing
public named clones or authorize cross-namespace ownership transfer. Those lifecycle
boundaries retain their existing validation and default-off configuration.
