# shift-base UB in PureDB's big-endian decode (relaxed in build.sh, not fixed upstream)

`puredb/src/puredb_read.c:69` (`read_be_long`) decodes each u32 as
`mapoffset[0] << 24 | mapoffset[1] << 16 | ...`. `mapoffset[0]` is an `unsigned char` promoted to
`int`, so any first byte >= 0x80 shifts into the sign bit: UBSan `shift-base`, "left shift of 128 by
24 places cannot be represented in type 'int'". libFuzzer hit it within 2000 runs from the seeds
(any `.pdb` whose hash-table or record offset has the top bit set).

Impact: none on the usual LP64/two's-complement targets (the result is converted to
`puredb_u32_t` and the bits are as intended). It fires on most mutated inputs, so build.sh relaxes
only `-fno-sanitize=shift-base` for the fuzz build to keep the real PureDB bugs reachable.

One-line upstream fix: cast before shifting, `(puredb_u32_t) mapoffset[0] << 24 | ...`.
