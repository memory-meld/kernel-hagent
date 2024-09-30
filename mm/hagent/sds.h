#ifndef HAGENT_PLACEMENT_SDS_H
#define HAGENT_PLACEMENT_SDS_H

#include "vector.h"

typedef u16 sds_fp_t;
typedef u16 sds_cnt_t;

struct sds_slot {
	sds_fp_t fingerprint;
	sds_cnt_t count;
};
struct sds {
	u64 w, d;
	// a vector of w * d slots
	struct vector slots;
};

noinline u64 sds_hash(u64 key, u64 i);
noinline void sds_drop(struct sds *s);
noinline int __must_check sds_init(struct sds *s, u64 w, u64 d);
noinline int __must_check sds_init_default(struct sds *s);
noinline struct sds_slot *sds_at_hinted(struct sds *s, u64 hash, u64 i);
noinline struct sds_slot *sds_at(struct sds *s, u64 key, u64 i);
noinline u16 sds_get(struct sds *s, u64 key);
noinline u16 sds_push_multiple(struct sds *s, u64 key, u16 delta);
u16 sds_push(struct sds *s, u64 key);

extern ulong streaming_decaying_sketch_width;
extern ulong streaming_decaying_sketch_depth;
DECLARE_STATIC_KEY_TRUE(should_decay_sketch);

#endif // !HAGENT_PLACEMENT_SDS_H
