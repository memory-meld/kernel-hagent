#include "mt19937.h"

DEFINE_PER_CPU(u64[MT19937_NN], mt19947_mt) = {};
DEFINE_PER_CPU(u64, mt19947_mti) = MT19937_NN + 1;

// clang-format off
u64 mt19937(void)
{
	static u64 const mag01[2] = { 0ULL, MT19937_MATRIX_A };
	// The array for the state vector
	u64 *mt = this_cpu_ptr(mt19947_mt);
	u64 mti = this_cpu_read(mt19947_mti);
	// mti==NN+1 means mt[NN] is not initialized
	if (mti >= MT19937_NN) {
		// generate NN words at one time
		// if init_genrand64() has not been called,
		// a default initial seed 5489ULL is used
		if (mti == MT19937_NN + 1) {
			mt[0] = MT19937_SEED;
			for (mti = 1; mti < MT19937_NN; ++mti) {
				mt[mti] = 6364136223846793005ULL * (mt[mti - 1] ^ (mt[mti - 1] >> 62)) + mti;
			}
		}
		for (int i = 0; i < MT19937_NN - MT19937_MM; i++) {
			u64 x = (mt[i] & MT19937_UM) | (mt[i + 1] & MT19937_LM);
			mt[i] = mt[i + MT19937_MM] ^ (x >> 1) ^ mag01[x & 1ULL];
		}
		for (int i = MT19937_NN - MT19937_MM; i < MT19937_NN - 1; i++) {
			u64 x = (mt[i] & MT19937_UM) | (mt[i + 1] & MT19937_LM);
			mt[i] = mt[i + (MT19937_MM - MT19937_NN)] ^ (x >> 1) ^ mag01[x & 1ULL];
		}
		u64 x = (mt[MT19937_NN - 1] & MT19937_UM) | (mt[0] & MT19937_LM);
		mt[MT19937_NN - 1] = mt[MT19937_MM - 1] ^ (x >> 1) ^ mag01[x & 1ULL];
		mti = 0;
	}
	u64 x = mt[mti++];
	this_cpu_write(mt19947_mti, mti);
	x ^= (x >> 29) & 0x5555555555555555ULL; x ^= (x << 17) & 0x71D67FFFEDA60000ULL;
	x ^= (x << 37) & 0xFFF7EEE000000000ULL; x ^= (x >> 43);
	return x;
}
// clang-format on
