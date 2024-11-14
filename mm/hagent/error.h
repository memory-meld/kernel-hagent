#ifndef HAGENT_PLACEMENT_ERROR_H
#define HAGENT_PLACEMENT_ERROR_H

#include <linux/err.h>
#include <linux/errno.h>
#include <linux/errname.h>

// IS_ERR_VALUE() supports upto MAX_ERRNO number of error codes. However, the
// kernel only defined 531 of them with the largest being ENOGRACE.
enum error_code {
	MAX_USED = ENOGRACE,
	// Bad pebs sample
	ECBADSAMPLE,
	// Address not of interest to us
	ECNOTCARE,

	MAX_CODES,
};

inline const char *ecname(int err)
{
#define E(err) [err - MAX_USED] = "-" #err
	static char const *names[] = {
		E(ECBADSAMPLE),
		E(ECNOTCARE),
	};
#undef E
	if (err <= MAX_USED)
		return errname(err);
	if (err < MAX_CODES)
		return names[err - MAX_USED];
	return NULL;
}

#define TRY1(val)                                                        \
	({                                                               \
		__auto_type __val = (val);                               \
		bool __is_pointer = __builtin_classify_type(__val) == 5; \
		if ((ulong)(__val) >= (ulong)(-MAX_ERRNO) ||             \
		    (__is_pointer && !__val))                            \
			return (long)__val ?: -EFAULT;                   \
		__val;                                                   \
	})

#define TRYn(val, ...)                                                      \
	({                                                                  \
		__auto_type __val = (val);                                  \
		bool __is_pointer = __builtin_classify_type(__val) == 5;    \
		if ((ulong)(__val) >= (ulong)(-MAX_ERRNO) ||                \
		    (__is_pointer && !__val)) {                             \
			pr_err("TRY(%pe) failed at %s:%d %s caller %pSR\n", \
			       (void *)(ulong)__val, __FILE__, __LINE__,    \
			       __func__, __builtin_return_address(0));      \
			pr_err(__VA_ARGS__);                                \
			return (long)__val ?: -EFAULT;                      \
		}                                                           \
		__val;                                                      \
	})

#define GET_TRY(_0, _1, _2, _3, _4, _5, _6, _7, _8, _9, NAME, ...) NAME
#define TRY(...)                                                             \
	GET_TRY(_0, ##__VA_ARGS__, TRYn, TRYn, TRYn, TRYn, TRYn, TRYn, TRYn, \
		TRYn, TRY1, BUILD_BUG)                                             \
	(__VA_ARGS__)

#define UNWRAP(val, ...)                                                             \
	({                                                                           \
		__auto_type __val = (val);                                           \
		bool __is_pointer = __builtin_classify_type(__val) == 5;             \
		if ((ulong)(__val) >= (ulong)(-MAX_ERRNO) ||                         \
		    (__is_pointer && !__val)) {                                      \
			pr_err("RTREE_UNWRAP(%pe) failed at %s:%d %s caller %pSR\n", \
			       (void *)(ulong)__val, __FILE__, __LINE__,             \
			       __func__, __builtin_return_address(0));               \
			pr_err(__VA_ARGS__);                                         \
			dump_stack();                                                \
			BUG();                                                       \
		}                                                                    \
		__val;                                                               \
	})

#endif // HAGENT_PLACEMENT_ERROR_H
