#ifndef _MOBERTIGO_PARAMETERS_H_
#define _MOBERTIGO_PARAMETERS_H_

/*****************************************************************************
 *                              SIZES                                        *
 *****************************************************************************/
#define BERTI_TABLE_SIZE (64)
#define BERTI_TABLE_DELTA_SIZE (16)
#define PC_PATH_HISTORY_SIZE (4)

// Enable the MO_hash prediction channel (memory object identity signature).
// Disabled by default: MO_hash competes with IP/PC_Path for Berti Table and
// HistoryTable capacity, which can degrade performance. Kept for evaluation.
// # define ENABLE_MO_HASH

// (Sizes summarized above)
#define HISTORY_TABLE_SETS (48)
#define HISTORY_TABLE_WAYS (32)

// Hash Function
// #define HASH_FN
// # define HASH_ORIGINAL
// # define THOMAS_WANG_HASH_1
// # define THOMAS_WANG_HASH_2
// # define THOMAS_WANG_HASH_3
// # define THOMAS_WANG_HASH_4
// # define THOMAS_WANG_HASH_5
// # define THOMAS_WANG_HASH_6
// # define THOMAS_WANG_HASH_7
// # define THOMAS_WANG_NEW_HASH
// # define THOMAS_WANG_HASH_HALF_AVALANCHE
// # define THOMAS_WANG_HASH_FULL_AVALANCHE
// # define THOMAS_WANG_HASH_INT_1
// # define THOMAS_WANG_HASH_INT_2
#define ENTANGLING_HASH
// # define FOLD_HASH

/*****************************************************************************
 *                              MASKS                                        *
 *****************************************************************************/
#define SIZE_IP_MASK (64)
#define IP_MASK (0xFFFF)
#define TIME_MASK (0xFFFF)
#define LAT_MASK (0xFFF)
#define ADDR_MASK (0xFFFFFF)
#define DELTA_MASK (12)
#define TABLE_SET_MASK (0x7)

/*****************************************************************************
 *                      CONFIDENCE VALUES                                    *
 *****************************************************************************/
#define CONFIDENCE_MAX (16) // 6 bits
#define CONFIDENCE_INC (1)  // 6 bits
#define CONFIDENCE_INIT (1) // 6 bits

// TODO: chekc of limit
// NOTE: comparisons use '>', so effective promotion threshold = value + 1.
// e.g. CONFIDENCE_L1 = 5 means conf >= 6 promotes to L1D issue.
#define CONFIDENCE_L1 (5) // 6 bits - conf > 5 (>=6)  -> issue to L1D
#define CONFIDENCE_L2 (4) // 6 bits - conf > 4 (>=5)  -> issue to L2C (mid)
#define CONFIDENCE_L2R (2) // 6 bits - conf > 2 (>=3) -> issue to L2C (low)

// High-confidence boundary used by the tiered MSHR scheme.
// Deltas with conf >= this value are considered fully validated (they would
// have been L1D-eligible at the original conservative threshold) and are
// allowed to issue to L1D even under heavier MSHR pressure.
#define CONFIDENCE_L1_HIGH_BOUND (10)

#define CONFIDENCE_MIDDLE_L1 (14) // 6 bits
#define CONFIDENCE_MIDDLE_L2 (12) // 6 bits
#define LAUNCH_MIDDLE_CONF (8)

/*****************************************************************************
 *                              LIMITS                                       *
 *****************************************************************************/
// Tiered MSHR thresholds: high-confidence deltas can fill L1D under heavier
// MSHR pressure, while mid/low-confidence deltas are kept more conservative.
#define MSHR_LIMIT_HIGH_CONF (85) // conf >= CONFIDENCE_L1_HIGH_BOUND: almost never rejected
#define MSHR_LIMIT_MID_CONF (75)  // conf >= CONFIDENCE_L1: moderately allowed
#define MSHR_LIMIT_LOW_CONF (60)  // conf <  CONFIDENCE_L1: strict

// Legacy aggregate limit (kept for reference/compatibility)
#define MSHR_LIMIT (MSHR_LIMIT_MID_CONF)

/*****************************************************************************
 *                              CONSTANT PARAMETERS                          *
 *****************************************************************************/
#define BERTI_R (0x0)
#define BERTI_L1 (0x1)
#define BERTI_L2 (0x2)
#define BERTI_L2R (0x3)
#endif