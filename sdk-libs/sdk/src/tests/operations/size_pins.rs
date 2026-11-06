// One table, included by the SDK size test and the validator sweep.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Measured {
    Confidential,
    ConfidentialPolicy,
    ConfidentialEscrow,
    InProofOwner,
    InProofOwnerPolicy,
    InProofOwnerEscrow,
    Anonymous,
    AnonymousPolicy,
    AnonymousEntry,
    AnonymousEntryPolicy,
    Delegate,
}

impl Measured {
    const COLUMNS: [Self; 11] = [
        Self::Confidential,
        Self::ConfidentialPolicy,
        Self::ConfidentialEscrow,
        Self::InProofOwner,
        Self::InProofOwnerPolicy,
        Self::InProofOwnerEscrow,
        Self::Anonymous,
        Self::AnonymousPolicy,
        Self::AnonymousEntry,
        Self::AnonymousEntryPolicy,
        Self::Delegate,
    ];
}

#[derive(Debug, PartialEq, Eq)]
struct SizePin {
    n_in: usize,
    n_out: usize,
    /// One per [`Measured::COLUMNS`] entry, `None` for a shape the rail has no key for.
    bytes: [Option<usize>; Measured::COLUMNS.len()],
}

/// A value past `MAX_TRANSACTION_SIZE` fails assembly.
#[rustfmt::skip]
const SIZE_PINS: [SizePin; 38] = [
    SizePin { n_in: 1, n_out: 2, bytes: [Some(1389), Some(1389), Some(1389), Some(1484), Some(1484), Some(1484), Some(1516), Some(1516), Some(1692), Some(1692), None] },
    SizePin { n_in: 1, n_out: 4, bytes: [Some(1823), Some(1823), Some(1823), Some(1918), Some(1918), Some(1918), Some(2014), Some(2014), Some(2190), Some(2190), None] },
    SizePin { n_in: 1, n_out: 8, bytes: [Some(2691), Some(2691), Some(2691), Some(2786), Some(2786), Some(2786), Some(3010), Some(3010), Some(3186), Some(3186), None] },
    SizePin { n_in: 2, n_out: 2, bytes: [Some(1454), Some(1454), Some(1454), Some(1549), Some(1549), Some(1549), Some(1581), Some(1581), Some(1893), Some(1893), Some(1413)] },
    SizePin { n_in: 2, n_out: 4, bytes: [Some(1888), Some(1888), Some(1888), Some(1983), Some(1983), Some(1983), Some(2079), Some(2079), Some(2391), Some(2391), None] },
    SizePin { n_in: 1, n_out: 16, bytes: [Some(3566), Some(3566), Some(3566), None, None, None, None, None, None, None, None] },
    SizePin { n_in: 2, n_out: 8, bytes: [Some(2756), Some(2756), Some(2756), Some(2851), Some(2851), Some(2851), Some(3075), Some(3075), Some(3387), Some(3387), None] },
    SizePin { n_in: 3, n_out: 2, bytes: [Some(1519), Some(1519), Some(1519), Some(1614), Some(1614), Some(1614), Some(1646), Some(1646), Some(2094), Some(2094), None] },
    SizePin { n_in: 3, n_out: 4, bytes: [Some(1953), Some(1953), Some(1953), Some(2048), Some(2048), Some(2048), Some(2144), Some(2144), Some(2592), Some(2592), None] },
    SizePin { n_in: 2, n_out: 16, bytes: [None, None, None, None, None, None, None, None, None, None, None] },
    SizePin { n_in: 3, n_out: 8, bytes: [Some(2821), Some(2821), Some(2821), Some(2916), Some(2916), Some(2916), Some(3140), Some(3140), Some(3588), Some(3588), None] },
    SizePin { n_in: 4, n_out: 2, bytes: [Some(1584), Some(1584), Some(1584), Some(1679), Some(1679), Some(1679), Some(1711), Some(1711), Some(2295), Some(2295), None] },
    SizePin { n_in: 4, n_out: 4, bytes: [Some(2018), Some(2018), Some(2018), Some(2113), Some(2113), Some(2113), Some(2209), Some(2209), Some(2793), Some(2793), Some(1977)] },
    SizePin { n_in: 4, n_out: 8, bytes: [Some(2886), Some(2886), Some(2886), Some(2981), Some(2981), Some(2981), Some(3205), Some(3205), Some(3789), Some(3789), None] },
    SizePin { n_in: 5, n_out: 2, bytes: [Some(1649), Some(1649), Some(1649), Some(1744), Some(1744), Some(1744), Some(1776), Some(1776), Some(2496), Some(2496), None] },
    SizePin { n_in: 5, n_out: 4, bytes: [Some(2083), Some(2083), Some(2083), Some(2178), Some(2178), Some(2178), Some(2274), Some(2274), Some(2994), Some(2994), None] },
    SizePin { n_in: 4, n_out: 16, bytes: [None, None, None, None, None, None, None, None, None, None, None] },
    SizePin { n_in: 5, n_out: 8, bytes: [Some(2951), Some(2951), Some(2951), Some(3046), Some(3046), Some(3046), Some(3270), Some(3270), Some(3990), Some(3990), None] },
    SizePin { n_in: 6, n_out: 2, bytes: [Some(1714), Some(1714), Some(1714), Some(1809), Some(1809), Some(1809), Some(1841), Some(1841), Some(2697), Some(2697), None] },
    SizePin { n_in: 6, n_out: 4, bytes: [Some(2148), Some(2148), Some(2148), Some(2243), Some(2243), Some(2243), Some(2339), Some(2339), Some(3195), Some(3195), None] },
    SizePin { n_in: 5, n_out: 16, bytes: [None, None, None, None, None, None, None, None, None, None, None] },
    SizePin { n_in: 6, n_out: 8, bytes: [Some(3016), Some(3016), Some(3016), Some(3111), Some(3111), Some(3111), Some(3335), Some(3335), Some(4191), Some(4191), None] },
    SizePin { n_in: 8, n_out: 2, bytes: [Some(1844), Some(1844), Some(1844), Some(1939), Some(1939), Some(1939), Some(1971), Some(1971), Some(3099), Some(3099), None] },
    SizePin { n_in: 8, n_out: 4, bytes: [Some(2278), Some(2278), Some(2278), Some(2373), Some(2373), Some(2373), Some(2469), Some(2469), Some(3597), Some(3597), None] },
    SizePin { n_in: 8, n_out: 8, bytes: [Some(3146), Some(3146), Some(3146), Some(3241), Some(3241), Some(3241), Some(3465), Some(3465), Some(4593), Some(4593), None] },
    SizePin { n_in: 8, n_out: 16, bytes: [None, None, None, None, None, None, None, None, None, None, None] },
    SizePin { n_in: 12, n_out: 2, bytes: [Some(2104), Some(2104), Some(2104), Some(2199), Some(2199), Some(2199), Some(2231), Some(2231), None, None, None] },
    SizePin { n_in: 12, n_out: 4, bytes: [Some(2538), Some(2538), Some(2538), Some(2633), Some(2633), Some(2633), Some(2729), Some(2729), None, None, None] },
    SizePin { n_in: 12, n_out: 8, bytes: [Some(3406), Some(3406), Some(3406), Some(3501), Some(3501), Some(3501), Some(3725), Some(3725), None, None, None] },
    SizePin { n_in: 16, n_out: 2, bytes: [Some(2364), Some(2364), Some(2364), Some(2459), Some(2459), Some(2459), Some(2491), Some(2491), None, None, None] },
    SizePin { n_in: 16, n_out: 4, bytes: [Some(2798), Some(2798), Some(2798), Some(2893), Some(2893), Some(2893), Some(2989), Some(2989), None, None, None] },
    SizePin { n_in: 16, n_out: 8, bytes: [Some(3666), Some(3666), Some(3666), Some(3761), Some(3761), Some(3761), Some(3985), Some(3985), None, None, None] },
    SizePin { n_in: 24, n_out: 2, bytes: [Some(2884), Some(2884), Some(2884), Some(2979), Some(2979), Some(2979), Some(3011), Some(3011), None, None, None] },
    SizePin { n_in: 24, n_out: 4, bytes: [Some(3318), Some(3318), Some(3318), Some(3413), Some(3413), Some(3413), Some(3509), Some(3509), None, None, None] },
    SizePin { n_in: 32, n_out: 2, bytes: [Some(3404), Some(3404), Some(3404), Some(3499), Some(3499), Some(3499), Some(3531), Some(3531), None, None, None] },
    SizePin { n_in: 40, n_out: 2, bytes: [Some(3924), Some(3924), Some(3924), Some(4019), Some(4019), Some(4019), Some(4051), Some(4051), None, None, None] },
    SizePin { n_in: 48, n_out: 2, bytes: [None, None, None, None, None, None, None, None, None, None, None] },
    SizePin { n_in: 49, n_out: 2, bytes: [None, None, None, None, None, None, None, None, None, None, None] },
];
