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
    SizePin { n_in: 1, n_out: 2, bytes: [Some(1364), Some(1364), Some(1364), Some(1459), Some(1459), Some(1459), Some(1555), Some(1555), Some(1731), Some(1731), None] },
    SizePin { n_in: 1, n_out: 4, bytes: [Some(1782), Some(1782), Some(1782), Some(1877), Some(1877), Some(1877), Some(2037), Some(2037), Some(2213), Some(2213), None] },
    SizePin { n_in: 1, n_out: 8, bytes: [Some(2618), Some(2618), Some(2618), Some(2713), Some(2713), Some(2713), Some(3001), Some(3001), Some(3177), Some(3177), None] },
    SizePin { n_in: 2, n_out: 2, bytes: [Some(1429), Some(1429), Some(1429), Some(1524), Some(1524), Some(1524), Some(1620), Some(1620), Some(1932), Some(1932), Some(1388)] },
    SizePin { n_in: 2, n_out: 4, bytes: [Some(1847), Some(1847), Some(1847), Some(1942), Some(1942), Some(1942), Some(2102), Some(2102), Some(2414), Some(2414), None] },
    SizePin { n_in: 1, n_out: 16, bytes: [None, None, None, None, None, None, None, None, None, None, None] },
    SizePin { n_in: 2, n_out: 8, bytes: [Some(2683), Some(2683), Some(2683), Some(2778), Some(2778), Some(2778), Some(3066), Some(3066), Some(3378), Some(3378), None] },
    SizePin { n_in: 3, n_out: 2, bytes: [Some(1494), Some(1494), Some(1494), Some(1589), Some(1589), Some(1589), Some(1685), Some(1685), Some(2133), Some(2133), None] },
    SizePin { n_in: 3, n_out: 4, bytes: [Some(1912), Some(1912), Some(1912), Some(2007), Some(2007), Some(2007), Some(2167), Some(2167), Some(2615), Some(2615), None] },
    SizePin { n_in: 2, n_out: 16, bytes: [None, None, None, None, None, None, None, None, None, None, None] },
    SizePin { n_in: 3, n_out: 8, bytes: [Some(2748), Some(2748), Some(2748), Some(2843), Some(2843), Some(2843), Some(3131), Some(3131), Some(3579), Some(3579), None] },
    SizePin { n_in: 4, n_out: 2, bytes: [Some(1559), Some(1559), Some(1559), Some(1654), Some(1654), Some(1654), Some(1750), Some(1750), Some(2334), Some(2334), None] },
    SizePin { n_in: 4, n_out: 4, bytes: [Some(1977), Some(1977), Some(1977), Some(2072), Some(2072), Some(2072), Some(2232), Some(2232), Some(2816), Some(2816), Some(1936)] },
    SizePin { n_in: 4, n_out: 8, bytes: [Some(2813), Some(2813), Some(2813), Some(2908), Some(2908), Some(2908), Some(3196), Some(3196), Some(3780), Some(3780), None] },
    SizePin { n_in: 5, n_out: 2, bytes: [Some(1624), Some(1624), Some(1624), Some(1719), Some(1719), Some(1719), Some(1815), Some(1815), Some(2535), Some(2535), None] },
    SizePin { n_in: 5, n_out: 4, bytes: [Some(2042), Some(2042), Some(2042), Some(2137), Some(2137), Some(2137), Some(2297), Some(2297), Some(3017), Some(3017), None] },
    SizePin { n_in: 4, n_out: 16, bytes: [None, None, None, None, None, None, None, None, None, None, None] },
    SizePin { n_in: 5, n_out: 8, bytes: [Some(2878), Some(2878), Some(2878), Some(2973), Some(2973), Some(2973), Some(3261), Some(3261), Some(3981), Some(3981), None] },
    SizePin { n_in: 6, n_out: 2, bytes: [Some(1689), Some(1689), Some(1689), Some(1784), Some(1784), Some(1784), Some(1880), Some(1880), Some(2736), Some(2736), None] },
    SizePin { n_in: 6, n_out: 4, bytes: [Some(2107), Some(2107), Some(2107), Some(2202), Some(2202), Some(2202), Some(2362), Some(2362), Some(3218), Some(3218), None] },
    SizePin { n_in: 5, n_out: 16, bytes: [None, None, None, None, None, None, None, None, None, None, None] },
    SizePin { n_in: 6, n_out: 8, bytes: [Some(2943), Some(2943), Some(2943), Some(3038), Some(3038), Some(3038), Some(3326), Some(3326), Some(4182), Some(4182), None] },
    SizePin { n_in: 8, n_out: 2, bytes: [Some(1819), Some(1819), Some(1819), Some(1914), Some(1914), Some(1914), Some(2010), Some(2010), Some(3138), Some(3138), None] },
    SizePin { n_in: 8, n_out: 4, bytes: [Some(2237), Some(2237), Some(2237), Some(2332), Some(2332), Some(2332), Some(2492), Some(2492), Some(3620), Some(3620), None] },
    SizePin { n_in: 8, n_out: 8, bytes: [Some(3073), Some(3073), Some(3073), Some(3168), Some(3168), Some(3168), Some(3456), Some(3456), Some(4584), Some(4584), None] },
    SizePin { n_in: 8, n_out: 16, bytes: [None, None, None, None, None, None, None, None, None, None, None] },
    SizePin { n_in: 12, n_out: 2, bytes: [Some(2079), Some(2079), Some(2079), Some(2174), Some(2174), Some(2174), Some(2270), Some(2270), None, None, None] },
    SizePin { n_in: 12, n_out: 4, bytes: [Some(2497), Some(2497), Some(2497), Some(2592), Some(2592), Some(2592), Some(2752), Some(2752), None, None, None] },
    SizePin { n_in: 12, n_out: 8, bytes: [Some(3333), Some(3333), Some(3333), Some(3428), Some(3428), Some(3428), Some(3716), Some(3716), None, None, None] },
    SizePin { n_in: 16, n_out: 2, bytes: [Some(2339), Some(2339), Some(2339), Some(2434), Some(2434), Some(2434), Some(2530), Some(2530), None, None, None] },
    SizePin { n_in: 16, n_out: 4, bytes: [Some(2757), Some(2757), Some(2757), Some(2852), Some(2852), Some(2852), Some(3012), Some(3012), None, None, None] },
    SizePin { n_in: 16, n_out: 8, bytes: [Some(3593), Some(3593), Some(3593), Some(3688), Some(3688), Some(3688), Some(3976), Some(3976), None, None, None] },
    SizePin { n_in: 24, n_out: 2, bytes: [Some(2859), Some(2859), Some(2859), Some(2954), Some(2954), Some(2954), Some(3050), Some(3050), None, None, None] },
    SizePin { n_in: 24, n_out: 4, bytes: [Some(3277), Some(3277), Some(3277), Some(3372), Some(3372), Some(3372), Some(3532), Some(3532), None, None, None] },
    SizePin { n_in: 32, n_out: 2, bytes: [Some(3379), Some(3379), Some(3379), Some(3474), Some(3474), Some(3474), Some(3570), Some(3570), None, None, None] },
    SizePin { n_in: 40, n_out: 2, bytes: [Some(3899), Some(3899), Some(3899), Some(3994), Some(3994), Some(3994), Some(4090), Some(4090), None, None, None] },
    SizePin { n_in: 48, n_out: 2, bytes: [None, None, None, None, None, None, None, None, None, None, None] },
    SizePin { n_in: 49, n_out: 2, bytes: [None, None, None, None, None, None, None, None, None, None, None] },
];
