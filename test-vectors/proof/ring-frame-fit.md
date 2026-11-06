Measured with the frame encoders, SPP's account builders and the v1 compiler. Ceilings 4096 B, 64 accounts, 12 signatures.
min: tracking root, no co-signer, no leg, no fee, the payer an owner where it may be. full: own, curator and tracking roots, one co-signer, 4 SOL legs, a fee, an outside payer, a body on every slot and one exit. The owner run is the ceilings' bound under full, the key's rows bound it apart. A shape's every input and output slot is published.
Every row is one transaction. fits: the row clears the transaction and CPI ceilings. limit: what refuses a row, rail for a shape the rail has no SPP key for, else the excess in accounts, signatures, bytes or CPI data at that row's load. A missing catalog key has no encoded measurement.
| shape | rail | load | catalog key | bytes | accounts | signatures | owner run | frame | SPP CPI | fits | limit |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1x2 | confidential signer | min | yes | 1348 | 9 | 1 | - | 932 | 945 | yes |  |
| 1x2 | confidential signer | full | yes | 1903 | 19 | 3 | 1 | 1019 | 990 | yes |  |
| 1x2 | confidential signer | full+spl | yes | 2271 | 26 | 3 | - | 1151 | 994 | yes |  |
| 1x2 | confidential signer | full+data | yes | 2105 | 19 | 3 | - | 1221 | 1188 | yes |  |
| 1x2 | confidential signer | full+reply | yes | 1903 | 19 | 3 | - | 1019 | 990 | yes |  |
| 1x2 | confidential signer | full+2tree | yes | 1941 | 20 | 3 | - | 1024 | 994 | yes |  |
| 1x2 | confidential in-proof | min | yes | 1443 | 9 | 1 | - | 1028 | 1042 | yes |  |
| 1x2 | confidential in-proof | full | yes | 1902 | 18 | 2 | 1 | 1115 | 1087 | yes |  |
| 1x2 | confidential in-proof | full+spl | yes | 2270 | 25 | 2 | - | 1247 | 1091 | yes |  |
| 1x2 | confidential in-proof | full+data | yes | 2104 | 18 | 2 | - | 1317 | 1285 | yes |  |
| 1x2 | confidential in-proof | full+reply | yes | 1902 | 18 | 2 | - | 1115 | 1087 | yes |  |
| 1x2 | confidential in-proof | full+2tree | yes | 1940 | 19 | 2 | - | 1120 | 1091 | yes |  |
| 1x2 | anonymous hidden | min | yes | 1475 | 9 | 1 | - | 1060 | 1104 | yes |  |
| 1x2 | anonymous hidden | full | yes | 1902 | 15 | 2 | 1 | 1211 | 1223 | yes |  |
| 1x2 | anonymous hidden | full+spl | yes | 2270 | 22 | 2 | - | 1343 | 1227 | yes |  |
| 1x2 | anonymous hidden | full+data | yes | 2104 | 15 | 2 | - | 1413 | 1421 | yes |  |
| 1x2 | anonymous hidden | full+reply | yes | 2001 | 15 | 2 | - | 1310 | 1320 | yes |  |
| 1x2 | anonymous hidden | full+2tree | yes | 1940 | 16 | 2 | - | 1216 | 1227 | yes |  |
| 1x2 | anonymous public owners | min | yes | 1412 | 9 | 1 | - | 996 | 1007 | yes |  |
| 1x2 | anonymous public owners | full | yes | 2031 | 19 | 3 | 1 | 1147 | 1126 | yes |  |
| 1x2 | anonymous public owners | full+spl | yes | 2399 | 26 | 3 | - | 1279 | 1130 | yes |  |
| 1x2 | anonymous public owners | full+data | yes | 2233 | 19 | 3 | - | 1349 | 1324 | yes |  |
| 1x2 | anonymous public owners | full+reply | yes | 2130 | 19 | 3 | - | 1246 | 1223 | yes |  |
| 1x2 | anonymous public owners | full+2tree | yes | 2069 | 20 | 3 | - | 1152 | 1130 | yes |  |
| 1x2 | confidential entry | min | yes | 1556 | 9 | 1 | - | 1140 | 1153 | yes |  |
| 1x2 | confidential entry | full | yes | 2111 | 19 | 3 | 1 | 1227 | 1198 | yes |  |
| 1x2 | confidential entry | full+spl | yes | 2479 | 26 | 3 | - | 1359 | 1202 | yes |  |
| 1x2 | confidential entry | full+data | yes | 2313 | 19 | 3 | - | 1429 | 1396 | yes |  |
| 1x2 | confidential entry | full+reply | yes | 2111 | 19 | 3 | - | 1227 | 1198 | yes |  |
| 1x2 | confidential entry | full+2tree | yes | 2149 | 20 | 3 | - | 1232 | 1202 | yes |  |
| 1x2 | anonymous entry | min | yes | 1715 | 9 | 1 | - | 1300 | 1312 | yes |  |
| 1x2 | anonymous entry | full | yes | 2142 | 15 | 2 | 1 | 1451 | 1431 | yes |  |
| 1x2 | anonymous entry | full+spl | yes | 2510 | 22 | 2 | - | 1583 | 1435 | yes |  |
| 1x2 | anonymous entry | full+data | yes | 2344 | 15 | 2 | - | 1653 | 1629 | yes |  |
| 1x2 | anonymous entry | full+reply | yes | 2241 | 15 | 2 | - | 1550 | 1528 | yes |  |
| 1x2 | anonymous entry | full+2tree | yes | 2180 | 16 | 2 | - | 1456 | 1435 | yes |  |
| 1x2 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 1x2 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 1x4 | confidential signer | min | yes | 1782 | 9 | 1 | - | 1366 | 1451 | yes |  |
| 1x4 | confidential signer | full | yes | 2337 | 19 | 3 | 1 | 1453 | 1496 | yes |  |
| 1x4 | confidential signer | full+spl | yes | 2705 | 26 | 3 | - | 1585 | 1500 | yes |  |
| 1x4 | confidential signer | full+data | yes | 2741 | 19 | 3 | - | 1857 | 1892 | yes |  |
| 1x4 | confidential signer | full+reply | yes | 2337 | 19 | 3 | - | 1453 | 1496 | yes |  |
| 1x4 | confidential signer | full+2tree | yes | 2375 | 20 | 3 | - | 1458 | 1500 | yes |  |
| 1x4 | confidential in-proof | min | yes | 1877 | 9 | 1 | - | 1462 | 1548 | yes |  |
| 1x4 | confidential in-proof | full | yes | 2336 | 18 | 2 | 1 | 1549 | 1593 | yes |  |
| 1x4 | confidential in-proof | full+spl | yes | 2704 | 25 | 2 | - | 1681 | 1597 | yes |  |
| 1x4 | confidential in-proof | full+data | yes | 2740 | 18 | 2 | - | 1953 | 1989 | yes |  |
| 1x4 | confidential in-proof | full+reply | yes | 2336 | 18 | 2 | - | 1549 | 1593 | yes |  |
| 1x4 | confidential in-proof | full+2tree | yes | 2374 | 19 | 2 | - | 1554 | 1597 | yes |  |
| 1x4 | anonymous hidden | min | yes | 1973 | 9 | 1 | - | 1558 | 1674 | yes |  |
| 1x4 | anonymous hidden | full | yes | 2400 | 15 | 2 | 1 | 1709 | 1793 | yes |  |
| 1x4 | anonymous hidden | full+spl | yes | 2768 | 22 | 2 | - | 1841 | 1797 | yes |  |
| 1x4 | anonymous hidden | full+data | yes | 2804 | 15 | 2 | - | 2113 | 2189 | yes |  |
| 1x4 | anonymous hidden | full+reply | yes | 2693 | 15 | 2 | - | 2002 | 2084 | yes |  |
| 1x4 | anonymous hidden | full+2tree | yes | 2438 | 16 | 2 | - | 1714 | 1797 | yes |  |
| 1x4 | anonymous public owners | min | yes | 1910 | 9 | 1 | - | 1494 | 1577 | yes |  |
| 1x4 | anonymous public owners | full | yes | 2529 | 19 | 3 | 1 | 1645 | 1696 | yes |  |
| 1x4 | anonymous public owners | full+spl | yes | 2897 | 26 | 3 | - | 1777 | 1700 | yes |  |
| 1x4 | anonymous public owners | full+data | yes | 2933 | 19 | 3 | - | 2049 | 2092 | yes |  |
| 1x4 | anonymous public owners | full+reply | yes | 2822 | 19 | 3 | - | 1938 | 1987 | yes |  |
| 1x4 | anonymous public owners | full+2tree | yes | 2567 | 20 | 3 | - | 1650 | 1700 | yes |  |
| 1x4 | confidential entry | min | yes | 1990 | 9 | 1 | - | 1574 | 1659 | yes |  |
| 1x4 | confidential entry | full | yes | 2545 | 19 | 3 | 1 | 1661 | 1704 | yes |  |
| 1x4 | confidential entry | full+spl | yes | 2913 | 26 | 3 | - | 1793 | 1708 | yes |  |
| 1x4 | confidential entry | full+data | yes | 2949 | 19 | 3 | - | 2065 | 2100 | yes |  |
| 1x4 | confidential entry | full+reply | yes | 2545 | 19 | 3 | - | 1661 | 1704 | yes |  |
| 1x4 | confidential entry | full+2tree | yes | 2583 | 20 | 3 | - | 1666 | 1708 | yes |  |
| 1x4 | anonymous entry | min | yes | 2213 | 9 | 1 | - | 1798 | 1882 | yes |  |
| 1x4 | anonymous entry | full | yes | 2640 | 15 | 2 | 1 | 1949 | 2001 | yes |  |
| 1x4 | anonymous entry | full+spl | yes | 3008 | 22 | 2 | - | 2081 | 2005 | yes |  |
| 1x4 | anonymous entry | full+data | yes | 3044 | 15 | 2 | - | 2353 | 2397 | yes |  |
| 1x4 | anonymous entry | full+reply | yes | 2933 | 15 | 2 | - | 2242 | 2292 | yes |  |
| 1x4 | anonymous entry | full+2tree | yes | 2678 | 16 | 2 | - | 1954 | 2005 | yes |  |
| 1x4 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 1x4 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 1x8 | confidential signer | min | yes | 2650 | 9 | 1 | - | 2234 | 2463 | yes |  |
| 1x8 | confidential signer | full | yes | 3205 | 19 | 3 | 1 | 2321 | 2508 | yes |  |
| 1x8 | confidential signer | full+spl | yes | 3573 | 26 | 3 | - | 2453 | 2512 | yes |  |
| 1x8 | confidential signer | full+data | yes | 4013 | 19 | 3 | - | 3129 | 3300 | yes |  |
| 1x8 | confidential signer | full+reply | yes | 3205 | 19 | 3 | - | 2321 | 2508 | yes |  |
| 1x8 | confidential signer | full+2tree | yes | 3243 | 20 | 3 | - | 2326 | 2512 | yes |  |
| 1x8 | confidential in-proof | min | yes | 2745 | 9 | 1 | - | 2330 | 2560 | yes |  |
| 1x8 | confidential in-proof | full | yes | 3204 | 18 | 2 | 1 | 2417 | 2605 | yes |  |
| 1x8 | confidential in-proof | full+spl | yes | 3572 | 25 | 2 | - | 2549 | 2609 | yes |  |
| 1x8 | confidential in-proof | full+data | yes | 4012 | 18 | 2 | - | 3225 | 3397 | yes |  |
| 1x8 | confidential in-proof | full+reply | yes | 3204 | 18 | 2 | - | 2417 | 2605 | yes |  |
| 1x8 | confidential in-proof | full+2tree | yes | 3242 | 19 | 2 | - | 2422 | 2609 | yes |  |
| 1x8 | anonymous hidden | min | yes | 2969 | 9 | 1 | - | 2554 | 2814 | yes |  |
| 1x8 | anonymous hidden | full | yes | 3396 | 15 | 2 | 1 | 2705 | 2933 | yes |  |
| 1x8 | anonymous hidden | full+spl | yes | 3764 | 22 | 2 | - | 2837 | 2937 | yes |  |
| 1x8 | anonymous hidden | full+data | yes | 4204 | 15 | 2 | - | 3513 | 3725 | no | 108 B |
| 1x8 | anonymous hidden | full+reply | yes | 4077 | 15 | 2 | - | 3386 | 3612 | yes |  |
| 1x8 | anonymous hidden | full+2tree | yes | 3434 | 16 | 2 | - | 2710 | 2937 | yes |  |
| 1x8 | anonymous public owners | min | yes | 2906 | 9 | 1 | - | 2490 | 2717 | yes |  |
| 1x8 | anonymous public owners | full | yes | 3525 | 19 | 3 | 1 | 2641 | 2836 | yes |  |
| 1x8 | anonymous public owners | full+spl | yes | 3893 | 26 | 3 | - | 2773 | 2840 | yes |  |
| 1x8 | anonymous public owners | full+data | yes | 4333 | 19 | 3 | - | 3449 | 3628 | no | 237 B |
| 1x8 | anonymous public owners | full+reply | yes | 4206 | 19 | 3 | - | 3322 | 3515 | no | 110 B |
| 1x8 | anonymous public owners | full+2tree | yes | 3563 | 20 | 3 | - | 2646 | 2840 | yes |  |
| 1x8 | confidential entry | min | yes | 2858 | 9 | 1 | - | 2442 | 2671 | yes |  |
| 1x8 | confidential entry | full | yes | 3413 | 19 | 3 | 1 | 2529 | 2716 | yes |  |
| 1x8 | confidential entry | full+spl | yes | 3781 | 26 | 3 | - | 2661 | 2720 | yes |  |
| 1x8 | confidential entry | full+data | yes | 4221 | 19 | 3 | - | 3337 | 3508 | no | 125 B |
| 1x8 | confidential entry | full+reply | yes | 3413 | 19 | 3 | - | 2529 | 2716 | yes |  |
| 1x8 | confidential entry | full+2tree | yes | 3451 | 20 | 3 | - | 2534 | 2720 | yes |  |
| 1x8 | anonymous entry | min | yes | 3209 | 9 | 1 | - | 2794 | 3022 | yes |  |
| 1x8 | anonymous entry | full | yes | 3636 | 15 | 2 | 1 | 2945 | 3141 | yes |  |
| 1x8 | anonymous entry | full+spl | yes | 4004 | 22 | 2 | - | 3077 | 3145 | yes |  |
| 1x8 | anonymous entry | full+data | yes | 4444 | 15 | 2 | - | 3753 | 3933 | no | 348 B |
| 1x8 | anonymous entry | full+reply | yes | 4317 | 15 | 2 | - | 3626 | 3820 | no | 221 B |
| 1x8 | anonymous entry | full+2tree | yes | 3674 | 16 | 2 | - | 2950 | 3145 | yes |  |
| 1x8 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 1x8 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 2x2 | confidential signer | min | yes | 1413 | 10 | 1 | - | 964 | 978 | yes |  |
| 2x2 | confidential signer | full | yes | 1968 | 20 | 3 | 2 | 1051 | 1023 | yes |  |
| 2x2 | confidential signer | full+spl | yes | 2336 | 27 | 3 | - | 1183 | 1027 | yes |  |
| 2x2 | confidential signer | full+data | yes | 2170 | 20 | 3 | - | 1253 | 1221 | yes |  |
| 2x2 | confidential signer | full+reply | yes | 1968 | 20 | 3 | - | 1051 | 1023 | yes |  |
| 2x2 | confidential signer | full+2tree | yes | 2006 | 21 | 3 | - | 1056 | 1027 | yes |  |
| 2x2 | confidential in-proof | min | yes | 1508 | 10 | 1 | - | 1060 | 1075 | yes |  |
| 2x2 | confidential in-proof | full | yes | 1967 | 19 | 2 | 2 | 1147 | 1120 | yes |  |
| 2x2 | confidential in-proof | full+spl | yes | 2335 | 26 | 2 | - | 1279 | 1124 | yes |  |
| 2x2 | confidential in-proof | full+data | yes | 2169 | 19 | 2 | - | 1349 | 1318 | yes |  |
| 2x2 | confidential in-proof | full+reply | yes | 1967 | 19 | 2 | - | 1147 | 1120 | yes |  |
| 2x2 | confidential in-proof | full+2tree | yes | 2005 | 20 | 2 | - | 1152 | 1124 | yes |  |
| 2x2 | anonymous hidden | min | yes | 1540 | 10 | 1 | - | 1092 | 1137 | yes |  |
| 2x2 | anonymous hidden | full | yes | 1967 | 16 | 2 | 2 | 1243 | 1256 | yes |  |
| 2x2 | anonymous hidden | full+spl | yes | 2335 | 23 | 2 | - | 1375 | 1260 | yes |  |
| 2x2 | anonymous hidden | full+data | yes | 2169 | 16 | 2 | - | 1445 | 1454 | yes |  |
| 2x2 | anonymous hidden | full+reply | yes | 2066 | 16 | 2 | - | 1342 | 1353 | yes |  |
| 2x2 | anonymous hidden | full+2tree | yes | 2005 | 17 | 2 | - | 1248 | 1260 | yes |  |
| 2x2 | anonymous public owners | min | yes | 1477 | 10 | 1 | - | 1028 | 1040 | yes |  |
| 2x2 | anonymous public owners | full | yes | 2096 | 20 | 3 | 2 | 1179 | 1159 | yes |  |
| 2x2 | anonymous public owners | full+spl | yes | 2464 | 27 | 3 | - | 1311 | 1163 | yes |  |
| 2x2 | anonymous public owners | full+data | yes | 2298 | 20 | 3 | - | 1381 | 1357 | yes |  |
| 2x2 | anonymous public owners | full+reply | yes | 2195 | 20 | 3 | - | 1278 | 1256 | yes |  |
| 2x2 | anonymous public owners | full+2tree | yes | 2134 | 21 | 3 | - | 1184 | 1163 | yes |  |
| 2x2 | confidential entry | min | yes | 1821 | 10 | 1 | - | 1372 | 1386 | yes |  |
| 2x2 | confidential entry | full | yes | 2376 | 20 | 3 | 2 | 1459 | 1431 | yes |  |
| 2x2 | confidential entry | full+spl | yes | 2744 | 27 | 3 | - | 1591 | 1435 | yes |  |
| 2x2 | confidential entry | full+data | yes | 2578 | 20 | 3 | - | 1661 | 1629 | yes |  |
| 2x2 | confidential entry | full+reply | yes | 2376 | 20 | 3 | - | 1459 | 1431 | yes |  |
| 2x2 | confidential entry | full+2tree | yes | 2414 | 21 | 3 | - | 1464 | 1435 | yes |  |
| 2x2 | anonymous entry | min | yes | 1980 | 10 | 1 | - | 1532 | 1545 | yes |  |
| 2x2 | anonymous entry | full | yes | 2407 | 16 | 2 | 2 | 1683 | 1664 | yes |  |
| 2x2 | anonymous entry | full+spl | yes | 2775 | 23 | 2 | - | 1815 | 1668 | yes |  |
| 2x2 | anonymous entry | full+data | yes | 2609 | 16 | 2 | - | 1885 | 1862 | yes |  |
| 2x2 | anonymous entry | full+reply | yes | 2506 | 16 | 2 | - | 1782 | 1761 | yes |  |
| 2x2 | anonymous entry | full+2tree | yes | 2445 | 17 | 2 | - | 1688 | 1668 | yes |  |
| 2x2 | delegate | min | yes | 1413 | 10 | 1 | - | 964 | 978 | yes |  |
| 2x2 | delegate | full | yes | 1756 | 16 | 2 | - | 1035 | 1023 | yes |  |
| 2x2 | delegate | full+spl | yes | 1996 | 23 | 2 | - | 1039 | 1027 | yes |  |
| 2x2 | delegate | full+data | yes | 1958 | 16 | 2 | - | 1237 | 1221 | yes |  |
| 2x2 | delegate | full+reply | yes | 1756 | 16 | 2 | - | 1035 | 1023 | yes |  |
| 2x2 | delegate | full+2tree | yes | 1794 | 17 | 2 | - | 1040 | 1027 | yes |  |
| 2x2 | anonymous delegate | min | yes | 1477 | 10 | 1 | - | 1028 | 1040 | yes |  |
| 2x2 | anonymous delegate | full | yes | 1884 | 16 | 2 | - | 1163 | 1159 | yes |  |
| 2x2 | anonymous delegate | full+spl | yes | 2124 | 23 | 2 | - | 1167 | 1163 | yes |  |
| 2x2 | anonymous delegate | full+data | yes | 2086 | 16 | 2 | - | 1365 | 1357 | yes |  |
| 2x2 | anonymous delegate | full+reply | yes | 1983 | 16 | 2 | - | 1262 | 1256 | yes |  |
| 2x2 | anonymous delegate | full+2tree | yes | 1922 | 17 | 2 | - | 1168 | 1163 | yes |  |
| 2x4 | confidential signer | min | yes | 1847 | 10 | 1 | - | 1398 | 1484 | yes |  |
| 2x4 | confidential signer | full | yes | 2402 | 20 | 3 | 2 | 1485 | 1529 | yes |  |
| 2x4 | confidential signer | full+spl | yes | 2770 | 27 | 3 | - | 1617 | 1533 | yes |  |
| 2x4 | confidential signer | full+data | yes | 2806 | 20 | 3 | - | 1889 | 1925 | yes |  |
| 2x4 | confidential signer | full+reply | yes | 2402 | 20 | 3 | - | 1485 | 1529 | yes |  |
| 2x4 | confidential signer | full+2tree | yes | 2440 | 21 | 3 | - | 1490 | 1533 | yes |  |
| 2x4 | confidential in-proof | min | yes | 1942 | 10 | 1 | - | 1494 | 1581 | yes |  |
| 2x4 | confidential in-proof | full | yes | 2401 | 19 | 2 | 2 | 1581 | 1626 | yes |  |
| 2x4 | confidential in-proof | full+spl | yes | 2769 | 26 | 2 | - | 1713 | 1630 | yes |  |
| 2x4 | confidential in-proof | full+data | yes | 2805 | 19 | 2 | - | 1985 | 2022 | yes |  |
| 2x4 | confidential in-proof | full+reply | yes | 2401 | 19 | 2 | - | 1581 | 1626 | yes |  |
| 2x4 | confidential in-proof | full+2tree | yes | 2439 | 20 | 2 | - | 1586 | 1630 | yes |  |
| 2x4 | anonymous hidden | min | yes | 2038 | 10 | 1 | - | 1590 | 1707 | yes |  |
| 2x4 | anonymous hidden | full | yes | 2465 | 16 | 2 | 2 | 1741 | 1826 | yes |  |
| 2x4 | anonymous hidden | full+spl | yes | 2833 | 23 | 2 | - | 1873 | 1830 | yes |  |
| 2x4 | anonymous hidden | full+data | yes | 2869 | 16 | 2 | - | 2145 | 2222 | yes |  |
| 2x4 | anonymous hidden | full+reply | yes | 2758 | 16 | 2 | - | 2034 | 2117 | yes |  |
| 2x4 | anonymous hidden | full+2tree | yes | 2503 | 17 | 2 | - | 1746 | 1830 | yes |  |
| 2x4 | anonymous public owners | min | yes | 1975 | 10 | 1 | - | 1526 | 1610 | yes |  |
| 2x4 | anonymous public owners | full | yes | 2594 | 20 | 3 | 2 | 1677 | 1729 | yes |  |
| 2x4 | anonymous public owners | full+spl | yes | 2962 | 27 | 3 | - | 1809 | 1733 | yes |  |
| 2x4 | anonymous public owners | full+data | yes | 2998 | 20 | 3 | - | 2081 | 2125 | yes |  |
| 2x4 | anonymous public owners | full+reply | yes | 2887 | 20 | 3 | - | 1970 | 2020 | yes |  |
| 2x4 | anonymous public owners | full+2tree | yes | 2632 | 21 | 3 | - | 1682 | 1733 | yes |  |
| 2x4 | confidential entry | min | yes | 2255 | 10 | 1 | - | 1806 | 1892 | yes |  |
| 2x4 | confidential entry | full | yes | 2810 | 20 | 3 | 2 | 1893 | 1937 | yes |  |
| 2x4 | confidential entry | full+spl | yes | 3178 | 27 | 3 | - | 2025 | 1941 | yes |  |
| 2x4 | confidential entry | full+data | yes | 3214 | 20 | 3 | - | 2297 | 2333 | yes |  |
| 2x4 | confidential entry | full+reply | yes | 2810 | 20 | 3 | - | 1893 | 1937 | yes |  |
| 2x4 | confidential entry | full+2tree | yes | 2848 | 21 | 3 | - | 1898 | 1941 | yes |  |
| 2x4 | anonymous entry | min | yes | 2478 | 10 | 1 | - | 2030 | 2115 | yes |  |
| 2x4 | anonymous entry | full | yes | 2905 | 16 | 2 | 2 | 2181 | 2234 | yes |  |
| 2x4 | anonymous entry | full+spl | yes | 3273 | 23 | 2 | - | 2313 | 2238 | yes |  |
| 2x4 | anonymous entry | full+data | yes | 3309 | 16 | 2 | - | 2585 | 2630 | yes |  |
| 2x4 | anonymous entry | full+reply | yes | 3198 | 16 | 2 | - | 2474 | 2525 | yes |  |
| 2x4 | anonymous entry | full+2tree | yes | 2943 | 17 | 2 | - | 2186 | 2238 | yes |  |
| 2x4 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 2x4 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 1x16 | confidential signer | min | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | confidential signer | full | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | confidential signer | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | confidential signer | full+data | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | confidential signer | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | confidential signer | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | confidential in-proof | min | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | confidential in-proof | full | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | confidential in-proof | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | confidential in-proof | full+data | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | confidential in-proof | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | confidential in-proof | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | anonymous hidden | min | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | anonymous hidden | full | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | anonymous hidden | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | anonymous hidden | full+data | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | anonymous hidden | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | anonymous hidden | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | anonymous public owners | min | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | anonymous public owners | full | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | anonymous public owners | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | anonymous public owners | full+data | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | anonymous public owners | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | anonymous public owners | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | confidential entry | min | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | confidential entry | full | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | confidential entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | confidential entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | confidential entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | confidential entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | anonymous entry | min | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | anonymous entry | full | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | anonymous entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | anonymous entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | anonymous entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | anonymous entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 1x16 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 1x16 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 2x8 | confidential signer | min | yes | 2715 | 10 | 1 | - | 2266 | 2496 | yes |  |
| 2x8 | confidential signer | full | yes | 3270 | 20 | 3 | 2 | 2353 | 2541 | yes |  |
| 2x8 | confidential signer | full+spl | yes | 3638 | 27 | 3 | - | 2485 | 2545 | yes |  |
| 2x8 | confidential signer | full+data | yes | 4078 | 20 | 3 | - | 3161 | 3333 | yes |  |
| 2x8 | confidential signer | full+reply | yes | 3270 | 20 | 3 | - | 2353 | 2541 | yes |  |
| 2x8 | confidential signer | full+2tree | yes | 3308 | 21 | 3 | - | 2358 | 2545 | yes |  |
| 2x8 | confidential in-proof | min | yes | 2810 | 10 | 1 | - | 2362 | 2593 | yes |  |
| 2x8 | confidential in-proof | full | yes | 3269 | 19 | 2 | 2 | 2449 | 2638 | yes |  |
| 2x8 | confidential in-proof | full+spl | yes | 3637 | 26 | 2 | - | 2581 | 2642 | yes |  |
| 2x8 | confidential in-proof | full+data | yes | 4077 | 19 | 2 | - | 3257 | 3430 | yes |  |
| 2x8 | confidential in-proof | full+reply | yes | 3269 | 19 | 2 | - | 2449 | 2638 | yes |  |
| 2x8 | confidential in-proof | full+2tree | yes | 3307 | 20 | 2 | - | 2454 | 2642 | yes |  |
| 2x8 | anonymous hidden | min | yes | 3034 | 10 | 1 | - | 2586 | 2847 | yes |  |
| 2x8 | anonymous hidden | full | yes | 3461 | 16 | 2 | 2 | 2737 | 2966 | yes |  |
| 2x8 | anonymous hidden | full+spl | yes | 3829 | 23 | 2 | - | 2869 | 2970 | yes |  |
| 2x8 | anonymous hidden | full+data | yes | 4269 | 16 | 2 | - | 3545 | 3758 | no | 173 B |
| 2x8 | anonymous hidden | full+reply | yes | 4142 | 16 | 2 | - | 3418 | 3645 | no | 46 B |
| 2x8 | anonymous hidden | full+2tree | yes | 3499 | 17 | 2 | - | 2742 | 2970 | yes |  |
| 2x8 | anonymous public owners | min | yes | 2971 | 10 | 1 | - | 2522 | 2750 | yes |  |
| 2x8 | anonymous public owners | full | yes | 3590 | 20 | 3 | 2 | 2673 | 2869 | yes |  |
| 2x8 | anonymous public owners | full+spl | yes | 3958 | 27 | 3 | - | 2805 | 2873 | yes |  |
| 2x8 | anonymous public owners | full+data | yes | 4398 | 20 | 3 | - | 3481 | 3661 | no | 302 B |
| 2x8 | anonymous public owners | full+reply | yes | 4271 | 20 | 3 | - | 3354 | 3548 | no | 175 B |
| 2x8 | anonymous public owners | full+2tree | yes | 3628 | 21 | 3 | - | 2678 | 2873 | yes |  |
| 2x8 | confidential entry | min | yes | 3123 | 10 | 1 | - | 2674 | 2904 | yes |  |
| 2x8 | confidential entry | full | yes | 3678 | 20 | 3 | 2 | 2761 | 2949 | yes |  |
| 2x8 | confidential entry | full+spl | yes | 4046 | 27 | 3 | - | 2893 | 2953 | yes |  |
| 2x8 | confidential entry | full+data | yes | 4486 | 20 | 3 | - | 3569 | 3741 | no | 390 B |
| 2x8 | confidential entry | full+reply | yes | 3678 | 20 | 3 | - | 2761 | 2949 | yes |  |
| 2x8 | confidential entry | full+2tree | yes | 3716 | 21 | 3 | - | 2766 | 2953 | yes |  |
| 2x8 | anonymous entry | min | yes | 3474 | 10 | 1 | - | 3026 | 3255 | yes |  |
| 2x8 | anonymous entry | full | yes | 3901 | 16 | 2 | 2 | 3177 | 3374 | yes |  |
| 2x8 | anonymous entry | full+spl | yes | 4269 | 23 | 2 | - | 3309 | 3378 | no | 173 B |
| 2x8 | anonymous entry | full+data | yes | 4709 | 16 | 2 | - | 3985 | 4166 | no | 613 B |
| 2x8 | anonymous entry | full+reply | yes | 4582 | 16 | 2 | - | 3858 | 4053 | no | 486 B |
| 2x8 | anonymous entry | full+2tree | yes | 3939 | 17 | 2 | - | 3182 | 3378 | yes |  |
| 2x8 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 2x8 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 3x2 | confidential signer | min | yes | 1478 | 11 | 1 | - | 996 | 1011 | yes |  |
| 3x2 | confidential signer | full | yes | 2033 | 21 | 3 | 3 | 1083 | 1056 | yes |  |
| 3x2 | confidential signer | full+spl | yes | 2401 | 28 | 3 | - | 1215 | 1060 | yes |  |
| 3x2 | confidential signer | full+data | yes | 2235 | 21 | 3 | - | 1285 | 1254 | yes |  |
| 3x2 | confidential signer | full+reply | yes | 2033 | 21 | 3 | - | 1083 | 1056 | yes |  |
| 3x2 | confidential signer | full+2tree | yes | 2071 | 22 | 3 | - | 1088 | 1060 | yes |  |
| 3x2 | confidential in-proof | min | yes | 1573 | 11 | 1 | - | 1092 | 1108 | yes |  |
| 3x2 | confidential in-proof | full | yes | 2032 | 20 | 2 | 3 | 1179 | 1153 | yes |  |
| 3x2 | confidential in-proof | full+spl | yes | 2400 | 27 | 2 | - | 1311 | 1157 | yes |  |
| 3x2 | confidential in-proof | full+data | yes | 2234 | 20 | 2 | - | 1381 | 1351 | yes |  |
| 3x2 | confidential in-proof | full+reply | yes | 2032 | 20 | 2 | - | 1179 | 1153 | yes |  |
| 3x2 | confidential in-proof | full+2tree | yes | 2070 | 21 | 2 | - | 1184 | 1157 | yes |  |
| 3x2 | anonymous hidden | min | yes | 1605 | 11 | 1 | - | 1124 | 1170 | yes |  |
| 3x2 | anonymous hidden | full | yes | 2032 | 17 | 2 | 3 | 1275 | 1289 | yes |  |
| 3x2 | anonymous hidden | full+spl | yes | 2400 | 24 | 2 | - | 1407 | 1293 | yes |  |
| 3x2 | anonymous hidden | full+data | yes | 2234 | 17 | 2 | - | 1477 | 1487 | yes |  |
| 3x2 | anonymous hidden | full+reply | yes | 2131 | 17 | 2 | - | 1374 | 1386 | yes |  |
| 3x2 | anonymous hidden | full+2tree | yes | 2070 | 18 | 2 | - | 1280 | 1293 | yes |  |
| 3x2 | anonymous public owners | min | yes | 1542 | 11 | 1 | - | 1060 | 1073 | yes |  |
| 3x2 | anonymous public owners | full | yes | 2161 | 21 | 3 | 3 | 1211 | 1192 | yes |  |
| 3x2 | anonymous public owners | full+spl | yes | 2529 | 28 | 3 | - | 1343 | 1196 | yes |  |
| 3x2 | anonymous public owners | full+data | yes | 2363 | 21 | 3 | - | 1413 | 1390 | yes |  |
| 3x2 | anonymous public owners | full+reply | yes | 2260 | 21 | 3 | - | 1310 | 1289 | yes |  |
| 3x2 | anonymous public owners | full+2tree | yes | 2199 | 22 | 3 | - | 1216 | 1196 | yes |  |
| 3x2 | confidential entry | min | yes | 2086 | 11 | 1 | - | 1604 | 1619 | yes |  |
| 3x2 | confidential entry | full | yes | 2641 | 21 | 3 | 3 | 1691 | 1664 | yes |  |
| 3x2 | confidential entry | full+spl | yes | 3009 | 28 | 3 | - | 1823 | 1668 | yes |  |
| 3x2 | confidential entry | full+data | yes | 2843 | 21 | 3 | - | 1893 | 1862 | yes |  |
| 3x2 | confidential entry | full+reply | yes | 2641 | 21 | 3 | - | 1691 | 1664 | yes |  |
| 3x2 | confidential entry | full+2tree | yes | 2679 | 22 | 3 | - | 1696 | 1668 | yes |  |
| 3x2 | anonymous entry | min | yes | 2245 | 11 | 1 | - | 1764 | 1778 | yes |  |
| 3x2 | anonymous entry | full | yes | 2672 | 17 | 2 | 3 | 1915 | 1897 | yes |  |
| 3x2 | anonymous entry | full+spl | yes | 3040 | 24 | 2 | - | 2047 | 1901 | yes |  |
| 3x2 | anonymous entry | full+data | yes | 2874 | 17 | 2 | - | 2117 | 2095 | yes |  |
| 3x2 | anonymous entry | full+reply | yes | 2771 | 17 | 2 | - | 2014 | 1994 | yes |  |
| 3x2 | anonymous entry | full+2tree | yes | 2710 | 18 | 2 | - | 1920 | 1901 | yes |  |
| 3x2 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 3x2 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 3x4 | confidential signer | min | yes | 1912 | 11 | 1 | - | 1430 | 1517 | yes |  |
| 3x4 | confidential signer | full | yes | 2467 | 21 | 3 | 3 | 1517 | 1562 | yes |  |
| 3x4 | confidential signer | full+spl | yes | 2835 | 28 | 3 | - | 1649 | 1566 | yes |  |
| 3x4 | confidential signer | full+data | yes | 2871 | 21 | 3 | - | 1921 | 1958 | yes |  |
| 3x4 | confidential signer | full+reply | yes | 2467 | 21 | 3 | - | 1517 | 1562 | yes |  |
| 3x4 | confidential signer | full+2tree | yes | 2505 | 22 | 3 | - | 1522 | 1566 | yes |  |
| 3x4 | confidential in-proof | min | yes | 2007 | 11 | 1 | - | 1526 | 1614 | yes |  |
| 3x4 | confidential in-proof | full | yes | 2466 | 20 | 2 | 3 | 1613 | 1659 | yes |  |
| 3x4 | confidential in-proof | full+spl | yes | 2834 | 27 | 2 | - | 1745 | 1663 | yes |  |
| 3x4 | confidential in-proof | full+data | yes | 2870 | 20 | 2 | - | 2017 | 2055 | yes |  |
| 3x4 | confidential in-proof | full+reply | yes | 2466 | 20 | 2 | - | 1613 | 1659 | yes |  |
| 3x4 | confidential in-proof | full+2tree | yes | 2504 | 21 | 2 | - | 1618 | 1663 | yes |  |
| 3x4 | anonymous hidden | min | yes | 2103 | 11 | 1 | - | 1622 | 1740 | yes |  |
| 3x4 | anonymous hidden | full | yes | 2530 | 17 | 2 | 3 | 1773 | 1859 | yes |  |
| 3x4 | anonymous hidden | full+spl | yes | 2898 | 24 | 2 | - | 1905 | 1863 | yes |  |
| 3x4 | anonymous hidden | full+data | yes | 2934 | 17 | 2 | - | 2177 | 2255 | yes |  |
| 3x4 | anonymous hidden | full+reply | yes | 2823 | 17 | 2 | - | 2066 | 2150 | yes |  |
| 3x4 | anonymous hidden | full+2tree | yes | 2568 | 18 | 2 | - | 1778 | 1863 | yes |  |
| 3x4 | anonymous public owners | min | yes | 2040 | 11 | 1 | - | 1558 | 1643 | yes |  |
| 3x4 | anonymous public owners | full | yes | 2659 | 21 | 3 | 3 | 1709 | 1762 | yes |  |
| 3x4 | anonymous public owners | full+spl | yes | 3027 | 28 | 3 | - | 1841 | 1766 | yes |  |
| 3x4 | anonymous public owners | full+data | yes | 3063 | 21 | 3 | - | 2113 | 2158 | yes |  |
| 3x4 | anonymous public owners | full+reply | yes | 2952 | 21 | 3 | - | 2002 | 2053 | yes |  |
| 3x4 | anonymous public owners | full+2tree | yes | 2697 | 22 | 3 | - | 1714 | 1766 | yes |  |
| 3x4 | confidential entry | min | yes | 2520 | 11 | 1 | - | 2038 | 2125 | yes |  |
| 3x4 | confidential entry | full | yes | 3075 | 21 | 3 | 3 | 2125 | 2170 | yes |  |
| 3x4 | confidential entry | full+spl | yes | 3443 | 28 | 3 | - | 2257 | 2174 | yes |  |
| 3x4 | confidential entry | full+data | yes | 3479 | 21 | 3 | - | 2529 | 2566 | yes |  |
| 3x4 | confidential entry | full+reply | yes | 3075 | 21 | 3 | - | 2125 | 2170 | yes |  |
| 3x4 | confidential entry | full+2tree | yes | 3113 | 22 | 3 | - | 2130 | 2174 | yes |  |
| 3x4 | anonymous entry | min | yes | 2743 | 11 | 1 | - | 2262 | 2348 | yes |  |
| 3x4 | anonymous entry | full | yes | 3170 | 17 | 2 | 3 | 2413 | 2467 | yes |  |
| 3x4 | anonymous entry | full+spl | yes | 3538 | 24 | 2 | - | 2545 | 2471 | yes |  |
| 3x4 | anonymous entry | full+data | yes | 3574 | 17 | 2 | - | 2817 | 2863 | yes |  |
| 3x4 | anonymous entry | full+reply | yes | 3463 | 17 | 2 | - | 2706 | 2758 | yes |  |
| 3x4 | anonymous entry | full+2tree | yes | 3208 | 18 | 2 | - | 2418 | 2471 | yes |  |
| 3x4 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 3x4 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 2x16 | confidential signer | min | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | confidential signer | full | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | confidential signer | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | confidential signer | full+data | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | confidential signer | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | confidential signer | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | confidential in-proof | min | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | confidential in-proof | full | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | confidential in-proof | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | confidential in-proof | full+data | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | confidential in-proof | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | confidential in-proof | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | anonymous hidden | min | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | anonymous hidden | full | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | anonymous hidden | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | anonymous hidden | full+data | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | anonymous hidden | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | anonymous hidden | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | anonymous public owners | min | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | anonymous public owners | full | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | anonymous public owners | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | anonymous public owners | full+data | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | anonymous public owners | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | anonymous public owners | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | confidential entry | min | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | confidential entry | full | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | confidential entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | confidential entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | confidential entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | confidential entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | anonymous entry | min | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | anonymous entry | full | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | anonymous entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | anonymous entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | anonymous entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | anonymous entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 2x16 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 2x16 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 3x8 | confidential signer | min | yes | 2780 | 11 | 1 | - | 2298 | 2529 | yes |  |
| 3x8 | confidential signer | full | yes | 3335 | 21 | 3 | 3 | 2385 | 2574 | yes |  |
| 3x8 | confidential signer | full+spl | yes | 3703 | 28 | 3 | - | 2517 | 2578 | yes |  |
| 3x8 | confidential signer | full+data | yes | 4143 | 21 | 3 | - | 3193 | 3366 | no | 47 B |
| 3x8 | confidential signer | full+reply | yes | 3335 | 21 | 3 | - | 2385 | 2574 | yes |  |
| 3x8 | confidential signer | full+2tree | yes | 3373 | 22 | 3 | - | 2390 | 2578 | yes |  |
| 3x8 | confidential in-proof | min | yes | 2875 | 11 | 1 | - | 2394 | 2626 | yes |  |
| 3x8 | confidential in-proof | full | yes | 3334 | 20 | 2 | 3 | 2481 | 2671 | yes |  |
| 3x8 | confidential in-proof | full+spl | yes | 3702 | 27 | 2 | - | 2613 | 2675 | yes |  |
| 3x8 | confidential in-proof | full+data | yes | 4142 | 20 | 2 | - | 3289 | 3463 | no | 46 B |
| 3x8 | confidential in-proof | full+reply | yes | 3334 | 20 | 2 | - | 2481 | 2671 | yes |  |
| 3x8 | confidential in-proof | full+2tree | yes | 3372 | 21 | 2 | - | 2486 | 2675 | yes |  |
| 3x8 | anonymous hidden | min | yes | 3099 | 11 | 1 | - | 2618 | 2880 | yes |  |
| 3x8 | anonymous hidden | full | yes | 3526 | 17 | 2 | 3 | 2769 | 2999 | yes |  |
| 3x8 | anonymous hidden | full+spl | yes | 3894 | 24 | 2 | - | 2901 | 3003 | yes |  |
| 3x8 | anonymous hidden | full+data | yes | 4334 | 17 | 2 | - | 3577 | 3791 | no | 238 B |
| 3x8 | anonymous hidden | full+reply | yes | 4207 | 17 | 2 | - | 3450 | 3678 | no | 111 B |
| 3x8 | anonymous hidden | full+2tree | yes | 3564 | 18 | 2 | - | 2774 | 3003 | yes |  |
| 3x8 | anonymous public owners | min | yes | 3036 | 11 | 1 | - | 2554 | 2783 | yes |  |
| 3x8 | anonymous public owners | full | yes | 3655 | 21 | 3 | 3 | 2705 | 2902 | yes |  |
| 3x8 | anonymous public owners | full+spl | yes | 4023 | 28 | 3 | - | 2837 | 2906 | yes |  |
| 3x8 | anonymous public owners | full+data | yes | 4463 | 21 | 3 | - | 3513 | 3694 | no | 367 B |
| 3x8 | anonymous public owners | full+reply | yes | 4336 | 21 | 3 | - | 3386 | 3581 | no | 240 B |
| 3x8 | anonymous public owners | full+2tree | yes | 3693 | 22 | 3 | - | 2710 | 2906 | yes |  |
| 3x8 | confidential entry | min | yes | 3388 | 11 | 1 | - | 2906 | 3137 | yes |  |
| 3x8 | confidential entry | full | yes | 3943 | 21 | 3 | 2 | 2993 | 3182 | yes |  |
| 3x8 | confidential entry | full+spl | yes | 4311 | 28 | 3 | - | 3125 | 3186 | no | 215 B |
| 3x8 | confidential entry | full+data | yes | 4751 | 21 | 3 | - | 3801 | 3974 | no | 655 B |
| 3x8 | confidential entry | full+reply | yes | 3943 | 21 | 3 | - | 2993 | 3182 | yes |  |
| 3x8 | confidential entry | full+2tree | yes | 3981 | 22 | 3 | - | 2998 | 3186 | yes |  |
| 3x8 | anonymous entry | min | yes | 3739 | 11 | 1 | - | 3258 | 3488 | yes |  |
| 3x8 | anonymous entry | full | yes | 4166 | 17 | 2 | none | 3409 | 3607 | no | 70 B |
| 3x8 | anonymous entry | full+spl | yes | 4534 | 24 | 2 | - | 3541 | 3611 | no | 438 B |
| 3x8 | anonymous entry | full+data | yes | 4974 | 17 | 2 | - | 4217 | 4399 | no | 878 B |
| 3x8 | anonymous entry | full+reply | yes | 4847 | 17 | 2 | - | 4090 | 4286 | no | 751 B |
| 3x8 | anonymous entry | full+2tree | yes | 4204 | 18 | 2 | - | 3414 | 3611 | no | 108 B |
| 3x8 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 3x8 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 4x2 | confidential signer | min | yes | 1543 | 12 | 1 | - | 1028 | 1044 | yes |  |
| 4x2 | confidential signer | full | yes | 2098 | 22 | 3 | 4 | 1115 | 1089 | yes |  |
| 4x2 | confidential signer | full+spl | yes | 2466 | 29 | 3 | - | 1247 | 1093 | yes |  |
| 4x2 | confidential signer | full+data | yes | 2300 | 22 | 3 | - | 1317 | 1287 | yes |  |
| 4x2 | confidential signer | full+reply | yes | 2098 | 22 | 3 | - | 1115 | 1089 | yes |  |
| 4x2 | confidential signer | full+2tree | yes | 2136 | 23 | 3 | - | 1120 | 1093 | yes |  |
| 4x2 | confidential in-proof | min | yes | 1638 | 12 | 1 | - | 1124 | 1141 | yes |  |
| 4x2 | confidential in-proof | full | yes | 2097 | 21 | 2 | 4 | 1211 | 1186 | yes |  |
| 4x2 | confidential in-proof | full+spl | yes | 2465 | 28 | 2 | - | 1343 | 1190 | yes |  |
| 4x2 | confidential in-proof | full+data | yes | 2299 | 21 | 2 | - | 1413 | 1384 | yes |  |
| 4x2 | confidential in-proof | full+reply | yes | 2097 | 21 | 2 | - | 1211 | 1186 | yes |  |
| 4x2 | confidential in-proof | full+2tree | yes | 2135 | 22 | 2 | - | 1216 | 1190 | yes |  |
| 4x2 | anonymous hidden | min | yes | 1670 | 12 | 1 | - | 1156 | 1203 | yes |  |
| 4x2 | anonymous hidden | full | yes | 2097 | 18 | 2 | 4 | 1307 | 1322 | yes |  |
| 4x2 | anonymous hidden | full+spl | yes | 2465 | 25 | 2 | - | 1439 | 1326 | yes |  |
| 4x2 | anonymous hidden | full+data | yes | 2299 | 18 | 2 | - | 1509 | 1520 | yes |  |
| 4x2 | anonymous hidden | full+reply | yes | 2196 | 18 | 2 | - | 1406 | 1419 | yes |  |
| 4x2 | anonymous hidden | full+2tree | yes | 2135 | 19 | 2 | - | 1312 | 1326 | yes |  |
| 4x2 | anonymous public owners | min | yes | 1607 | 12 | 1 | - | 1092 | 1106 | yes |  |
| 4x2 | anonymous public owners | full | yes | 2226 | 22 | 3 | 4 | 1243 | 1225 | yes |  |
| 4x2 | anonymous public owners | full+spl | yes | 2594 | 29 | 3 | - | 1375 | 1229 | yes |  |
| 4x2 | anonymous public owners | full+data | yes | 2428 | 22 | 3 | - | 1445 | 1423 | yes |  |
| 4x2 | anonymous public owners | full+reply | yes | 2325 | 22 | 3 | - | 1342 | 1322 | yes |  |
| 4x2 | anonymous public owners | full+2tree | yes | 2264 | 23 | 3 | - | 1248 | 1229 | yes |  |
| 4x2 | confidential entry | min | yes | 2351 | 12 | 1 | - | 1836 | 1852 | yes |  |
| 4x2 | confidential entry | full | yes | 2906 | 22 | 3 | 4 | 1923 | 1897 | yes |  |
| 4x2 | confidential entry | full+spl | yes | 3274 | 29 | 3 | - | 2055 | 1901 | yes |  |
| 4x2 | confidential entry | full+data | yes | 3108 | 22 | 3 | - | 2125 | 2095 | yes |  |
| 4x2 | confidential entry | full+reply | yes | 2906 | 22 | 3 | - | 1923 | 1897 | yes |  |
| 4x2 | confidential entry | full+2tree | yes | 2944 | 23 | 3 | - | 1928 | 1901 | yes |  |
| 4x2 | anonymous entry | min | yes | 2510 | 12 | 1 | - | 1996 | 2011 | yes |  |
| 4x2 | anonymous entry | full | yes | 2937 | 18 | 2 | 4 | 2147 | 2130 | yes |  |
| 4x2 | anonymous entry | full+spl | yes | 3305 | 25 | 2 | - | 2279 | 2134 | yes |  |
| 4x2 | anonymous entry | full+data | yes | 3139 | 18 | 2 | - | 2349 | 2328 | yes |  |
| 4x2 | anonymous entry | full+reply | yes | 3036 | 18 | 2 | - | 2246 | 2227 | yes |  |
| 4x2 | anonymous entry | full+2tree | yes | 2975 | 19 | 2 | - | 2152 | 2134 | yes |  |
| 4x2 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 4x2 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 4x4 | confidential signer | min | yes | 1977 | 12 | 1 | - | 1462 | 1550 | yes |  |
| 4x4 | confidential signer | full | yes | 2532 | 22 | 3 | 4 | 1549 | 1595 | yes |  |
| 4x4 | confidential signer | full+spl | yes | 2900 | 29 | 3 | - | 1681 | 1599 | yes |  |
| 4x4 | confidential signer | full+data | yes | 2936 | 22 | 3 | - | 1953 | 1991 | yes |  |
| 4x4 | confidential signer | full+reply | yes | 2532 | 22 | 3 | - | 1549 | 1595 | yes |  |
| 4x4 | confidential signer | full+2tree | yes | 2570 | 23 | 3 | - | 1554 | 1599 | yes |  |
| 4x4 | confidential in-proof | min | yes | 2072 | 12 | 1 | - | 1558 | 1647 | yes |  |
| 4x4 | confidential in-proof | full | yes | 2531 | 21 | 2 | 4 | 1645 | 1692 | yes |  |
| 4x4 | confidential in-proof | full+spl | yes | 2899 | 28 | 2 | - | 1777 | 1696 | yes |  |
| 4x4 | confidential in-proof | full+data | yes | 2935 | 21 | 2 | - | 2049 | 2088 | yes |  |
| 4x4 | confidential in-proof | full+reply | yes | 2531 | 21 | 2 | - | 1645 | 1692 | yes |  |
| 4x4 | confidential in-proof | full+2tree | yes | 2569 | 22 | 2 | - | 1650 | 1696 | yes |  |
| 4x4 | anonymous hidden | min | yes | 2168 | 12 | 1 | - | 1654 | 1773 | yes |  |
| 4x4 | anonymous hidden | full | yes | 2595 | 18 | 2 | 4 | 1805 | 1892 | yes |  |
| 4x4 | anonymous hidden | full+spl | yes | 2963 | 25 | 2 | - | 1937 | 1896 | yes |  |
| 4x4 | anonymous hidden | full+data | yes | 2999 | 18 | 2 | - | 2209 | 2288 | yes |  |
| 4x4 | anonymous hidden | full+reply | yes | 2888 | 18 | 2 | - | 2098 | 2183 | yes |  |
| 4x4 | anonymous hidden | full+2tree | yes | 2633 | 19 | 2 | - | 1810 | 1896 | yes |  |
| 4x4 | anonymous public owners | min | yes | 2105 | 12 | 1 | - | 1590 | 1676 | yes |  |
| 4x4 | anonymous public owners | full | yes | 2724 | 22 | 3 | 4 | 1741 | 1795 | yes |  |
| 4x4 | anonymous public owners | full+spl | yes | 3092 | 29 | 3 | - | 1873 | 1799 | yes |  |
| 4x4 | anonymous public owners | full+data | yes | 3128 | 22 | 3 | - | 2145 | 2191 | yes |  |
| 4x4 | anonymous public owners | full+reply | yes | 3017 | 22 | 3 | - | 2034 | 2086 | yes |  |
| 4x4 | anonymous public owners | full+2tree | yes | 2762 | 23 | 3 | - | 1746 | 1799 | yes |  |
| 4x4 | confidential entry | min | yes | 2785 | 12 | 1 | - | 2270 | 2358 | yes |  |
| 4x4 | confidential entry | full | yes | 3340 | 22 | 3 | 4 | 2357 | 2403 | yes |  |
| 4x4 | confidential entry | full+spl | yes | 3708 | 29 | 3 | - | 2489 | 2407 | yes |  |
| 4x4 | confidential entry | full+data | yes | 3744 | 22 | 3 | - | 2761 | 2799 | yes |  |
| 4x4 | confidential entry | full+reply | yes | 3340 | 22 | 3 | - | 2357 | 2403 | yes |  |
| 4x4 | confidential entry | full+2tree | yes | 3378 | 23 | 3 | - | 2362 | 2407 | yes |  |
| 4x4 | anonymous entry | min | yes | 3008 | 12 | 1 | - | 2494 | 2581 | yes |  |
| 4x4 | anonymous entry | full | yes | 3435 | 18 | 2 | 4 | 2645 | 2700 | yes |  |
| 4x4 | anonymous entry | full+spl | yes | 3803 | 25 | 2 | - | 2777 | 2704 | yes |  |
| 4x4 | anonymous entry | full+data | yes | 3839 | 18 | 2 | - | 3049 | 3096 | yes |  |
| 4x4 | anonymous entry | full+reply | yes | 3728 | 18 | 2 | - | 2938 | 2991 | yes |  |
| 4x4 | anonymous entry | full+2tree | yes | 3473 | 19 | 2 | - | 2650 | 2704 | yes |  |
| 4x4 | delegate | min | yes | 1977 | 12 | 1 | - | 1462 | 1550 | yes |  |
| 4x4 | delegate | full | yes | 2320 | 18 | 2 | - | 1533 | 1595 | yes |  |
| 4x4 | delegate | full+spl | yes | 2560 | 25 | 2 | - | 1537 | 1599 | yes |  |
| 4x4 | delegate | full+data | yes | 2724 | 18 | 2 | - | 1937 | 1991 | yes |  |
| 4x4 | delegate | full+reply | yes | 2320 | 18 | 2 | - | 1533 | 1595 | yes |  |
| 4x4 | delegate | full+2tree | yes | 2358 | 19 | 2 | - | 1538 | 1599 | yes |  |
| 4x4 | anonymous delegate | min | yes | 2105 | 12 | 1 | - | 1590 | 1676 | yes |  |
| 4x4 | anonymous delegate | full | yes | 2512 | 18 | 2 | - | 1725 | 1795 | yes |  |
| 4x4 | anonymous delegate | full+spl | yes | 2752 | 25 | 2 | - | 1729 | 1799 | yes |  |
| 4x4 | anonymous delegate | full+data | yes | 2916 | 18 | 2 | - | 2129 | 2191 | yes |  |
| 4x4 | anonymous delegate | full+reply | yes | 2805 | 18 | 2 | - | 2018 | 2086 | yes |  |
| 4x4 | anonymous delegate | full+2tree | yes | 2550 | 19 | 2 | - | 1730 | 1799 | yes |  |
| 4x8 | confidential signer | min | yes | 2845 | 12 | 1 | - | 2330 | 2562 | yes |  |
| 4x8 | confidential signer | full | yes | 3400 | 22 | 3 | 4 | 2417 | 2607 | yes |  |
| 4x8 | confidential signer | full+spl | yes | 3768 | 29 | 3 | - | 2549 | 2611 | yes |  |
| 4x8 | confidential signer | full+data | yes | 4208 | 22 | 3 | - | 3225 | 3399 | no | 112 B |
| 4x8 | confidential signer | full+reply | yes | 3400 | 22 | 3 | - | 2417 | 2607 | yes |  |
| 4x8 | confidential signer | full+2tree | yes | 3438 | 23 | 3 | - | 2422 | 2611 | yes |  |
| 4x8 | confidential in-proof | min | yes | 2940 | 12 | 1 | - | 2426 | 2659 | yes |  |
| 4x8 | confidential in-proof | full | yes | 3399 | 21 | 2 | 4 | 2513 | 2704 | yes |  |
| 4x8 | confidential in-proof | full+spl | yes | 3767 | 28 | 2 | - | 2645 | 2708 | yes |  |
| 4x8 | confidential in-proof | full+data | yes | 4207 | 21 | 2 | - | 3321 | 3496 | no | 111 B |
| 4x8 | confidential in-proof | full+reply | yes | 3399 | 21 | 2 | - | 2513 | 2704 | yes |  |
| 4x8 | confidential in-proof | full+2tree | yes | 3437 | 22 | 2 | - | 2518 | 2708 | yes |  |
| 4x8 | anonymous hidden | min | yes | 3164 | 12 | 1 | - | 2650 | 2913 | yes |  |
| 4x8 | anonymous hidden | full | yes | 3591 | 18 | 2 | 4 | 2801 | 3032 | yes |  |
| 4x8 | anonymous hidden | full+spl | yes | 3959 | 25 | 2 | - | 2933 | 3036 | yes |  |
| 4x8 | anonymous hidden | full+data | yes | 4399 | 18 | 2 | - | 3609 | 3824 | no | 303 B |
| 4x8 | anonymous hidden | full+reply | yes | 4272 | 18 | 2 | - | 3482 | 3711 | no | 176 B |
| 4x8 | anonymous hidden | full+2tree | yes | 3629 | 19 | 2 | - | 2806 | 3036 | yes |  |
| 4x8 | anonymous public owners | min | yes | 3101 | 12 | 1 | - | 2586 | 2816 | yes |  |
| 4x8 | anonymous public owners | full | yes | 3720 | 22 | 3 | 4 | 2737 | 2935 | yes |  |
| 4x8 | anonymous public owners | full+spl | yes | 4088 | 29 | 3 | - | 2869 | 2939 | yes |  |
| 4x8 | anonymous public owners | full+data | yes | 4528 | 22 | 3 | - | 3545 | 3727 | no | 432 B |
| 4x8 | anonymous public owners | full+reply | yes | 4401 | 22 | 3 | - | 3418 | 3614 | no | 305 B |
| 4x8 | anonymous public owners | full+2tree | yes | 3758 | 23 | 3 | - | 2742 | 2939 | yes |  |
| 4x8 | confidential entry | min | yes | 3653 | 12 | 1 | - | 3138 | 3370 | yes |  |
| 4x8 | confidential entry | full | yes | 4208 | 22 | 3 | none | 3225 | 3415 | no | 112 B |
| 4x8 | confidential entry | full+spl | yes | 4576 | 29 | 3 | - | 3357 | 3419 | no | 480 B |
| 4x8 | confidential entry | full+data | yes | 5016 | 22 | 3 | - | 4033 | 4207 | no | 920 B |
| 4x8 | confidential entry | full+reply | yes | 4208 | 22 | 3 | - | 3225 | 3415 | no | 112 B |
| 4x8 | confidential entry | full+2tree | yes | 4246 | 23 | 3 | - | 3230 | 3419 | no | 150 B |
| 4x8 | anonymous entry | min | yes | 4004 | 12 | 1 | - | 3490 | 3721 | yes |  |
| 4x8 | anonymous entry | full | yes | 4431 | 18 | 2 | none | 3641 | 3840 | no | 335 B |
| 4x8 | anonymous entry | full+spl | yes | 4799 | 25 | 2 | - | 3773 | 3844 | no | 703 B |
| 4x8 | anonymous entry | full+data | yes | 5239 | 18 | 2 | - | 4449 | 4632 | no | 1143 B |
| 4x8 | anonymous entry | full+reply | yes | 5112 | 18 | 2 | - | 4322 | 4519 | no | 1016 B |
| 4x8 | anonymous entry | full+2tree | yes | 4469 | 19 | 2 | - | 3646 | 3844 | no | 373 B |
| 4x8 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 4x8 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 5x2 | confidential signer | min | yes | 1608 | 13 | 1 | - | 1060 | 1077 | yes |  |
| 5x2 | confidential signer | full | yes | 2163 | 23 | 3 | 5 | 1147 | 1122 | yes |  |
| 5x2 | confidential signer | full+spl | yes | 2531 | 30 | 3 | - | 1279 | 1126 | yes |  |
| 5x2 | confidential signer | full+data | yes | 2365 | 23 | 3 | - | 1349 | 1320 | yes |  |
| 5x2 | confidential signer | full+reply | yes | 2163 | 23 | 3 | - | 1147 | 1122 | yes |  |
| 5x2 | confidential signer | full+2tree | yes | 2201 | 24 | 3 | - | 1152 | 1126 | yes |  |
| 5x2 | confidential in-proof | min | yes | 1703 | 13 | 1 | - | 1156 | 1174 | yes |  |
| 5x2 | confidential in-proof | full | yes | 2162 | 22 | 2 | 5 | 1243 | 1219 | yes |  |
| 5x2 | confidential in-proof | full+spl | yes | 2530 | 29 | 2 | - | 1375 | 1223 | yes |  |
| 5x2 | confidential in-proof | full+data | yes | 2364 | 22 | 2 | - | 1445 | 1417 | yes |  |
| 5x2 | confidential in-proof | full+reply | yes | 2162 | 22 | 2 | - | 1243 | 1219 | yes |  |
| 5x2 | confidential in-proof | full+2tree | yes | 2200 | 23 | 2 | - | 1248 | 1223 | yes |  |
| 5x2 | anonymous hidden | min | yes | 1735 | 13 | 1 | - | 1188 | 1236 | yes |  |
| 5x2 | anonymous hidden | full | yes | 2162 | 19 | 2 | 5 | 1339 | 1355 | yes |  |
| 5x2 | anonymous hidden | full+spl | yes | 2530 | 26 | 2 | - | 1471 | 1359 | yes |  |
| 5x2 | anonymous hidden | full+data | yes | 2364 | 19 | 2 | - | 1541 | 1553 | yes |  |
| 5x2 | anonymous hidden | full+reply | yes | 2261 | 19 | 2 | - | 1438 | 1452 | yes |  |
| 5x2 | anonymous hidden | full+2tree | yes | 2200 | 20 | 2 | - | 1344 | 1359 | yes |  |
| 5x2 | anonymous public owners | min | yes | 1672 | 13 | 1 | - | 1124 | 1139 | yes |  |
| 5x2 | anonymous public owners | full | yes | 2291 | 23 | 3 | 5 | 1275 | 1258 | yes |  |
| 5x2 | anonymous public owners | full+spl | yes | 2659 | 30 | 3 | - | 1407 | 1262 | yes |  |
| 5x2 | anonymous public owners | full+data | yes | 2493 | 23 | 3 | - | 1477 | 1456 | yes |  |
| 5x2 | anonymous public owners | full+reply | yes | 2390 | 23 | 3 | - | 1374 | 1355 | yes |  |
| 5x2 | anonymous public owners | full+2tree | yes | 2329 | 24 | 3 | - | 1280 | 1262 | yes |  |
| 5x2 | confidential entry | min | yes | 2616 | 13 | 1 | - | 2068 | 2085 | yes |  |
| 5x2 | confidential entry | full | yes | 3171 | 23 | 3 | 5 | 2155 | 2130 | yes |  |
| 5x2 | confidential entry | full+spl | yes | 3539 | 30 | 3 | - | 2287 | 2134 | yes |  |
| 5x2 | confidential entry | full+data | yes | 3373 | 23 | 3 | - | 2357 | 2328 | yes |  |
| 5x2 | confidential entry | full+reply | yes | 3171 | 23 | 3 | - | 2155 | 2130 | yes |  |
| 5x2 | confidential entry | full+2tree | yes | 3209 | 24 | 3 | - | 2160 | 2134 | yes |  |
| 5x2 | anonymous entry | min | yes | 2775 | 13 | 1 | - | 2228 | 2244 | yes |  |
| 5x2 | anonymous entry | full | yes | 3202 | 19 | 2 | 5 | 2379 | 2363 | yes |  |
| 5x2 | anonymous entry | full+spl | yes | 3570 | 26 | 2 | - | 2511 | 2367 | yes |  |
| 5x2 | anonymous entry | full+data | yes | 3404 | 19 | 2 | - | 2581 | 2561 | yes |  |
| 5x2 | anonymous entry | full+reply | yes | 3301 | 19 | 2 | - | 2478 | 2460 | yes |  |
| 5x2 | anonymous entry | full+2tree | yes | 3240 | 20 | 2 | - | 2384 | 2367 | yes |  |
| 5x2 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 5x2 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 5x4 | confidential signer | min | yes | 2042 | 13 | 1 | - | 1494 | 1583 | yes |  |
| 5x4 | confidential signer | full | yes | 2597 | 23 | 3 | 5 | 1581 | 1628 | yes |  |
| 5x4 | confidential signer | full+spl | yes | 2965 | 30 | 3 | - | 1713 | 1632 | yes |  |
| 5x4 | confidential signer | full+data | yes | 3001 | 23 | 3 | - | 1985 | 2024 | yes |  |
| 5x4 | confidential signer | full+reply | yes | 2597 | 23 | 3 | - | 1581 | 1628 | yes |  |
| 5x4 | confidential signer | full+2tree | yes | 2635 | 24 | 3 | - | 1586 | 1632 | yes |  |
| 5x4 | confidential in-proof | min | yes | 2137 | 13 | 1 | - | 1590 | 1680 | yes |  |
| 5x4 | confidential in-proof | full | yes | 2596 | 22 | 2 | 5 | 1677 | 1725 | yes |  |
| 5x4 | confidential in-proof | full+spl | yes | 2964 | 29 | 2 | - | 1809 | 1729 | yes |  |
| 5x4 | confidential in-proof | full+data | yes | 3000 | 22 | 2 | - | 2081 | 2121 | yes |  |
| 5x4 | confidential in-proof | full+reply | yes | 2596 | 22 | 2 | - | 1677 | 1725 | yes |  |
| 5x4 | confidential in-proof | full+2tree | yes | 2634 | 23 | 2 | - | 1682 | 1729 | yes |  |
| 5x4 | anonymous hidden | min | yes | 2233 | 13 | 1 | - | 1686 | 1806 | yes |  |
| 5x4 | anonymous hidden | full | yes | 2660 | 19 | 2 | 5 | 1837 | 1925 | yes |  |
| 5x4 | anonymous hidden | full+spl | yes | 3028 | 26 | 2 | - | 1969 | 1929 | yes |  |
| 5x4 | anonymous hidden | full+data | yes | 3064 | 19 | 2 | - | 2241 | 2321 | yes |  |
| 5x4 | anonymous hidden | full+reply | yes | 2953 | 19 | 2 | - | 2130 | 2216 | yes |  |
| 5x4 | anonymous hidden | full+2tree | yes | 2698 | 20 | 2 | - | 1842 | 1929 | yes |  |
| 5x4 | anonymous public owners | min | yes | 2170 | 13 | 1 | - | 1622 | 1709 | yes |  |
| 5x4 | anonymous public owners | full | yes | 2789 | 23 | 3 | 5 | 1773 | 1828 | yes |  |
| 5x4 | anonymous public owners | full+spl | yes | 3157 | 30 | 3 | - | 1905 | 1832 | yes |  |
| 5x4 | anonymous public owners | full+data | yes | 3193 | 23 | 3 | - | 2177 | 2224 | yes |  |
| 5x4 | anonymous public owners | full+reply | yes | 3082 | 23 | 3 | - | 2066 | 2119 | yes |  |
| 5x4 | anonymous public owners | full+2tree | yes | 2827 | 24 | 3 | - | 1778 | 1832 | yes |  |
| 5x4 | confidential entry | min | yes | 3050 | 13 | 1 | - | 2502 | 2591 | yes |  |
| 5x4 | confidential entry | full | yes | 3605 | 23 | 3 | 5 | 2589 | 2636 | yes |  |
| 5x4 | confidential entry | full+spl | yes | 3973 | 30 | 3 | - | 2721 | 2640 | yes |  |
| 5x4 | confidential entry | full+data | yes | 4009 | 23 | 3 | - | 2993 | 3032 | yes |  |
| 5x4 | confidential entry | full+reply | yes | 3605 | 23 | 3 | - | 2589 | 2636 | yes |  |
| 5x4 | confidential entry | full+2tree | yes | 3643 | 24 | 3 | - | 2594 | 2640 | yes |  |
| 5x4 | anonymous entry | min | yes | 3273 | 13 | 1 | - | 2726 | 2814 | yes |  |
| 5x4 | anonymous entry | full | yes | 3700 | 19 | 2 | 4 | 2877 | 2933 | yes |  |
| 5x4 | anonymous entry | full+spl | yes | 4068 | 26 | 2 | - | 3009 | 2937 | yes |  |
| 5x4 | anonymous entry | full+data | yes | 4104 | 19 | 2 | - | 3281 | 3329 | no | 8 B |
| 5x4 | anonymous entry | full+reply | yes | 3993 | 19 | 2 | - | 3170 | 3224 | yes |  |
| 5x4 | anonymous entry | full+2tree | yes | 3738 | 20 | 2 | - | 2882 | 2937 | yes |  |
| 5x4 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 5x4 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 4x16 | confidential signer | min | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | confidential signer | full | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | confidential signer | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | confidential signer | full+data | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | confidential signer | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | confidential signer | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | confidential in-proof | min | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | confidential in-proof | full | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | confidential in-proof | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | confidential in-proof | full+data | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | confidential in-proof | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | confidential in-proof | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | anonymous hidden | min | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | anonymous hidden | full | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | anonymous hidden | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | anonymous hidden | full+data | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | anonymous hidden | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | anonymous hidden | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | anonymous public owners | min | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | anonymous public owners | full | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | anonymous public owners | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | anonymous public owners | full+data | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | anonymous public owners | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | anonymous public owners | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | confidential entry | min | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | confidential entry | full | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | confidential entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | confidential entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | confidential entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | confidential entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | anonymous entry | min | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | anonymous entry | full | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | anonymous entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | anonymous entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | anonymous entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | anonymous entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 4x16 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 4x16 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 5x8 | confidential signer | min | yes | 2910 | 13 | 1 | - | 2362 | 2595 | yes |  |
| 5x8 | confidential signer | full | yes | 3465 | 23 | 3 | 5 | 2449 | 2640 | yes |  |
| 5x8 | confidential signer | full+spl | yes | 3833 | 30 | 3 | - | 2581 | 2644 | yes |  |
| 5x8 | confidential signer | full+data | yes | 4273 | 23 | 3 | - | 3257 | 3432 | no | 177 B |
| 5x8 | confidential signer | full+reply | yes | 3465 | 23 | 3 | - | 2449 | 2640 | yes |  |
| 5x8 | confidential signer | full+2tree | yes | 3503 | 24 | 3 | - | 2454 | 2644 | yes |  |
| 5x8 | confidential in-proof | min | yes | 3005 | 13 | 1 | - | 2458 | 2692 | yes |  |
| 5x8 | confidential in-proof | full | yes | 3464 | 22 | 2 | 5 | 2545 | 2737 | yes |  |
| 5x8 | confidential in-proof | full+spl | yes | 3832 | 29 | 2 | - | 2677 | 2741 | yes |  |
| 5x8 | confidential in-proof | full+data | yes | 4272 | 22 | 2 | - | 3353 | 3529 | no | 176 B |
| 5x8 | confidential in-proof | full+reply | yes | 3464 | 22 | 2 | - | 2545 | 2737 | yes |  |
| 5x8 | confidential in-proof | full+2tree | yes | 3502 | 23 | 2 | - | 2550 | 2741 | yes |  |
| 5x8 | anonymous hidden | min | yes | 3229 | 13 | 1 | - | 2682 | 2946 | yes |  |
| 5x8 | anonymous hidden | full | yes | 3656 | 19 | 2 | 4 | 2833 | 3065 | yes |  |
| 5x8 | anonymous hidden | full+spl | yes | 4024 | 26 | 2 | - | 2965 | 3069 | yes |  |
| 5x8 | anonymous hidden | full+data | yes | 4464 | 19 | 2 | - | 3641 | 3857 | no | 368 B |
| 5x8 | anonymous hidden | full+reply | yes | 4337 | 19 | 2 | - | 3514 | 3744 | no | 241 B |
| 5x8 | anonymous hidden | full+2tree | yes | 3694 | 20 | 2 | - | 2838 | 3069 | yes |  |
| 5x8 | anonymous public owners | min | yes | 3166 | 13 | 1 | - | 2618 | 2849 | yes |  |
| 5x8 | anonymous public owners | full | yes | 3785 | 23 | 3 | 4 | 2769 | 2968 | yes |  |
| 5x8 | anonymous public owners | full+spl | yes | 4153 | 30 | 3 | - | 2901 | 2972 | no | 57 B |
| 5x8 | anonymous public owners | full+data | yes | 4593 | 23 | 3 | - | 3577 | 3760 | no | 497 B |
| 5x8 | anonymous public owners | full+reply | yes | 4466 | 23 | 3 | - | 3450 | 3647 | no | 370 B |
| 5x8 | anonymous public owners | full+2tree | yes | 3823 | 24 | 3 | - | 2774 | 2972 | yes |  |
| 5x8 | confidential entry | min | yes | 3918 | 13 | 1 | - | 3370 | 3603 | yes |  |
| 5x8 | confidential entry | full | yes | 4473 | 23 | 3 | none | 3457 | 3648 | no | 377 B |
| 5x8 | confidential entry | full+spl | yes | 4841 | 30 | 3 | - | 3589 | 3652 | no | 745 B |
| 5x8 | confidential entry | full+data | yes | 5281 | 23 | 3 | - | 4265 | 4440 | no | 1185 B |
| 5x8 | confidential entry | full+reply | yes | 4473 | 23 | 3 | - | 3457 | 3648 | no | 377 B |
| 5x8 | confidential entry | full+2tree | yes | 4511 | 24 | 3 | - | 3462 | 3652 | no | 415 B |
| 5x8 | anonymous entry | min | yes | 4269 | 13 | 1 | - | 3722 | 3954 | no | 173 B |
| 5x8 | anonymous entry | full | yes | 4696 | 19 | 2 | none | 3873 | 4073 | no | 600 B |
| 5x8 | anonymous entry | full+spl | yes | 5064 | 26 | 2 | - | 4005 | 4077 | no | 968 B |
| 5x8 | anonymous entry | full+data | yes | 5504 | 19 | 2 | - | 4681 | 4865 | no | 1408 B |
| 5x8 | anonymous entry | full+reply | yes | 5377 | 19 | 2 | - | 4554 | 4752 | no | 1281 B |
| 5x8 | anonymous entry | full+2tree | yes | 4734 | 20 | 2 | - | 3878 | 4077 | no | 638 B |
| 5x8 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 5x8 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 6x2 | confidential signer | min | yes | 1673 | 14 | 1 | - | 1092 | 1110 | yes |  |
| 6x2 | confidential signer | full | yes | 2228 | 24 | 3 | 6 | 1179 | 1155 | yes |  |
| 6x2 | confidential signer | full+spl | yes | 2596 | 31 | 3 | - | 1311 | 1159 | yes |  |
| 6x2 | confidential signer | full+data | yes | 2430 | 24 | 3 | - | 1381 | 1353 | yes |  |
| 6x2 | confidential signer | full+reply | yes | 2228 | 24 | 3 | - | 1179 | 1155 | yes |  |
| 6x2 | confidential signer | full+2tree | yes | 2266 | 25 | 3 | - | 1184 | 1159 | yes |  |
| 6x2 | confidential in-proof | min | yes | 1768 | 14 | 1 | - | 1188 | 1207 | yes |  |
| 6x2 | confidential in-proof | full | yes | 2227 | 23 | 2 | 6 | 1275 | 1252 | yes |  |
| 6x2 | confidential in-proof | full+spl | yes | 2595 | 30 | 2 | - | 1407 | 1256 | yes |  |
| 6x2 | confidential in-proof | full+data | yes | 2429 | 23 | 2 | - | 1477 | 1450 | yes |  |
| 6x2 | confidential in-proof | full+reply | yes | 2227 | 23 | 2 | - | 1275 | 1252 | yes |  |
| 6x2 | confidential in-proof | full+2tree | yes | 2265 | 24 | 2 | - | 1280 | 1256 | yes |  |
| 6x2 | anonymous hidden | min | yes | 1800 | 14 | 1 | - | 1220 | 1269 | yes |  |
| 6x2 | anonymous hidden | full | yes | 2227 | 20 | 2 | 6 | 1371 | 1388 | yes |  |
| 6x2 | anonymous hidden | full+spl | yes | 2595 | 27 | 2 | - | 1503 | 1392 | yes |  |
| 6x2 | anonymous hidden | full+data | yes | 2429 | 20 | 2 | - | 1573 | 1586 | yes |  |
| 6x2 | anonymous hidden | full+reply | yes | 2326 | 20 | 2 | - | 1470 | 1485 | yes |  |
| 6x2 | anonymous hidden | full+2tree | yes | 2265 | 21 | 2 | - | 1376 | 1392 | yes |  |
| 6x2 | anonymous public owners | min | yes | 1737 | 14 | 1 | - | 1156 | 1172 | yes |  |
| 6x2 | anonymous public owners | full | yes | 2356 | 24 | 3 | 6 | 1307 | 1291 | yes |  |
| 6x2 | anonymous public owners | full+spl | yes | 2724 | 31 | 3 | - | 1439 | 1295 | yes |  |
| 6x2 | anonymous public owners | full+data | yes | 2558 | 24 | 3 | - | 1509 | 1489 | yes |  |
| 6x2 | anonymous public owners | full+reply | yes | 2455 | 24 | 3 | - | 1406 | 1388 | yes |  |
| 6x2 | anonymous public owners | full+2tree | yes | 2394 | 25 | 3 | - | 1312 | 1295 | yes |  |
| 6x2 | confidential entry | min | yes | 2881 | 14 | 1 | - | 2300 | 2318 | yes |  |
| 6x2 | confidential entry | full | yes | 3436 | 24 | 3 | 6 | 2387 | 2363 | yes |  |
| 6x2 | confidential entry | full+spl | yes | 3804 | 31 | 3 | - | 2519 | 2367 | yes |  |
| 6x2 | confidential entry | full+data | yes | 3638 | 24 | 3 | - | 2589 | 2561 | yes |  |
| 6x2 | confidential entry | full+reply | yes | 3436 | 24 | 3 | - | 2387 | 2363 | yes |  |
| 6x2 | confidential entry | full+2tree | yes | 3474 | 25 | 3 | - | 2392 | 2367 | yes |  |
| 6x2 | anonymous entry | min | yes | 3040 | 14 | 1 | - | 2460 | 2477 | yes |  |
| 6x2 | anonymous entry | full | yes | 3467 | 20 | 2 | 6 | 2611 | 2596 | yes |  |
| 6x2 | anonymous entry | full+spl | yes | 3835 | 27 | 2 | - | 2743 | 2600 | yes |  |
| 6x2 | anonymous entry | full+data | yes | 3669 | 20 | 2 | - | 2813 | 2794 | yes |  |
| 6x2 | anonymous entry | full+reply | yes | 3566 | 20 | 2 | - | 2710 | 2693 | yes |  |
| 6x2 | anonymous entry | full+2tree | yes | 3505 | 21 | 2 | - | 2616 | 2600 | yes |  |
| 6x2 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 6x2 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 6x4 | confidential signer | min | yes | 2107 | 14 | 1 | - | 1526 | 1616 | yes |  |
| 6x4 | confidential signer | full | yes | 2662 | 24 | 3 | 6 | 1613 | 1661 | yes |  |
| 6x4 | confidential signer | full+spl | yes | 3030 | 31 | 3 | - | 1745 | 1665 | yes |  |
| 6x4 | confidential signer | full+data | yes | 3066 | 24 | 3 | - | 2017 | 2057 | yes |  |
| 6x4 | confidential signer | full+reply | yes | 2662 | 24 | 3 | - | 1613 | 1661 | yes |  |
| 6x4 | confidential signer | full+2tree | yes | 2700 | 25 | 3 | - | 1618 | 1665 | yes |  |
| 6x4 | confidential in-proof | min | yes | 2202 | 14 | 1 | - | 1622 | 1713 | yes |  |
| 6x4 | confidential in-proof | full | yes | 2661 | 23 | 2 | 6 | 1709 | 1758 | yes |  |
| 6x4 | confidential in-proof | full+spl | yes | 3029 | 30 | 2 | - | 1841 | 1762 | yes |  |
| 6x4 | confidential in-proof | full+data | yes | 3065 | 23 | 2 | - | 2113 | 2154 | yes |  |
| 6x4 | confidential in-proof | full+reply | yes | 2661 | 23 | 2 | - | 1709 | 1758 | yes |  |
| 6x4 | confidential in-proof | full+2tree | yes | 2699 | 24 | 2 | - | 1714 | 1762 | yes |  |
| 6x4 | anonymous hidden | min | yes | 2298 | 14 | 1 | - | 1718 | 1839 | yes |  |
| 6x4 | anonymous hidden | full | yes | 2725 | 20 | 2 | 6 | 1869 | 1958 | yes |  |
| 6x4 | anonymous hidden | full+spl | yes | 3093 | 27 | 2 | - | 2001 | 1962 | yes |  |
| 6x4 | anonymous hidden | full+data | yes | 3129 | 20 | 2 | - | 2273 | 2354 | yes |  |
| 6x4 | anonymous hidden | full+reply | yes | 3018 | 20 | 2 | - | 2162 | 2249 | yes |  |
| 6x4 | anonymous hidden | full+2tree | yes | 2763 | 21 | 2 | - | 1874 | 1962 | yes |  |
| 6x4 | anonymous public owners | min | yes | 2235 | 14 | 1 | - | 1654 | 1742 | yes |  |
| 6x4 | anonymous public owners | full | yes | 2854 | 24 | 3 | 6 | 1805 | 1861 | yes |  |
| 6x4 | anonymous public owners | full+spl | yes | 3222 | 31 | 3 | - | 1937 | 1865 | yes |  |
| 6x4 | anonymous public owners | full+data | yes | 3258 | 24 | 3 | - | 2209 | 2257 | yes |  |
| 6x4 | anonymous public owners | full+reply | yes | 3147 | 24 | 3 | - | 2098 | 2152 | yes |  |
| 6x4 | anonymous public owners | full+2tree | yes | 2892 | 25 | 3 | - | 1810 | 1865 | yes |  |
| 6x4 | confidential entry | min | yes | 3315 | 14 | 1 | - | 2734 | 2824 | yes |  |
| 6x4 | confidential entry | full | yes | 3870 | 24 | 3 | 3 | 2821 | 2869 | yes |  |
| 6x4 | confidential entry | full+spl | yes | 4238 | 31 | 3 | - | 2953 | 2873 | no | 142 B |
| 6x4 | confidential entry | full+data | yes | 4274 | 24 | 3 | - | 3225 | 3265 | no | 178 B |
| 6x4 | confidential entry | full+reply | yes | 3870 | 24 | 3 | - | 2821 | 2869 | yes |  |
| 6x4 | confidential entry | full+2tree | yes | 3908 | 25 | 3 | - | 2826 | 2873 | yes |  |
| 6x4 | anonymous entry | min | yes | 3538 | 14 | 1 | - | 2958 | 3047 | yes |  |
| 6x4 | anonymous entry | full | yes | 3965 | 20 | 2 | 1 | 3109 | 3166 | yes |  |
| 6x4 | anonymous entry | full+spl | yes | 4333 | 27 | 2 | - | 3241 | 3170 | no | 237 B |
| 6x4 | anonymous entry | full+data | yes | 4369 | 20 | 2 | - | 3513 | 3562 | no | 273 B |
| 6x4 | anonymous entry | full+reply | yes | 4258 | 20 | 2 | - | 3402 | 3457 | no | 162 B |
| 6x4 | anonymous entry | full+2tree | yes | 4003 | 21 | 2 | - | 3114 | 3170 | yes |  |
| 6x4 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 6x4 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 5x16 | confidential signer | min | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | confidential signer | full | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | confidential signer | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | confidential signer | full+data | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | confidential signer | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | confidential signer | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | confidential in-proof | min | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | confidential in-proof | full | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | confidential in-proof | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | confidential in-proof | full+data | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | confidential in-proof | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | confidential in-proof | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | anonymous hidden | min | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | anonymous hidden | full | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | anonymous hidden | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | anonymous hidden | full+data | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | anonymous hidden | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | anonymous hidden | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | anonymous public owners | min | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | anonymous public owners | full | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | anonymous public owners | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | anonymous public owners | full+data | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | anonymous public owners | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | anonymous public owners | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | confidential entry | min | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | confidential entry | full | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | confidential entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | confidential entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | confidential entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | confidential entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | anonymous entry | min | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | anonymous entry | full | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | anonymous entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | anonymous entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | anonymous entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | anonymous entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 5x16 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 5x16 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 6x8 | confidential signer | min | yes | 2975 | 14 | 1 | - | 2394 | 2628 | yes |  |
| 6x8 | confidential signer | full | yes | 3530 | 24 | 3 | 6 | 2481 | 2673 | yes |  |
| 6x8 | confidential signer | full+spl | yes | 3898 | 31 | 3 | - | 2613 | 2677 | yes |  |
| 6x8 | confidential signer | full+data | yes | 4338 | 24 | 3 | - | 3289 | 3465 | no | 242 B |
| 6x8 | confidential signer | full+reply | yes | 3530 | 24 | 3 | - | 2481 | 2673 | yes |  |
| 6x8 | confidential signer | full+2tree | yes | 3568 | 25 | 3 | - | 2486 | 2677 | yes |  |
| 6x8 | confidential in-proof | min | yes | 3070 | 14 | 1 | - | 2490 | 2725 | yes |  |
| 6x8 | confidential in-proof | full | yes | 3529 | 23 | 2 | 5 | 2577 | 2770 | yes |  |
| 6x8 | confidential in-proof | full+spl | yes | 3897 | 30 | 2 | - | 2709 | 2774 | yes |  |
| 6x8 | confidential in-proof | full+data | yes | 4337 | 23 | 2 | - | 3385 | 3562 | no | 241 B |
| 6x8 | confidential in-proof | full+reply | yes | 3529 | 23 | 2 | - | 2577 | 2770 | yes |  |
| 6x8 | confidential in-proof | full+2tree | yes | 3567 | 24 | 2 | - | 2582 | 2774 | yes |  |
| 6x8 | anonymous hidden | min | yes | 3294 | 14 | 1 | - | 2714 | 2979 | yes |  |
| 6x8 | anonymous hidden | full | yes | 3721 | 20 | 2 | 3 | 2865 | 3098 | yes |  |
| 6x8 | anonymous hidden | full+spl | yes | 4089 | 27 | 2 | - | 2997 | 3102 | yes |  |
| 6x8 | anonymous hidden | full+data | yes | 4529 | 20 | 2 | - | 3673 | 3890 | no | 433 B |
| 6x8 | anonymous hidden | full+reply | yes | 4402 | 20 | 2 | - | 3546 | 3777 | no | 306 B |
| 6x8 | anonymous hidden | full+2tree | yes | 3759 | 21 | 2 | - | 2870 | 3102 | yes |  |
| 6x8 | anonymous public owners | min | yes | 3231 | 14 | 1 | - | 2650 | 2882 | yes |  |
| 6x8 | anonymous public owners | full | yes | 3850 | 24 | 3 | 3 | 2801 | 3001 | yes |  |
| 6x8 | anonymous public owners | full+spl | yes | 4218 | 31 | 3 | - | 2933 | 3005 | no | 122 B |
| 6x8 | anonymous public owners | full+data | yes | 4658 | 24 | 3 | - | 3609 | 3793 | no | 562 B |
| 6x8 | anonymous public owners | full+reply | yes | 4531 | 24 | 3 | - | 3482 | 3680 | no | 435 B |
| 6x8 | anonymous public owners | full+2tree | yes | 3888 | 25 | 3 | - | 2806 | 3005 | yes |  |
| 6x8 | confidential entry | min | yes | 4183 | 14 | 1 | - | 3602 | 3836 | no | 87 B |
| 6x8 | confidential entry | full | yes | 4738 | 24 | 3 | none | 3689 | 3881 | no | 642 B |
| 6x8 | confidential entry | full+spl | yes | 5106 | 31 | 3 | - | 3821 | 3885 | no | 1010 B |
| 6x8 | confidential entry | full+data | yes | 5546 | 24 | 3 | - | 4497 | 4673 | no | 1450 B |
| 6x8 | confidential entry | full+reply | yes | 4738 | 24 | 3 | - | 3689 | 3881 | no | 642 B |
| 6x8 | confidential entry | full+2tree | yes | 4776 | 25 | 3 | - | 3694 | 3885 | no | 680 B |
| 6x8 | anonymous entry | min | yes | 4534 | 14 | 1 | - | 3954 | 4187 | no | 438 B |
| 6x8 | anonymous entry | full | yes | 4961 | 20 | 2 | none | 4105 | 4306 | no | 865 B |
| 6x8 | anonymous entry | full+spl | yes | 5329 | 27 | 2 | - | 4237 | 4310 | no | 1233 B |
| 6x8 | anonymous entry | full+data | yes | 5769 | 20 | 2 | - | 4913 | 5098 | no | 1673 B |
| 6x8 | anonymous entry | full+reply | yes | 5642 | 20 | 2 | - | 4786 | 4985 | no | 1546 B |
| 6x8 | anonymous entry | full+2tree | yes | 4999 | 21 | 2 | - | 4110 | 4310 | no | 903 B |
| 6x8 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 6x8 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 8x2 | confidential signer | min | yes | 1803 | 16 | 1 | - | 1156 | 1176 | yes |  |
| 8x2 | confidential signer | full | yes | 2358 | 26 | 3 | 8 | 1243 | 1221 | yes |  |
| 8x2 | confidential signer | full+spl | yes | 2726 | 33 | 3 | - | 1375 | 1225 | yes |  |
| 8x2 | confidential signer | full+data | yes | 2560 | 26 | 3 | - | 1445 | 1419 | yes |  |
| 8x2 | confidential signer | full+reply | yes | 2358 | 26 | 3 | - | 1243 | 1221 | yes |  |
| 8x2 | confidential signer | full+2tree | yes | 2396 | 27 | 3 | - | 1248 | 1225 | yes |  |
| 8x2 | confidential in-proof | min | yes | 1898 | 16 | 1 | - | 1252 | 1273 | yes |  |
| 8x2 | confidential in-proof | full | yes | 2357 | 25 | 2 | 8 | 1339 | 1318 | yes |  |
| 8x2 | confidential in-proof | full+spl | yes | 2725 | 32 | 2 | - | 1471 | 1322 | yes |  |
| 8x2 | confidential in-proof | full+data | yes | 2559 | 25 | 2 | - | 1541 | 1516 | yes |  |
| 8x2 | confidential in-proof | full+reply | yes | 2357 | 25 | 2 | - | 1339 | 1318 | yes |  |
| 8x2 | confidential in-proof | full+2tree | yes | 2395 | 26 | 2 | - | 1344 | 1322 | yes |  |
| 8x2 | anonymous hidden | min | yes | 1930 | 16 | 1 | - | 1284 | 1335 | yes |  |
| 8x2 | anonymous hidden | full | yes | 2357 | 22 | 2 | 8 | 1435 | 1454 | yes |  |
| 8x2 | anonymous hidden | full+spl | yes | 2725 | 29 | 2 | - | 1567 | 1458 | yes |  |
| 8x2 | anonymous hidden | full+data | yes | 2559 | 22 | 2 | - | 1637 | 1652 | yes |  |
| 8x2 | anonymous hidden | full+reply | yes | 2456 | 22 | 2 | - | 1534 | 1551 | yes |  |
| 8x2 | anonymous hidden | full+2tree | yes | 2395 | 23 | 2 | - | 1440 | 1458 | yes |  |
| 8x2 | anonymous public owners | min | yes | 1867 | 16 | 1 | - | 1220 | 1238 | yes |  |
| 8x2 | anonymous public owners | full | yes | 2486 | 26 | 3 | 8 | 1371 | 1357 | yes |  |
| 8x2 | anonymous public owners | full+spl | yes | 2854 | 33 | 3 | - | 1503 | 1361 | yes |  |
| 8x2 | anonymous public owners | full+data | yes | 2688 | 26 | 3 | - | 1573 | 1555 | yes |  |
| 8x2 | anonymous public owners | full+reply | yes | 2585 | 26 | 3 | - | 1470 | 1454 | yes |  |
| 8x2 | anonymous public owners | full+2tree | yes | 2524 | 27 | 3 | - | 1376 | 1361 | yes |  |
| 8x2 | confidential entry | min | yes | 3411 | 16 | 1 | - | 2764 | 2784 | yes |  |
| 8x2 | confidential entry | full | yes | 3966 | 26 | 3 | 2 | 2851 | 2829 | yes |  |
| 8x2 | confidential entry | full+spl | yes | 4334 | 33 | 3 | - | 2983 | 2833 | no | 238 B |
| 8x2 | confidential entry | full+data | yes | 4168 | 26 | 3 | - | 3053 | 3027 | no | 72 B |
| 8x2 | confidential entry | full+reply | yes | 3966 | 26 | 3 | - | 2851 | 2829 | yes |  |
| 8x2 | confidential entry | full+2tree | yes | 4004 | 27 | 3 | - | 2856 | 2833 | yes |  |
| 8x2 | anonymous entry | min | yes | 3570 | 16 | 1 | - | 2924 | 2943 | yes |  |
| 8x2 | anonymous entry | full | yes | 3997 | 22 | 2 | 1 | 3075 | 3062 | yes |  |
| 8x2 | anonymous entry | full+spl | yes | 4365 | 29 | 2 | - | 3207 | 3066 | no | 269 B |
| 8x2 | anonymous entry | full+data | yes | 4199 | 22 | 2 | - | 3277 | 3260 | no | 103 B |
| 8x2 | anonymous entry | full+reply | yes | 4096 | 22 | 2 | - | 3174 | 3159 | yes |  |
| 8x2 | anonymous entry | full+2tree | yes | 4035 | 23 | 2 | - | 3080 | 3066 | yes |  |
| 8x2 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 8x2 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 8x4 | confidential signer | min | yes | 2237 | 16 | 1 | - | 1590 | 1682 | yes |  |
| 8x4 | confidential signer | full | yes | 2792 | 26 | 3 | 8 | 1677 | 1727 | yes |  |
| 8x4 | confidential signer | full+spl | yes | 3160 | 33 | 3 | - | 1809 | 1731 | yes |  |
| 8x4 | confidential signer | full+data | yes | 3196 | 26 | 3 | - | 2081 | 2123 | yes |  |
| 8x4 | confidential signer | full+reply | yes | 2792 | 26 | 3 | - | 1677 | 1727 | yes |  |
| 8x4 | confidential signer | full+2tree | yes | 2830 | 27 | 3 | - | 1682 | 1731 | yes |  |
| 8x4 | confidential in-proof | min | yes | 2332 | 16 | 1 | - | 1686 | 1779 | yes |  |
| 8x4 | confidential in-proof | full | yes | 2791 | 25 | 2 | 8 | 1773 | 1824 | yes |  |
| 8x4 | confidential in-proof | full+spl | yes | 3159 | 32 | 2 | - | 1905 | 1828 | yes |  |
| 8x4 | confidential in-proof | full+data | yes | 3195 | 25 | 2 | - | 2177 | 2220 | yes |  |
| 8x4 | confidential in-proof | full+reply | yes | 2791 | 25 | 2 | - | 1773 | 1824 | yes |  |
| 8x4 | confidential in-proof | full+2tree | yes | 2829 | 26 | 2 | - | 1778 | 1828 | yes |  |
| 8x4 | anonymous hidden | min | yes | 2428 | 16 | 1 | - | 1782 | 1905 | yes |  |
| 8x4 | anonymous hidden | full | yes | 2855 | 22 | 2 | 8 | 1933 | 2024 | yes |  |
| 8x4 | anonymous hidden | full+spl | yes | 3223 | 29 | 2 | - | 2065 | 2028 | yes |  |
| 8x4 | anonymous hidden | full+data | yes | 3259 | 22 | 2 | - | 2337 | 2420 | yes |  |
| 8x4 | anonymous hidden | full+reply | yes | 3148 | 22 | 2 | - | 2226 | 2315 | yes |  |
| 8x4 | anonymous hidden | full+2tree | yes | 2893 | 23 | 2 | - | 1938 | 2028 | yes |  |
| 8x4 | anonymous public owners | min | yes | 2365 | 16 | 1 | - | 1718 | 1808 | yes |  |
| 8x4 | anonymous public owners | full | yes | 2984 | 26 | 3 | 8 | 1869 | 1927 | yes |  |
| 8x4 | anonymous public owners | full+spl | yes | 3352 | 33 | 3 | - | 2001 | 1931 | yes |  |
| 8x4 | anonymous public owners | full+data | yes | 3388 | 26 | 3 | - | 2273 | 2323 | yes |  |
| 8x4 | anonymous public owners | full+reply | yes | 3277 | 26 | 3 | - | 2162 | 2218 | yes |  |
| 8x4 | anonymous public owners | full+2tree | yes | 3022 | 27 | 3 | - | 1874 | 1931 | yes |  |
| 8x4 | confidential entry | min | yes | 3845 | 16 | 1 | - | 3198 | 3290 | yes |  |
| 8x4 | confidential entry | full | yes | 4400 | 26 | 3 | none | 3285 | 3335 | no | 304 B |
| 8x4 | confidential entry | full+spl | yes | 4768 | 33 | 3 | - | 3417 | 3339 | no | 672 B |
| 8x4 | confidential entry | full+data | yes | 4804 | 26 | 3 | - | 3689 | 3731 | no | 708 B |
| 8x4 | confidential entry | full+reply | yes | 4400 | 26 | 3 | - | 3285 | 3335 | no | 304 B |
| 8x4 | confidential entry | full+2tree | yes | 4438 | 27 | 3 | - | 3290 | 3339 | no | 342 B |
| 8x4 | anonymous entry | min | yes | 4068 | 16 | 1 | - | 3422 | 3513 | yes |  |
| 8x4 | anonymous entry | full | yes | 4495 | 22 | 2 | none | 3573 | 3632 | no | 399 B |
| 8x4 | anonymous entry | full+spl | yes | 4863 | 29 | 2 | - | 3705 | 3636 | no | 767 B |
| 8x4 | anonymous entry | full+data | yes | 4899 | 22 | 2 | - | 3977 | 4028 | no | 803 B |
| 8x4 | anonymous entry | full+reply | yes | 4788 | 22 | 2 | - | 3866 | 3923 | no | 692 B |
| 8x4 | anonymous entry | full+2tree | yes | 4533 | 23 | 2 | - | 3578 | 3636 | no | 437 B |
| 8x4 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 8x4 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 8x8 | confidential signer | min | yes | 3105 | 16 | 1 | - | 2458 | 2694 | yes |  |
| 8x8 | confidential signer | full | yes | 3660 | 26 | 3 | 5 | 2545 | 2739 | yes |  |
| 8x8 | confidential signer | full+spl | yes | 4028 | 33 | 3 | - | 2677 | 2743 | yes |  |
| 8x8 | confidential signer | full+data | yes | 4468 | 26 | 3 | - | 3353 | 3531 | no | 372 B |
| 8x8 | confidential signer | full+reply | yes | 3660 | 26 | 3 | - | 2545 | 2739 | yes |  |
| 8x8 | confidential signer | full+2tree | yes | 3698 | 27 | 3 | - | 2550 | 2743 | yes |  |
| 8x8 | confidential in-proof | min | yes | 3200 | 16 | 1 | - | 2554 | 2791 | yes |  |
| 8x8 | confidential in-proof | full | yes | 3659 | 25 | 2 | 4 | 2641 | 2836 | yes |  |
| 8x8 | confidential in-proof | full+spl | yes | 4027 | 32 | 2 | - | 2773 | 2840 | yes |  |
| 8x8 | confidential in-proof | full+data | yes | 4467 | 25 | 2 | - | 3449 | 3628 | no | 371 B |
| 8x8 | confidential in-proof | full+reply | yes | 3659 | 25 | 2 | - | 2641 | 2836 | yes |  |
| 8x8 | confidential in-proof | full+2tree | yes | 3697 | 26 | 2 | - | 2646 | 2840 | yes |  |
| 8x8 | anonymous hidden | min | yes | 3424 | 16 | 1 | - | 2778 | 3045 | yes |  |
| 8x8 | anonymous hidden | full | yes | 3851 | 22 | 2 | 2 | 2929 | 3164 | yes |  |
| 8x8 | anonymous hidden | full+spl | yes | 4219 | 29 | 2 | - | 3061 | 3168 | no | 123 B |
| 8x8 | anonymous hidden | full+data | yes | 4659 | 22 | 2 | - | 3737 | 3956 | no | 563 B |
| 8x8 | anonymous hidden | full+reply | yes | 4532 | 22 | 2 | - | 3610 | 3843 | no | 436 B |
| 8x8 | anonymous hidden | full+2tree | yes | 3889 | 23 | 2 | - | 2934 | 3168 | yes |  |
| 8x8 | anonymous public owners | min | yes | 3361 | 16 | 1 | - | 2714 | 2948 | yes |  |
| 8x8 | anonymous public owners | full | yes | 3980 | 26 | 3 | 2 | 2865 | 3067 | yes |  |
| 8x8 | anonymous public owners | full+spl | yes | 4348 | 33 | 3 | - | 2997 | 3071 | no | 252 B |
| 8x8 | anonymous public owners | full+data | yes | 4788 | 26 | 3 | - | 3673 | 3859 | no | 692 B |
| 8x8 | anonymous public owners | full+reply | yes | 4661 | 26 | 3 | - | 3546 | 3746 | no | 565 B |
| 8x8 | anonymous public owners | full+2tree | yes | 4018 | 27 | 3 | - | 2870 | 3071 | yes |  |
| 8x8 | confidential entry | min | yes | 4713 | 16 | 1 | - | 4066 | 4302 | no | 617 B |
| 8x8 | confidential entry | full | yes | 5268 | 26 | 3 | none | 4153 | 4347 | no | 1172 B |
| 8x8 | confidential entry | full+spl | yes | 5636 | 33 | 3 | - | 4285 | 4351 | no | 1540 B |
| 8x8 | confidential entry | full+data | yes | 6076 | 26 | 3 | - | 4961 | 5139 | no | 1980 B |
| 8x8 | confidential entry | full+reply | yes | 5268 | 26 | 3 | - | 4153 | 4347 | no | 1172 B |
| 8x8 | confidential entry | full+2tree | yes | 5306 | 27 | 3 | - | 4158 | 4351 | no | 1210 B |
| 8x8 | anonymous entry | min | yes | 5064 | 16 | 1 | - | 4418 | 4653 | no | 968 B |
| 8x8 | anonymous entry | full | yes | 5491 | 22 | 2 | none | 4569 | 4772 | no | 1395 B |
| 8x8 | anonymous entry | full+spl | yes | 5859 | 29 | 2 | - | 4701 | 4776 | no | 1763 B |
| 8x8 | anonymous entry | full+data | yes | 6299 | 22 | 2 | - | 5377 | 5564 | no | 2203 B |
| 8x8 | anonymous entry | full+reply | yes | 6172 | 22 | 2 | - | 5250 | 5451 | no | 2076 B |
| 8x8 | anonymous entry | full+2tree | yes | 5529 | 23 | 2 | - | 4574 | 4776 | no | 1433 B |
| 8x8 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 8x8 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 8x16 | confidential signer | min | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | confidential signer | full | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | confidential signer | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | confidential signer | full+data | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | confidential signer | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | confidential signer | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | confidential in-proof | min | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | confidential in-proof | full | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | confidential in-proof | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | confidential in-proof | full+data | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | confidential in-proof | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | confidential in-proof | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | anonymous hidden | min | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | anonymous hidden | full | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | anonymous hidden | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | anonymous hidden | full+data | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | anonymous hidden | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | anonymous hidden | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | anonymous public owners | min | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | anonymous public owners | full | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | anonymous public owners | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | anonymous public owners | full+data | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | anonymous public owners | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | anonymous public owners | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | confidential entry | min | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | confidential entry | full | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | confidential entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | confidential entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | confidential entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | confidential entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | anonymous entry | min | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | anonymous entry | full | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | anonymous entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | anonymous entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | anonymous entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | anonymous entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 8x16 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 8x16 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 12x2 | confidential signer | min | yes | 2063 | 20 | 1 | - | 1284 | 1308 | yes |  |
| 12x2 | confidential signer | full | yes | 2618 | 30 | 3 | 10 | 1371 | 1353 | yes |  |
| 12x2 | confidential signer | full+spl | yes | 2986 | 37 | 3 | - | 1503 | 1357 | yes |  |
| 12x2 | confidential signer | full+data | yes | 2820 | 30 | 3 | - | 1573 | 1551 | yes |  |
| 12x2 | confidential signer | full+reply | yes | 2618 | 30 | 3 | - | 1371 | 1353 | yes |  |
| 12x2 | confidential signer | full+2tree | yes | 2657 | 31 | 3 | - | 1377 | 1357 | yes |  |
| 12x2 | confidential in-proof | min | yes | 2158 | 20 | 1 | - | 1380 | 1405 | yes |  |
| 12x2 | confidential in-proof | full | yes | 2617 | 29 | 2 | 10 | 1467 | 1450 | yes |  |
| 12x2 | confidential in-proof | full+spl | yes | 2985 | 36 | 2 | - | 1599 | 1454 | yes |  |
| 12x2 | confidential in-proof | full+data | yes | 2819 | 29 | 2 | - | 1669 | 1648 | yes |  |
| 12x2 | confidential in-proof | full+reply | yes | 2617 | 29 | 2 | - | 1467 | 1450 | yes |  |
| 12x2 | confidential in-proof | full+2tree | yes | 2656 | 30 | 2 | - | 1473 | 1454 | yes |  |
| 12x2 | anonymous hidden | min | yes | 2190 | 20 | 1 | - | 1412 | 1467 | yes |  |
| 12x2 | anonymous hidden | full | yes | 2617 | 26 | 2 | 10 | 1563 | 1586 | yes |  |
| 12x2 | anonymous hidden | full+spl | yes | 2985 | 33 | 2 | - | 1695 | 1590 | yes |  |
| 12x2 | anonymous hidden | full+data | yes | 2819 | 26 | 2 | - | 1765 | 1784 | yes |  |
| 12x2 | anonymous hidden | full+reply | yes | 2716 | 26 | 2 | - | 1662 | 1683 | yes |  |
| 12x2 | anonymous hidden | full+2tree | yes | 2656 | 27 | 2 | - | 1569 | 1590 | yes |  |
| 12x2 | anonymous public owners | min | yes | 2127 | 20 | 1 | - | 1348 | 1370 | yes |  |
| 12x2 | anonymous public owners | full | yes | 2746 | 30 | 3 | 10 | 1499 | 1489 | yes |  |
| 12x2 | anonymous public owners | full+spl | yes | 3114 | 37 | 3 | - | 1631 | 1493 | yes |  |
| 12x2 | anonymous public owners | full+data | yes | 2948 | 30 | 3 | - | 1701 | 1687 | yes |  |
| 12x2 | anonymous public owners | full+reply | yes | 2845 | 30 | 3 | - | 1598 | 1586 | yes |  |
| 12x2 | anonymous public owners | full+2tree | yes | 2785 | 31 | 3 | - | 1505 | 1493 | yes |  |
| 12x2 | confidential entry | min | none | - | - | - | - | - | - | no | catalog key |
| 12x2 | confidential entry | full | none | - | - | - | - | - | - | no | catalog key |
| 12x2 | confidential entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 12x2 | confidential entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 12x2 | confidential entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 12x2 | confidential entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 12x2 | anonymous entry | min | none | - | - | - | - | - | - | no | catalog key |
| 12x2 | anonymous entry | full | none | - | - | - | - | - | - | no | catalog key |
| 12x2 | anonymous entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 12x2 | anonymous entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 12x2 | anonymous entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 12x2 | anonymous entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 12x2 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 12x2 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 12x4 | confidential signer | min | yes | 2497 | 20 | 1 | - | 1718 | 1814 | yes |  |
| 12x4 | confidential signer | full | yes | 3052 | 30 | 3 | 10 | 1805 | 1859 | yes |  |
| 12x4 | confidential signer | full+spl | yes | 3420 | 37 | 3 | - | 1937 | 1863 | yes |  |
| 12x4 | confidential signer | full+data | yes | 3456 | 30 | 3 | - | 2209 | 2255 | yes |  |
| 12x4 | confidential signer | full+reply | yes | 3052 | 30 | 3 | - | 1805 | 1859 | yes |  |
| 12x4 | confidential signer | full+2tree | yes | 3091 | 31 | 3 | - | 1811 | 1863 | yes |  |
| 12x4 | confidential in-proof | min | yes | 2592 | 20 | 1 | - | 1814 | 1911 | yes |  |
| 12x4 | confidential in-proof | full | yes | 3051 | 29 | 2 | 10 | 1901 | 1956 | yes |  |
| 12x4 | confidential in-proof | full+spl | yes | 3419 | 36 | 2 | - | 2033 | 1960 | yes |  |
| 12x4 | confidential in-proof | full+data | yes | 3455 | 29 | 2 | - | 2305 | 2352 | yes |  |
| 12x4 | confidential in-proof | full+reply | yes | 3051 | 29 | 2 | - | 1901 | 1956 | yes |  |
| 12x4 | confidential in-proof | full+2tree | yes | 3090 | 30 | 2 | - | 1907 | 1960 | yes |  |
| 12x4 | anonymous hidden | min | yes | 2688 | 20 | 1 | - | 1910 | 2037 | yes |  |
| 12x4 | anonymous hidden | full | yes | 3115 | 26 | 2 | 10 | 2061 | 2156 | yes |  |
| 12x4 | anonymous hidden | full+spl | yes | 3483 | 33 | 2 | - | 2193 | 2160 | yes |  |
| 12x4 | anonymous hidden | full+data | yes | 3519 | 26 | 2 | - | 2465 | 2552 | yes |  |
| 12x4 | anonymous hidden | full+reply | yes | 3408 | 26 | 2 | - | 2354 | 2447 | yes |  |
| 12x4 | anonymous hidden | full+2tree | yes | 3154 | 27 | 2 | - | 2067 | 2160 | yes |  |
| 12x4 | anonymous public owners | min | yes | 2625 | 20 | 1 | - | 1846 | 1940 | yes |  |
| 12x4 | anonymous public owners | full | yes | 3244 | 30 | 3 | 9 | 1997 | 2059 | yes |  |
| 12x4 | anonymous public owners | full+spl | yes | 3612 | 37 | 3 | - | 2129 | 2063 | yes |  |
| 12x4 | anonymous public owners | full+data | yes | 3648 | 30 | 3 | - | 2401 | 2455 | yes |  |
| 12x4 | anonymous public owners | full+reply | yes | 3537 | 30 | 3 | - | 2290 | 2350 | yes |  |
| 12x4 | anonymous public owners | full+2tree | yes | 3283 | 31 | 3 | - | 2003 | 2063 | yes |  |
| 12x4 | confidential entry | min | none | - | - | - | - | - | - | no | catalog key |
| 12x4 | confidential entry | full | none | - | - | - | - | - | - | no | catalog key |
| 12x4 | confidential entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 12x4 | confidential entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 12x4 | confidential entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 12x4 | confidential entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 12x4 | anonymous entry | min | none | - | - | - | - | - | - | no | catalog key |
| 12x4 | anonymous entry | full | none | - | - | - | - | - | - | no | catalog key |
| 12x4 | anonymous entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 12x4 | anonymous entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 12x4 | anonymous entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 12x4 | anonymous entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 12x4 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 12x4 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 12x8 | confidential signer | min | yes | 3365 | 20 | 1 | - | 2586 | 2826 | yes |  |
| 12x8 | confidential signer | full | yes | 3920 | 30 | 3 | 2 | 2673 | 2871 | yes |  |
| 12x8 | confidential signer | full+spl | yes | 4288 | 37 | 3 | - | 2805 | 2875 | no | 192 B |
| 12x8 | confidential signer | full+data | yes | 4728 | 30 | 3 | - | 3481 | 3663 | no | 632 B |
| 12x8 | confidential signer | full+reply | yes | 3920 | 30 | 3 | - | 2673 | 2871 | yes |  |
| 12x8 | confidential signer | full+2tree | yes | 3959 | 31 | 3 | - | 2679 | 2875 | yes |  |
| 12x8 | confidential in-proof | min | yes | 3460 | 20 | 1 | - | 2682 | 2923 | yes |  |
| 12x8 | confidential in-proof | full | yes | 3919 | 29 | 2 | 1 | 2769 | 2968 | yes |  |
| 12x8 | confidential in-proof | full+spl | yes | 4287 | 36 | 2 | - | 2901 | 2972 | no | 191 B |
| 12x8 | confidential in-proof | full+data | yes | 4727 | 29 | 2 | - | 3577 | 3760 | no | 631 B |
| 12x8 | confidential in-proof | full+reply | yes | 3919 | 29 | 2 | - | 2769 | 2968 | yes |  |
| 12x8 | confidential in-proof | full+2tree | yes | 3958 | 30 | 2 | - | 2775 | 2972 | yes |  |
| 12x8 | anonymous hidden | min | yes | 3684 | 20 | 1 | - | 2906 | 3177 | yes |  |
| 12x8 | anonymous hidden | full | yes | 4111 | 26 | 2 | none | 3057 | 3296 | no | 15 B |
| 12x8 | anonymous hidden | full+spl | yes | 4479 | 33 | 2 | - | 3189 | 3300 | no | 383 B |
| 12x8 | anonymous hidden | full+data | yes | 4919 | 26 | 2 | - | 3865 | 4088 | no | 823 B |
| 12x8 | anonymous hidden | full+reply | yes | 4792 | 26 | 2 | - | 3738 | 3975 | no | 696 B |
| 12x8 | anonymous hidden | full+2tree | yes | 4150 | 27 | 2 | - | 3063 | 3300 | no | 54 B |
| 12x8 | anonymous public owners | min | yes | 3621 | 20 | 1 | - | 2842 | 3080 | yes |  |
| 12x8 | anonymous public owners | full | yes | 4240 | 30 | 3 | none | 2993 | 3199 | no | 144 B |
| 12x8 | anonymous public owners | full+spl | yes | 4608 | 37 | 3 | - | 3125 | 3203 | no | 512 B |
| 12x8 | anonymous public owners | full+data | yes | 5048 | 30 | 3 | - | 3801 | 3991 | no | 952 B |
| 12x8 | anonymous public owners | full+reply | yes | 4921 | 30 | 3 | - | 3674 | 3878 | no | 825 B |
| 12x8 | anonymous public owners | full+2tree | yes | 4279 | 31 | 3 | - | 2999 | 3203 | no | 183 B |
| 12x8 | confidential entry | min | none | - | - | - | - | - | - | no | catalog key |
| 12x8 | confidential entry | full | none | - | - | - | - | - | - | no | catalog key |
| 12x8 | confidential entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 12x8 | confidential entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 12x8 | confidential entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 12x8 | confidential entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 12x8 | anonymous entry | min | none | - | - | - | - | - | - | no | catalog key |
| 12x8 | anonymous entry | full | none | - | - | - | - | - | - | no | catalog key |
| 12x8 | anonymous entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 12x8 | anonymous entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 12x8 | anonymous entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 12x8 | anonymous entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 12x8 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 12x8 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 16x2 | confidential signer | min | yes | 2323 | 24 | 1 | - | 1412 | 1440 | yes |  |
| 16x2 | confidential signer | full | yes | 2878 | 34 | 3 | 10 | 1499 | 1485 | yes |  |
| 16x2 | confidential signer | full+spl | yes | 3246 | 41 | 3 | - | 1631 | 1489 | yes |  |
| 16x2 | confidential signer | full+data | yes | 3080 | 34 | 3 | - | 1701 | 1683 | yes |  |
| 16x2 | confidential signer | full+reply | yes | 2878 | 34 | 3 | - | 1499 | 1485 | yes |  |
| 16x2 | confidential signer | full+2tree | yes | 2917 | 35 | 3 | - | 1505 | 1489 | yes |  |
| 16x2 | confidential in-proof | min | yes | 2418 | 24 | 1 | - | 1508 | 1537 | yes |  |
| 16x2 | confidential in-proof | full | yes | 2877 | 33 | 2 | 10 | 1595 | 1582 | yes |  |
| 16x2 | confidential in-proof | full+spl | yes | 3245 | 40 | 2 | - | 1727 | 1586 | yes |  |
| 16x2 | confidential in-proof | full+data | yes | 3079 | 33 | 2 | - | 1797 | 1780 | yes |  |
| 16x2 | confidential in-proof | full+reply | yes | 2877 | 33 | 2 | - | 1595 | 1582 | yes |  |
| 16x2 | confidential in-proof | full+2tree | yes | 2916 | 34 | 2 | - | 1601 | 1586 | yes |  |
| 16x2 | anonymous hidden | min | yes | 2450 | 24 | 1 | - | 1540 | 1599 | yes |  |
| 16x2 | anonymous hidden | full | yes | 2877 | 30 | 2 | 10 | 1691 | 1718 | yes |  |
| 16x2 | anonymous hidden | full+spl | yes | 3245 | 37 | 2 | - | 1823 | 1722 | yes |  |
| 16x2 | anonymous hidden | full+data | yes | 3079 | 30 | 2 | - | 1893 | 1916 | yes |  |
| 16x2 | anonymous hidden | full+reply | yes | 2976 | 30 | 2 | - | 1790 | 1815 | yes |  |
| 16x2 | anonymous hidden | full+2tree | yes | 2916 | 31 | 2 | - | 1697 | 1722 | yes |  |
| 16x2 | anonymous public owners | min | yes | 2387 | 24 | 1 | - | 1476 | 1502 | yes |  |
| 16x2 | anonymous public owners | full | yes | 3006 | 34 | 3 | 10 | 1627 | 1621 | yes |  |
| 16x2 | anonymous public owners | full+spl | yes | 3374 | 41 | 3 | - | 1759 | 1625 | yes |  |
| 16x2 | anonymous public owners | full+data | yes | 3208 | 34 | 3 | - | 1829 | 1819 | yes |  |
| 16x2 | anonymous public owners | full+reply | yes | 3105 | 34 | 3 | - | 1726 | 1718 | yes |  |
| 16x2 | anonymous public owners | full+2tree | yes | 3045 | 35 | 3 | - | 1633 | 1625 | yes |  |
| 16x2 | confidential entry | min | none | - | - | - | - | - | - | no | catalog key |
| 16x2 | confidential entry | full | none | - | - | - | - | - | - | no | catalog key |
| 16x2 | confidential entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 16x2 | confidential entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 16x2 | confidential entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 16x2 | confidential entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 16x2 | anonymous entry | min | none | - | - | - | - | - | - | no | catalog key |
| 16x2 | anonymous entry | full | none | - | - | - | - | - | - | no | catalog key |
| 16x2 | anonymous entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 16x2 | anonymous entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 16x2 | anonymous entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 16x2 | anonymous entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 16x2 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 16x2 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 16x4 | confidential signer | min | yes | 2757 | 24 | 1 | - | 1846 | 1946 | yes |  |
| 16x4 | confidential signer | full | yes | 3312 | 34 | 3 | 9 | 1933 | 1991 | yes |  |
| 16x4 | confidential signer | full+spl | yes | 3680 | 41 | 3 | - | 2065 | 1995 | yes |  |
| 16x4 | confidential signer | full+data | yes | 3716 | 34 | 3 | - | 2337 | 2387 | yes |  |
| 16x4 | confidential signer | full+reply | yes | 3312 | 34 | 3 | - | 1933 | 1991 | yes |  |
| 16x4 | confidential signer | full+2tree | yes | 3351 | 35 | 3 | - | 1939 | 1995 | yes |  |
| 16x4 | confidential in-proof | min | yes | 2852 | 24 | 1 | - | 1942 | 2043 | yes |  |
| 16x4 | confidential in-proof | full | yes | 3311 | 33 | 2 | 8 | 2029 | 2088 | yes |  |
| 16x4 | confidential in-proof | full+spl | yes | 3679 | 40 | 2 | - | 2161 | 2092 | yes |  |
| 16x4 | confidential in-proof | full+data | yes | 3715 | 33 | 2 | - | 2433 | 2484 | yes |  |
| 16x4 | confidential in-proof | full+reply | yes | 3311 | 33 | 2 | - | 2029 | 2088 | yes |  |
| 16x4 | confidential in-proof | full+2tree | yes | 3350 | 34 | 2 | - | 2035 | 2092 | yes |  |
| 16x4 | anonymous hidden | min | yes | 2948 | 24 | 1 | - | 2038 | 2169 | yes |  |
| 16x4 | anonymous hidden | full | yes | 3375 | 30 | 2 | 7 | 2189 | 2288 | yes |  |
| 16x4 | anonymous hidden | full+spl | yes | 3743 | 37 | 2 | - | 2321 | 2292 | yes |  |
| 16x4 | anonymous hidden | full+data | yes | 3779 | 30 | 2 | - | 2593 | 2684 | yes |  |
| 16x4 | anonymous hidden | full+reply | yes | 3668 | 30 | 2 | - | 2482 | 2579 | yes |  |
| 16x4 | anonymous hidden | full+2tree | yes | 3414 | 31 | 2 | - | 2195 | 2292 | yes |  |
| 16x4 | anonymous public owners | min | yes | 2885 | 24 | 1 | - | 1974 | 2072 | yes |  |
| 16x4 | anonymous public owners | full | yes | 3504 | 34 | 3 | 7 | 2125 | 2191 | yes |  |
| 16x4 | anonymous public owners | full+spl | yes | 3872 | 41 | 3 | - | 2257 | 2195 | yes |  |
| 16x4 | anonymous public owners | full+data | yes | 3908 | 34 | 3 | - | 2529 | 2587 | yes |  |
| 16x4 | anonymous public owners | full+reply | yes | 3797 | 34 | 3 | - | 2418 | 2482 | yes |  |
| 16x4 | anonymous public owners | full+2tree | yes | 3543 | 35 | 3 | - | 2131 | 2195 | yes |  |
| 16x4 | confidential entry | min | none | - | - | - | - | - | - | no | catalog key |
| 16x4 | confidential entry | full | none | - | - | - | - | - | - | no | catalog key |
| 16x4 | confidential entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 16x4 | confidential entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 16x4 | confidential entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 16x4 | confidential entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 16x4 | anonymous entry | min | none | - | - | - | - | - | - | no | catalog key |
| 16x4 | anonymous entry | full | none | - | - | - | - | - | - | no | catalog key |
| 16x4 | anonymous entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 16x4 | anonymous entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 16x4 | anonymous entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 16x4 | anonymous entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 16x4 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 16x4 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 16x8 | confidential signer | min | yes | 3625 | 24 | 1 | - | 2714 | 2958 | yes |  |
| 16x8 | confidential signer | full | yes | 4180 | 34 | 3 | none | 2801 | 3003 | no | 84 B |
| 16x8 | confidential signer | full+spl | yes | 4548 | 41 | 3 | - | 2933 | 3007 | no | 452 B |
| 16x8 | confidential signer | full+data | yes | 4988 | 34 | 3 | - | 3609 | 3795 | no | 892 B |
| 16x8 | confidential signer | full+reply | yes | 4180 | 34 | 3 | - | 2801 | 3003 | no | 84 B |
| 16x8 | confidential signer | full+2tree | yes | 4219 | 35 | 3 | - | 2807 | 3007 | no | 123 B |
| 16x8 | confidential in-proof | min | yes | 3720 | 24 | 1 | - | 2810 | 3055 | yes |  |
| 16x8 | confidential in-proof | full | yes | 4179 | 33 | 2 | none | 2897 | 3100 | no | 83 B |
| 16x8 | confidential in-proof | full+spl | yes | 4547 | 40 | 2 | - | 3029 | 3104 | no | 451 B |
| 16x8 | confidential in-proof | full+data | yes | 4987 | 33 | 2 | - | 3705 | 3892 | no | 891 B |
| 16x8 | confidential in-proof | full+reply | yes | 4179 | 33 | 2 | - | 2897 | 3100 | no | 83 B |
| 16x8 | confidential in-proof | full+2tree | yes | 4218 | 34 | 2 | - | 2903 | 3104 | no | 122 B |
| 16x8 | anonymous hidden | min | yes | 3944 | 24 | 1 | - | 3034 | 3309 | yes |  |
| 16x8 | anonymous hidden | full | yes | 4371 | 30 | 2 | none | 3185 | 3428 | no | 275 B |
| 16x8 | anonymous hidden | full+spl | yes | 4739 | 37 | 2 | - | 3317 | 3432 | no | 643 B |
| 16x8 | anonymous hidden | full+data | yes | 5179 | 30 | 2 | - | 3993 | 4220 | no | 1083 B |
| 16x8 | anonymous hidden | full+reply | yes | 5052 | 30 | 2 | - | 3866 | 4107 | no | 956 B |
| 16x8 | anonymous hidden | full+2tree | yes | 4410 | 31 | 2 | - | 3191 | 3432 | no | 314 B |
| 16x8 | anonymous public owners | min | yes | 3881 | 24 | 1 | - | 2970 | 3212 | yes |  |
| 16x8 | anonymous public owners | full | yes | 4500 | 34 | 3 | none | 3121 | 3331 | no | 404 B |
| 16x8 | anonymous public owners | full+spl | yes | 4868 | 41 | 3 | - | 3253 | 3335 | no | 772 B |
| 16x8 | anonymous public owners | full+data | yes | 5308 | 34 | 3 | - | 3929 | 4123 | no | 1212 B |
| 16x8 | anonymous public owners | full+reply | yes | 5181 | 34 | 3 | - | 3802 | 4010 | no | 1085 B |
| 16x8 | anonymous public owners | full+2tree | yes | 4539 | 35 | 3 | - | 3127 | 3335 | no | 443 B |
| 16x8 | confidential entry | min | none | - | - | - | - | - | - | no | catalog key |
| 16x8 | confidential entry | full | none | - | - | - | - | - | - | no | catalog key |
| 16x8 | confidential entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 16x8 | confidential entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 16x8 | confidential entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 16x8 | confidential entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 16x8 | anonymous entry | min | none | - | - | - | - | - | - | no | catalog key |
| 16x8 | anonymous entry | full | none | - | - | - | - | - | - | no | catalog key |
| 16x8 | anonymous entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 16x8 | anonymous entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 16x8 | anonymous entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 16x8 | anonymous entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 16x8 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 16x8 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 24x2 | confidential signer | min | yes | 2843 | 32 | 1 | - | 1668 | 1704 | yes |  |
| 24x2 | confidential signer | full | yes | 3398 | 42 | 3 | 8 | 1755 | 1749 | yes |  |
| 24x2 | confidential signer | full+spl | yes | 3766 | 49 | 3 | - | 1887 | 1753 | yes |  |
| 24x2 | confidential signer | full+data | yes | 3600 | 42 | 3 | - | 1957 | 1947 | yes |  |
| 24x2 | confidential signer | full+reply | yes | 3398 | 42 | 3 | - | 1755 | 1749 | yes |  |
| 24x2 | confidential signer | full+2tree | yes | 3438 | 43 | 3 | - | 1762 | 1753 | yes |  |
| 24x2 | confidential in-proof | min | yes | 2938 | 32 | 1 | - | 1764 | 1801 | yes |  |
| 24x2 | confidential in-proof | full | yes | 3397 | 41 | 2 | 7 | 1851 | 1846 | yes |  |
| 24x2 | confidential in-proof | full+spl | yes | 3765 | 48 | 2 | - | 1983 | 1850 | yes |  |
| 24x2 | confidential in-proof | full+data | yes | 3599 | 41 | 2 | - | 2053 | 2044 | yes |  |
| 24x2 | confidential in-proof | full+reply | yes | 3397 | 41 | 2 | - | 1851 | 1846 | yes |  |
| 24x2 | confidential in-proof | full+2tree | yes | 3437 | 42 | 2 | - | 1858 | 1850 | yes |  |
| 24x2 | anonymous hidden | min | yes | 2970 | 32 | 1 | - | 1796 | 1863 | yes |  |
| 24x2 | anonymous hidden | full | yes | 3397 | 38 | 2 | 7 | 1947 | 1982 | yes |  |
| 24x2 | anonymous hidden | full+spl | yes | 3765 | 45 | 2 | - | 2079 | 1986 | yes |  |
| 24x2 | anonymous hidden | full+data | yes | 3599 | 38 | 2 | - | 2149 | 2180 | yes |  |
| 24x2 | anonymous hidden | full+reply | yes | 3496 | 38 | 2 | - | 2046 | 2079 | yes |  |
| 24x2 | anonymous hidden | full+2tree | yes | 3437 | 39 | 2 | - | 1954 | 1986 | yes |  |
| 24x2 | anonymous public owners | min | yes | 2907 | 32 | 1 | - | 1732 | 1766 | yes |  |
| 24x2 | anonymous public owners | full | yes | 3526 | 42 | 3 | 6 | 1883 | 1885 | yes |  |
| 24x2 | anonymous public owners | full+spl | yes | 3894 | 49 | 3 | - | 2015 | 1889 | yes |  |
| 24x2 | anonymous public owners | full+data | yes | 3728 | 42 | 3 | - | 2085 | 2083 | yes |  |
| 24x2 | anonymous public owners | full+reply | yes | 3625 | 42 | 3 | - | 1982 | 1982 | yes |  |
| 24x2 | anonymous public owners | full+2tree | yes | 3566 | 43 | 3 | - | 1890 | 1889 | yes |  |
| 24x2 | confidential entry | min | none | - | - | - | - | - | - | no | catalog key |
| 24x2 | confidential entry | full | none | - | - | - | - | - | - | no | catalog key |
| 24x2 | confidential entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 24x2 | confidential entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 24x2 | confidential entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 24x2 | confidential entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 24x2 | anonymous entry | min | none | - | - | - | - | - | - | no | catalog key |
| 24x2 | anonymous entry | full | none | - | - | - | - | - | - | no | catalog key |
| 24x2 | anonymous entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 24x2 | anonymous entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 24x2 | anonymous entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 24x2 | anonymous entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 24x2 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 24x2 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 24x4 | confidential signer | min | yes | 3277 | 32 | 1 | - | 2102 | 2210 | yes |  |
| 24x4 | confidential signer | full | yes | 3832 | 42 | 3 | 3 | 2189 | 2255 | yes |  |
| 24x4 | confidential signer | full+spl | yes | 4200 | 49 | 3 | - | 2321 | 2259 | no | 104 B |
| 24x4 | confidential signer | full+data | yes | 4236 | 42 | 3 | - | 2593 | 2651 | no | 140 B |
| 24x4 | confidential signer | full+reply | yes | 3832 | 42 | 3 | - | 2189 | 2255 | yes |  |
| 24x4 | confidential signer | full+2tree | yes | 3872 | 43 | 3 | - | 2196 | 2259 | yes |  |
| 24x4 | confidential in-proof | min | yes | 3372 | 32 | 1 | - | 2198 | 2307 | yes |  |
| 24x4 | confidential in-proof | full | yes | 3831 | 41 | 2 | 2 | 2285 | 2352 | yes |  |
| 24x4 | confidential in-proof | full+spl | yes | 4199 | 48 | 2 | - | 2417 | 2356 | no | 103 B |
| 24x4 | confidential in-proof | full+data | yes | 4235 | 41 | 2 | - | 2689 | 2748 | no | 139 B |
| 24x4 | confidential in-proof | full+reply | yes | 3831 | 41 | 2 | - | 2285 | 2352 | yes |  |
| 24x4 | confidential in-proof | full+2tree | yes | 3871 | 42 | 2 | - | 2292 | 2356 | yes |  |
| 24x4 | anonymous hidden | min | yes | 3468 | 32 | 1 | - | 2294 | 2433 | yes |  |
| 24x4 | anonymous hidden | full | yes | 3895 | 38 | 2 | 2 | 2445 | 2552 | yes |  |
| 24x4 | anonymous hidden | full+spl | yes | 4263 | 45 | 2 | - | 2577 | 2556 | no | 167 B |
| 24x4 | anonymous hidden | full+data | yes | 4299 | 38 | 2 | - | 2849 | 2948 | no | 203 B |
| 24x4 | anonymous hidden | full+reply | yes | 4188 | 38 | 2 | - | 2738 | 2843 | no | 92 B |
| 24x4 | anonymous hidden | full+2tree | yes | 3935 | 39 | 2 | - | 2452 | 2556 | yes |  |
| 24x4 | anonymous public owners | min | yes | 3405 | 32 | 1 | - | 2230 | 2336 | yes |  |
| 24x4 | anonymous public owners | full | yes | 4024 | 42 | 3 | 1 | 2381 | 2455 | yes |  |
| 24x4 | anonymous public owners | full+spl | yes | 4392 | 49 | 3 | - | 2513 | 2459 | no | 296 B |
| 24x4 | anonymous public owners | full+data | yes | 4428 | 42 | 3 | - | 2785 | 2851 | no | 332 B |
| 24x4 | anonymous public owners | full+reply | yes | 4317 | 42 | 3 | - | 2674 | 2746 | no | 221 B |
| 24x4 | anonymous public owners | full+2tree | yes | 4064 | 43 | 3 | - | 2388 | 2459 | yes |  |
| 24x4 | confidential entry | min | none | - | - | - | - | - | - | no | catalog key |
| 24x4 | confidential entry | full | none | - | - | - | - | - | - | no | catalog key |
| 24x4 | confidential entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 24x4 | confidential entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 24x4 | confidential entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 24x4 | confidential entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 24x4 | anonymous entry | min | none | - | - | - | - | - | - | no | catalog key |
| 24x4 | anonymous entry | full | none | - | - | - | - | - | - | no | catalog key |
| 24x4 | anonymous entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 24x4 | anonymous entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 24x4 | anonymous entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 24x4 | anonymous entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 24x4 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 24x4 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 32x2 | confidential signer | min | yes | 3363 | 40 | 1 | - | 1924 | 1968 | yes |  |
| 32x2 | confidential signer | full | yes | 3918 | 50 | 3 | 2 | 2011 | 2013 | yes |  |
| 32x2 | confidential signer | full+spl | yes | 4286 | 57 | 3 | - | 2143 | 2017 | no | 190 B |
| 32x2 | confidential signer | full+data | yes | 4120 | 50 | 3 | - | 2213 | 2211 | no | 24 B |
| 32x2 | confidential signer | full+reply | yes | 3918 | 50 | 3 | - | 2011 | 2013 | yes |  |
| 32x2 | confidential signer | full+2tree | yes | 3959 | 51 | 3 | - | 2019 | 2017 | yes |  |
| 32x2 | confidential in-proof | min | yes | 3458 | 40 | 1 | - | 2020 | 2065 | yes |  |
| 32x2 | confidential in-proof | full | yes | 3917 | 49 | 2 | 1 | 2107 | 2110 | yes |  |
| 32x2 | confidential in-proof | full+spl | yes | 4285 | 56 | 2 | - | 2239 | 2114 | no | 189 B |
| 32x2 | confidential in-proof | full+data | yes | 4119 | 49 | 2 | - | 2309 | 2308 | no | 23 B |
| 32x2 | confidential in-proof | full+reply | yes | 3917 | 49 | 2 | - | 2107 | 2110 | yes |  |
| 32x2 | confidential in-proof | full+2tree | yes | 3958 | 50 | 2 | - | 2115 | 2114 | yes |  |
| 32x2 | anonymous hidden | min | yes | 3490 | 40 | 1 | - | 2052 | 2127 | yes |  |
| 32x2 | anonymous hidden | full | yes | 3917 | 46 | 2 | 1 | 2203 | 2246 | yes |  |
| 32x2 | anonymous hidden | full+spl | yes | 4285 | 53 | 2 | - | 2335 | 2250 | no | 189 B |
| 32x2 | anonymous hidden | full+data | yes | 4119 | 46 | 2 | - | 2405 | 2444 | no | 23 B |
| 32x2 | anonymous hidden | full+reply | yes | 4016 | 46 | 2 | - | 2302 | 2343 | yes |  |
| 32x2 | anonymous hidden | full+2tree | yes | 3958 | 47 | 2 | - | 2211 | 2250 | yes |  |
| 32x2 | anonymous public owners | min | yes | 3427 | 40 | 1 | - | 1988 | 2030 | yes |  |
| 32x2 | anonymous public owners | full | yes | 4046 | 50 | 3 | 1 | 2139 | 2149 | yes |  |
| 32x2 | anonymous public owners | full+spl | yes | 4414 | 57 | 3 | - | 2271 | 2153 | no | 318 B |
| 32x2 | anonymous public owners | full+data | yes | 4248 | 50 | 3 | - | 2341 | 2347 | no | 152 B |
| 32x2 | anonymous public owners | full+reply | yes | 4145 | 50 | 3 | - | 2238 | 2246 | no | 49 B |
| 32x2 | anonymous public owners | full+2tree | yes | 4087 | 51 | 3 | - | 2147 | 2153 | yes |  |
| 32x2 | confidential entry | min | none | - | - | - | - | - | - | no | catalog key |
| 32x2 | confidential entry | full | none | - | - | - | - | - | - | no | catalog key |
| 32x2 | confidential entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 32x2 | confidential entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 32x2 | confidential entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 32x2 | confidential entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 32x2 | anonymous entry | min | none | - | - | - | - | - | - | no | catalog key |
| 32x2 | anonymous entry | full | none | - | - | - | - | - | - | no | catalog key |
| 32x2 | anonymous entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 32x2 | anonymous entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 32x2 | anonymous entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 32x2 | anonymous entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 32x2 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 32x2 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 40x2 | confidential signer | min | yes | 3883 | 48 | 1 | - | 2180 | 2232 | yes |  |
| 40x2 | confidential signer | full | yes | 4438 | 58 | 3 | none | 2267 | 2277 | no | 342 B |
| 40x2 | confidential signer | full+spl | yes | 4806 | 65 | 3 | - | 2399 | 2281 | no | 710 B, 1 accounts |
| 40x2 | confidential signer | full+data | yes | 4640 | 58 | 3 | - | 2469 | 2475 | no | 544 B |
| 40x2 | confidential signer | full+reply | yes | 4438 | 58 | 3 | - | 2267 | 2277 | no | 342 B |
| 40x2 | confidential signer | full+2tree | yes | 4480 | 59 | 3 | - | 2276 | 2281 | no | 384 B |
| 40x2 | confidential in-proof | min | yes | 3978 | 48 | 1 | - | 2276 | 2329 | yes |  |
| 40x2 | confidential in-proof | full | yes | 4437 | 57 | 2 | none | 2363 | 2374 | no | 341 B |
| 40x2 | confidential in-proof | full+spl | yes | 4805 | 64 | 2 | - | 2495 | 2378 | no | 709 B |
| 40x2 | confidential in-proof | full+data | yes | 4639 | 57 | 2 | - | 2565 | 2572 | no | 543 B |
| 40x2 | confidential in-proof | full+reply | yes | 4437 | 57 | 2 | - | 2363 | 2374 | no | 341 B |
| 40x2 | confidential in-proof | full+2tree | yes | 4479 | 58 | 2 | - | 2372 | 2378 | no | 383 B |
| 40x2 | anonymous hidden | min | yes | 4010 | 48 | 1 | - | 2308 | 2391 | yes |  |
| 40x2 | anonymous hidden | full | yes | 4437 | 54 | 2 | none | 2459 | 2510 | no | 341 B |
| 40x2 | anonymous hidden | full+spl | yes | 4805 | 61 | 2 | - | 2591 | 2514 | no | 709 B |
| 40x2 | anonymous hidden | full+data | yes | 4639 | 54 | 2 | - | 2661 | 2708 | no | 543 B |
| 40x2 | anonymous hidden | full+reply | yes | 4536 | 54 | 2 | - | 2558 | 2607 | no | 440 B |
| 40x2 | anonymous hidden | full+2tree | yes | 4479 | 55 | 2 | - | 2468 | 2514 | no | 383 B |
| 40x2 | anonymous public owners | min | yes | 3947 | 48 | 1 | - | 2244 | 2294 | yes |  |
| 40x2 | anonymous public owners | full | yes | 4566 | 58 | 3 | none | 2395 | 2413 | no | 470 B |
| 40x2 | anonymous public owners | full+spl | yes | 4934 | 65 | 3 | - | 2527 | 2417 | no | 838 B, 1 accounts |
| 40x2 | anonymous public owners | full+data | yes | 4768 | 58 | 3 | - | 2597 | 2611 | no | 672 B |
| 40x2 | anonymous public owners | full+reply | yes | 4665 | 58 | 3 | - | 2494 | 2510 | no | 569 B |
| 40x2 | anonymous public owners | full+2tree | yes | 4608 | 59 | 3 | - | 2404 | 2417 | no | 512 B |
| 40x2 | confidential entry | min | none | - | - | - | - | - | - | no | catalog key |
| 40x2 | confidential entry | full | none | - | - | - | - | - | - | no | catalog key |
| 40x2 | confidential entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 40x2 | confidential entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 40x2 | confidential entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 40x2 | confidential entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 40x2 | anonymous entry | min | none | - | - | - | - | - | - | no | catalog key |
| 40x2 | anonymous entry | full | none | - | - | - | - | - | - | no | catalog key |
| 40x2 | anonymous entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 40x2 | anonymous entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 40x2 | anonymous entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 40x2 | anonymous entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 40x2 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 40x2 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 48x2 | confidential signer | min | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | confidential signer | full | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | confidential signer | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | confidential signer | full+data | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | confidential signer | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | confidential signer | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | confidential in-proof | min | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | confidential in-proof | full | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | confidential in-proof | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | confidential in-proof | full+data | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | confidential in-proof | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | confidential in-proof | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | anonymous hidden | min | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | anonymous hidden | full | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | anonymous hidden | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | anonymous hidden | full+data | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | anonymous hidden | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | anonymous hidden | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | anonymous public owners | min | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | anonymous public owners | full | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | anonymous public owners | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | anonymous public owners | full+data | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | anonymous public owners | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | anonymous public owners | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | confidential entry | min | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | confidential entry | full | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | confidential entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | confidential entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | confidential entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | confidential entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | anonymous entry | min | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | anonymous entry | full | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | anonymous entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | anonymous entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | anonymous entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | anonymous entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 48x2 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 48x2 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 49x2 | confidential signer | min | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | confidential signer | full | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | confidential signer | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | confidential signer | full+data | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | confidential signer | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | confidential signer | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | confidential in-proof | min | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | confidential in-proof | full | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | confidential in-proof | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | confidential in-proof | full+data | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | confidential in-proof | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | confidential in-proof | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | anonymous hidden | min | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | anonymous hidden | full | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | anonymous hidden | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | anonymous hidden | full+data | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | anonymous hidden | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | anonymous hidden | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | anonymous public owners | min | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | anonymous public owners | full | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | anonymous public owners | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | anonymous public owners | full+data | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | anonymous public owners | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | anonymous public owners | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | confidential entry | min | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | confidential entry | full | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | confidential entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | confidential entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | confidential entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | confidential entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | anonymous entry | min | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | anonymous entry | full | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | anonymous entry | full+spl | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | anonymous entry | full+data | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | anonymous entry | full+reply | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | anonymous entry | full+2tree | none | - | - | - | - | - | - | no | catalog key |
| 49x2 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 49x2 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 8x1 | merge | ring | yes | 1640 | 16 | 1 | - | - | - | yes |  |
| 8x1 | merge | owner signed | yes | 1737 | 17 | 2 | - | - | - | yes |  |
| 24x1 | merge | ring | yes | 2680 | 32 | 1 | - | - | - | yes |  |
| 24x1 | merge | owner signed | yes | 2777 | 33 | 2 | - | - | - | yes |  |
| 52x1 | merge | ring | yes | 4500 | 60 | 1 | - | - | - | no | 404 B |
| 52x1 | merge | owner signed | yes | 4597 | 61 | 2 | - | - | - | no | 501 B |

Entry capacities at two outputs. Each row is the widest owner run one transaction clears at that leg count, rows = run + a hidden sender. A confidential leg names its own destination, a hidden sender's legs name one. over: what stops the next owner.
| shape | rail | load | legs | leg kind | owner run | rows | accounts | signatures | frame | SPP CPI | fits | over |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 12x2 | confidential entry | min | 0 | sol | none | - | - | - | - | - | no | catalog key |
| 12x2 | confidential entry | full | 0 | sol | none | - | - | - | - | - | no | catalog key |
| 12x2 | confidential entry | full+data+reply | 0 | sol | none | - | - | - | - | - | no | catalog key |
| 12x2 | confidential entry | min | 0 | spl | none | - | - | - | - | - | no | catalog key |
| 12x2 | confidential entry | full | 0 | spl | none | - | - | - | - | - | no | catalog key |
| 12x2 | confidential entry | full+data+reply | 0 | spl | none | - | - | - | - | - | no | catalog key |
| 12x2 | anonymous entry | min | 0 | sol | none | - | - | - | - | - | no | catalog key |
| 12x2 | anonymous entry | full | 0 | sol | none | - | - | - | - | - | no | catalog key |
| 12x2 | anonymous entry | full+data+reply | 0 | sol | none | - | - | - | - | - | no | catalog key |
| 12x2 | anonymous entry | min | 0 | spl | none | - | - | - | - | - | no | catalog key |
| 12x2 | anonymous entry | full | 0 | spl | none | - | - | - | - | - | no | catalog key |
| 12x2 | anonymous entry | full+data+reply | 0 | spl | none | - | - | - | - | - | no | catalog key |
| 16x2 | confidential entry | min | 0 | sol | none | - | - | - | - | - | no | catalog key |
| 16x2 | confidential entry | full | 0 | sol | none | - | - | - | - | - | no | catalog key |
| 16x2 | confidential entry | full+data+reply | 0 | sol | none | - | - | - | - | - | no | catalog key |
| 16x2 | confidential entry | min | 0 | spl | none | - | - | - | - | - | no | catalog key |
| 16x2 | confidential entry | full | 0 | spl | none | - | - | - | - | - | no | catalog key |
| 16x2 | confidential entry | full+data+reply | 0 | spl | none | - | - | - | - | - | no | catalog key |
| 16x2 | anonymous entry | min | 0 | sol | none | - | - | - | - | - | no | catalog key |
| 16x2 | anonymous entry | full | 0 | sol | none | - | - | - | - | - | no | catalog key |
| 16x2 | anonymous entry | full+data+reply | 0 | sol | none | - | - | - | - | - | no | catalog key |
| 16x2 | anonymous entry | min | 0 | spl | none | - | - | - | - | - | no | catalog key |
| 16x2 | anonymous entry | full | 0 | spl | none | - | - | - | - | - | no | catalog key |
| 16x2 | anonymous entry | full+data+reply | 0 | spl | none | - | - | - | - | - | no | catalog key |
| 24x2 | confidential entry | min | 0 | sol | none | - | - | - | - | - | no | catalog key |
| 24x2 | confidential entry | full | 0 | sol | none | - | - | - | - | - | no | catalog key |
| 24x2 | confidential entry | full+data+reply | 0 | sol | none | - | - | - | - | - | no | catalog key |
| 24x2 | confidential entry | min | 0 | spl | none | - | - | - | - | - | no | catalog key |
| 24x2 | confidential entry | full | 0 | spl | none | - | - | - | - | - | no | catalog key |
| 24x2 | confidential entry | full+data+reply | 0 | spl | none | - | - | - | - | - | no | catalog key |
| 24x2 | anonymous entry | min | 0 | sol | none | - | - | - | - | - | no | catalog key |
| 24x2 | anonymous entry | full | 0 | sol | none | - | - | - | - | - | no | catalog key |
| 24x2 | anonymous entry | full+data+reply | 0 | sol | none | - | - | - | - | - | no | catalog key |
| 24x2 | anonymous entry | min | 0 | spl | none | - | - | - | - | - | no | catalog key |
| 24x2 | anonymous entry | full | 0 | spl | none | - | - | - | - | - | no | catalog key |
| 24x2 | anonymous entry | full+data+reply | 0 | spl | none | - | - | - | - | - | no | catalog key |

Maxima. Load max is full with data tails, every extension but the cache, two SPP input trees, replies on anonymous frames. Each row widens one axis from that load to the largest value one transaction clears. reply: the reply length. messages: empty application messages. message bytes: one application message. over: what refuses one more step. Heap is not measured here.
| shape | rail | axis | widest | frame | SPP CPI | bytes | accounts | signatures | over |
|---|---|---|---|---|---|---|---|---|---|
| 1x2 | confidential signer | messages | 54 | 3168 | 3092 | 4085 | 20 | 3 | 23 B |
| 1x2 | confidential signer | message bytes | 1813 | 3179 | 3103 | 4096 | 20 | 3 | 1 B |
| 1x2 | confidential in-proof | messages | 54 | 3264 | 3189 | 4084 | 19 | 2 | 22 B |
| 1x2 | confidential in-proof | message bytes | 1814 | 3276 | 3201 | 4096 | 19 | 2 | 1 B |
| 1x2 | anonymous hidden | reply | 1847 | 3372 | 3336 | 4096 | 16 | 2 | 1 B |
| 1x2 | anonymous hidden | messages | 51 | 3357 | 3320 | 4081 | 16 | 2 | 19 B |
| 1x2 | anonymous hidden | message bytes | 1715 | 3372 | 3335 | 4096 | 16 | 2 | 1 B |
| 1x2 | anonymous public owners | reply | 1718 | 3179 | 3110 | 4096 | 20 | 3 | 1 B |
| 1x2 | anonymous public owners | messages | 47 | 3157 | 3087 | 4074 | 20 | 3 | 12 B |
| 1x2 | anonymous public owners | message bytes | 1586 | 3179 | 3109 | 4096 | 20 | 3 | 1 B |
| 1x2 | confidential entry | messages | 48 | 3172 | 3096 | 4089 | 20 | 3 | 27 B |
| 1x2 | confidential entry | message bytes | 1605 | 3179 | 3103 | 4096 | 20 | 3 | 1 B |
| 1x2 | anonymous entry | reply | 1607 | 3372 | 3304 | 4096 | 16 | 2 | 1 B |
| 1x2 | anonymous entry | messages | 44 | 3359 | 3290 | 4083 | 16 | 2 | 21 B |
| 1x2 | anonymous entry | message bytes | 1475 | 3372 | 3303 | 4096 | 16 | 2 | 1 B |
| 1x4 | confidential signer | messages | 35 | 3158 | 3150 | 4075 | 20 | 3 | 13 B |
| 1x4 | confidential signer | message bytes | 1177 | 3179 | 3171 | 4096 | 20 | 3 | 1 B |
| 1x4 | confidential in-proof | messages | 35 | 3254 | 3247 | 4074 | 19 | 2 | 12 B |
| 1x4 | confidential in-proof | message bytes | 1178 | 3276 | 3269 | 4096 | 19 | 2 | 1 B |
| 1x4 | anonymous hidden | reply | 382 | 3371 | 3403 | 4095 | 16 | 2 | 2 B |
| 1x4 | anonymous hidden | messages | 25 | 3367 | 3398 | 4091 | 16 | 2 | 29 B |
| 1x4 | anonymous hidden | message bytes | 821 | 3372 | 3403 | 4096 | 16 | 2 | 1 B |
| 1x4 | anonymous public owners | reply | 339 | 3178 | 3177 | 4095 | 20 | 3 | 2 B |
| 1x4 | anonymous public owners | messages | 21 | 3167 | 3165 | 4084 | 20 | 3 | 22 B |
| 1x4 | anonymous public owners | message bytes | 692 | 3179 | 3177 | 4096 | 20 | 3 | 1 B |
| 1x4 | confidential entry | messages | 29 | 3162 | 3154 | 4079 | 20 | 3 | 17 B |
| 1x4 | confidential entry | message bytes | 969 | 3179 | 3171 | 4096 | 20 | 3 | 1 B |
| 1x4 | anonymous entry | reply | 302 | 3371 | 3371 | 4095 | 16 | 2 | 2 B |
| 1x4 | anonymous entry | messages | 18 | 3369 | 3368 | 4093 | 16 | 2 | 31 B |
| 1x4 | anonymous entry | message bytes | 581 | 3372 | 3371 | 4096 | 16 | 2 | 1 B |
| 1x8 | confidential signer | messages | none | - | - | - | - | - | 60 B |
| 1x8 | confidential signer | message bytes | none | - | - | - | - | - | 95 B |
| 1x8 | confidential in-proof | messages | none | - | - | - | - | - | 59 B |
| 1x8 | confidential in-proof | message bytes | none | - | - | - | - | - | 94 B |
| 1x8 | anonymous hidden | reply | none | - | - | - | - | - | 932 B |
| 1x8 | anonymous hidden | messages | none | - | - | - | - | - | 932 B |
| 1x8 | anonymous hidden | message bytes | none | - | - | - | - | - | 967 B |
| 1x8 | anonymous public owners | reply | none | - | - | - | - | - | 1061 B |
| 1x8 | anonymous public owners | messages | none | - | - | - | - | - | 1061 B |
| 1x8 | anonymous public owners | message bytes | none | - | - | - | - | - | 1096 B |
| 1x8 | confidential entry | messages | none | - | - | - | - | - | 268 B |
| 1x8 | confidential entry | message bytes | none | - | - | - | - | - | 303 B |
| 1x8 | anonymous entry | reply | none | - | - | - | - | - | 1172 B |
| 1x8 | anonymous entry | messages | none | - | - | - | - | - | 1172 B |
| 1x8 | anonymous entry | message bytes | none | - | - | - | - | - | 1207 B |
| 2x2 | confidential signer | messages | 52 | 3132 | 3057 | 4082 | 21 | 3 | 20 B |
| 2x2 | confidential signer | message bytes | 1748 | 3146 | 3071 | 4096 | 21 | 3 | 1 B |
| 2x2 | confidential in-proof | messages | 52 | 3228 | 3154 | 4081 | 20 | 2 | 19 B |
| 2x2 | confidential in-proof | message bytes | 1749 | 3243 | 3169 | 4096 | 20 | 2 | 1 B |
| 2x2 | anonymous hidden | reply | 1782 | 3339 | 3304 | 4096 | 17 | 2 | 1 B |
| 2x2 | anonymous hidden | messages | 49 | 3321 | 3285 | 4078 | 17 | 2 | 16 B |
| 2x2 | anonymous hidden | message bytes | 1650 | 3339 | 3303 | 4096 | 17 | 2 | 1 B |
| 2x2 | anonymous public owners | reply | 1653 | 3146 | 3078 | 4096 | 21 | 3 | 1 B |
| 2x2 | anonymous public owners | messages | 45 | 3121 | 3052 | 4071 | 21 | 3 | 9 B |
| 2x2 | anonymous public owners | message bytes | 1521 | 3146 | 3077 | 4096 | 21 | 3 | 1 B |
| 2x2 | confidential entry | messages | 40 | 3132 | 3057 | 4082 | 21 | 3 | 20 B |
| 2x2 | confidential entry | message bytes | 1340 | 3146 | 3071 | 4096 | 21 | 3 | 1 B |
| 2x2 | anonymous entry | reply | 1342 | 3339 | 3272 | 4096 | 17 | 2 | 1 B |
| 2x2 | anonymous entry | messages | 36 | 3319 | 3251 | 4076 | 17 | 2 | 14 B |
| 2x2 | anonymous entry | message bytes | 1210 | 3339 | 3271 | 4096 | 17 | 2 | 1 B |
| 2x2 | delegate | messages | 59 | 3314 | 3295 | 4068 | 17 | 2 | 6 B |
| 2x2 | delegate | message bytes | 2000 | 3342 | 3323 | 4096 | 17 | 2 | 1 B |
| 2x2 | anonymous delegate | reply | 1905 | 3342 | 3330 | 4096 | 17 | 2 | 1 B |
| 2x2 | anonymous delegate | messages | 53 | 3337 | 3324 | 4091 | 17 | 2 | 29 B |
| 2x2 | anonymous delegate | message bytes | 1773 | 3342 | 3329 | 4096 | 17 | 2 | 1 B |
| 2x4 | confidential signer | messages | 33 | 3122 | 3115 | 4072 | 21 | 3 | 10 B |
| 2x4 | confidential signer | message bytes | 1112 | 3146 | 3139 | 4096 | 21 | 3 | 1 B |
| 2x4 | confidential in-proof | messages | 33 | 3218 | 3212 | 4071 | 20 | 2 | 9 B |
| 2x4 | confidential in-proof | message bytes | 1113 | 3243 | 3237 | 4096 | 20 | 2 | 1 B |
| 2x4 | anonymous hidden | reply | 360 | 3337 | 3370 | 4094 | 17 | 2 | 1 B |
| 2x4 | anonymous hidden | messages | 23 | 3331 | 3363 | 4088 | 17 | 2 | 26 B |
| 2x4 | anonymous hidden | message bytes | 756 | 3339 | 3371 | 4096 | 17 | 2 | 1 B |
| 2x4 | anonymous public owners | reply | 317 | 3144 | 3144 | 4094 | 21 | 3 | 1 B |
| 2x4 | anonymous public owners | messages | 19 | 3131 | 3130 | 4081 | 21 | 3 | 19 B |
| 2x4 | anonymous public owners | message bytes | 627 | 3146 | 3145 | 4096 | 21 | 3 | 1 B |
| 2x4 | confidential entry | messages | 21 | 3122 | 3115 | 4072 | 21 | 3 | 10 B |
| 2x4 | confidential entry | message bytes | 704 | 3146 | 3139 | 4096 | 21 | 3 | 1 B |
| 2x4 | anonymous entry | reply | 214 | 3339 | 3340 | 4096 | 17 | 2 | 3 B |
| 2x4 | anonymous entry | messages | 10 | 3329 | 3329 | 4086 | 17 | 2 | 24 B |
| 2x4 | anonymous entry | message bytes | 316 | 3339 | 3339 | 4096 | 17 | 2 | 1 B |
| 2x8 | confidential signer | messages | none | - | - | - | - | - | 125 B |
| 2x8 | confidential signer | message bytes | none | - | - | - | - | - | 160 B |
| 2x8 | confidential in-proof | messages | none | - | - | - | - | - | 124 B |
| 2x8 | confidential in-proof | message bytes | none | - | - | - | - | - | 159 B |
| 2x8 | anonymous hidden | reply | none | - | - | - | - | - | 997 B |
| 2x8 | anonymous hidden | messages | none | - | - | - | - | - | 997 B |
| 2x8 | anonymous hidden | message bytes | none | - | - | - | - | - | 1032 B |
| 2x8 | anonymous public owners | reply | none | - | - | - | - | - | 1126 B |
| 2x8 | anonymous public owners | messages | none | - | - | - | - | - | 1126 B |
| 2x8 | anonymous public owners | message bytes | none | - | - | - | - | - | 1161 B |
| 2x8 | confidential entry | messages | none | - | - | - | - | - | 533 B |
| 2x8 | confidential entry | message bytes | none | - | - | - | - | - | 568 B |
| 2x8 | anonymous entry | reply | none | - | - | - | - | - | 1437 B |
| 2x8 | anonymous entry | messages | none | - | - | - | - | - | 1437 B |
| 2x8 | anonymous entry | message bytes | none | - | - | - | - | - | 1472 B |
| 3x2 | confidential signer | messages | 50 | 3096 | 3022 | 4079 | 22 | 3 | 17 B |
| 3x2 | confidential signer | message bytes | 1683 | 3113 | 3039 | 4096 | 22 | 3 | 1 B |
| 3x2 | confidential in-proof | messages | 50 | 3192 | 3119 | 4078 | 21 | 2 | 16 B |
| 3x2 | confidential in-proof | message bytes | 1684 | 3210 | 3137 | 4096 | 21 | 2 | 1 B |
| 3x2 | anonymous hidden | reply | 1717 | 3306 | 3272 | 4096 | 18 | 2 | 1 B |
| 3x2 | anonymous hidden | messages | 47 | 3285 | 3250 | 4075 | 18 | 2 | 13 B |
| 3x2 | anonymous hidden | message bytes | 1585 | 3306 | 3271 | 4096 | 18 | 2 | 1 B |
| 3x2 | anonymous public owners | reply | 1588 | 3113 | 3046 | 4096 | 22 | 3 | 1 B |
| 3x2 | anonymous public owners | messages | 43 | 3085 | 3017 | 4068 | 22 | 3 | 6 B |
| 3x2 | anonymous public owners | message bytes | 1456 | 3113 | 3045 | 4096 | 22 | 3 | 1 B |
| 3x2 | confidential entry | messages | 32 | 3092 | 3018 | 4075 | 22 | 3 | 13 B |
| 3x2 | confidential entry | message bytes | 1075 | 3113 | 3039 | 4096 | 22 | 3 | 1 B |
| 3x2 | anonymous entry | reply | 1077 | 3306 | 3240 | 4096 | 18 | 2 | 1 B |
| 3x2 | anonymous entry | messages | 28 | 3279 | 3212 | 4069 | 18 | 2 | 7 B |
| 3x2 | anonymous entry | message bytes | 945 | 3306 | 3239 | 4096 | 18 | 2 | 1 B |
| 3x4 | confidential signer | messages | 31 | 3086 | 3080 | 4069 | 22 | 3 | 7 B |
| 3x4 | confidential signer | message bytes | 1047 | 3113 | 3107 | 4096 | 22 | 3 | 1 B |
| 3x4 | confidential in-proof | messages | 31 | 3182 | 3177 | 4068 | 21 | 2 | 6 B |
| 3x4 | confidential in-proof | message bytes | 1048 | 3210 | 3205 | 4096 | 21 | 2 | 1 B |
| 3x4 | anonymous hidden | reply | 339 | 3306 | 3340 | 4096 | 18 | 2 | 3 B |
| 3x4 | anonymous hidden | messages | 21 | 3295 | 3328 | 4085 | 18 | 2 | 23 B |
| 3x4 | anonymous hidden | message bytes | 691 | 3306 | 3339 | 4096 | 18 | 2 | 1 B |
| 3x4 | anonymous public owners | reply | 296 | 3113 | 3114 | 4096 | 22 | 3 | 3 B |
| 3x4 | anonymous public owners | messages | 17 | 3095 | 3095 | 4078 | 22 | 3 | 16 B |
| 3x4 | anonymous public owners | message bytes | 562 | 3113 | 3113 | 4096 | 22 | 3 | 1 B |
| 3x4 | confidential entry | messages | 13 | 3082 | 3076 | 4065 | 22 | 3 | 3 B |
| 3x4 | confidential entry | message bytes | 439 | 3113 | 3107 | 4096 | 22 | 3 | 1 B |
| 3x4 | anonymous entry | reply | 125 | 3304 | 3306 | 4094 | 18 | 2 | 1 B |
| 3x4 | anonymous entry | messages | 2 | 3289 | 3290 | 4079 | 18 | 2 | 17 B |
| 3x4 | anonymous entry | message bytes | 51 | 3306 | 3307 | 4096 | 18 | 2 | 1 B |
| 3x8 | confidential signer | messages | none | - | - | - | - | - | 190 B |
| 3x8 | confidential signer | message bytes | none | - | - | - | - | - | 225 B |
| 3x8 | confidential in-proof | messages | none | - | - | - | - | - | 189 B |
| 3x8 | confidential in-proof | message bytes | none | - | - | - | - | - | 224 B |
| 3x8 | anonymous hidden | reply | none | - | - | - | - | - | 1062 B |
| 3x8 | anonymous hidden | messages | none | - | - | - | - | - | 1062 B |
| 3x8 | anonymous hidden | message bytes | none | - | - | - | - | - | 1097 B |
| 3x8 | anonymous public owners | reply | none | - | - | - | - | - | 1191 B |
| 3x8 | anonymous public owners | messages | none | - | - | - | - | - | 1191 B |
| 3x8 | anonymous public owners | message bytes | none | - | - | - | - | - | 1226 B |
| 3x8 | confidential entry | messages | none | - | - | - | - | - | 798 B |
| 3x8 | confidential entry | message bytes | none | - | - | - | - | - | 833 B |
| 3x8 | anonymous entry | reply | none | - | - | - | - | - | 1702 B |
| 3x8 | anonymous entry | messages | none | - | - | - | - | - | 1702 B |
| 3x8 | anonymous entry | message bytes | none | - | - | - | - | - | 1737 B |
| 4x2 | confidential signer | messages | 48 | 3060 | 2987 | 4076 | 23 | 3 | 14 B |
| 4x2 | confidential signer | message bytes | 1618 | 3080 | 3007 | 4096 | 23 | 3 | 1 B |
| 4x2 | confidential in-proof | messages | 48 | 3156 | 3084 | 4075 | 22 | 2 | 13 B |
| 4x2 | confidential in-proof | message bytes | 1619 | 3177 | 3105 | 4096 | 22 | 2 | 1 B |
| 4x2 | anonymous hidden | reply | 1652 | 3273 | 3240 | 4096 | 19 | 2 | 1 B |
| 4x2 | anonymous hidden | messages | 45 | 3249 | 3215 | 4072 | 19 | 2 | 10 B |
| 4x2 | anonymous hidden | message bytes | 1520 | 3273 | 3239 | 4096 | 19 | 2 | 1 B |
| 4x2 | anonymous public owners | reply | 1523 | 3080 | 3014 | 4096 | 23 | 3 | 1 B |
| 4x2 | anonymous public owners | messages | 41 | 3049 | 2982 | 4065 | 23 | 3 | 3 B |
| 4x2 | anonymous public owners | message bytes | 1391 | 3080 | 3013 | 4096 | 23 | 3 | 1 B |
| 4x2 | confidential entry | messages | 24 | 3052 | 2979 | 4068 | 23 | 3 | 6 B |
| 4x2 | confidential entry | message bytes | 810 | 3080 | 3007 | 4096 | 23 | 3 | 1 B |
| 4x2 | anonymous entry | reply | 812 | 3273 | 3208 | 4096 | 19 | 2 | 1 B |
| 4x2 | anonymous entry | messages | 21 | 3273 | 3207 | 4096 | 19 | 2 | 34 B |
| 4x2 | anonymous entry | message bytes | 680 | 3273 | 3207 | 4096 | 19 | 2 | 1 B |
| 4x4 | confidential signer | messages | 29 | 3050 | 3045 | 4066 | 23 | 3 | 4 B |
| 4x4 | confidential signer | message bytes | 982 | 3080 | 3075 | 4096 | 23 | 3 | 1 B |
| 4x4 | confidential in-proof | messages | 29 | 3146 | 3142 | 4065 | 22 | 2 | 3 B |
| 4x4 | confidential in-proof | message bytes | 983 | 3177 | 3173 | 4096 | 22 | 2 | 1 B |
| 4x4 | anonymous hidden | reply | 317 | 3272 | 3307 | 4095 | 19 | 2 | 2 B |
| 4x4 | anonymous hidden | messages | 19 | 3259 | 3293 | 4082 | 19 | 2 | 20 B |
| 4x4 | anonymous hidden | message bytes | 626 | 3273 | 3307 | 4096 | 19 | 2 | 1 B |
| 4x4 | anonymous public owners | reply | 274 | 3079 | 3081 | 4095 | 23 | 3 | 2 B |
| 4x4 | anonymous public owners | messages | 15 | 3059 | 3060 | 4075 | 23 | 3 | 13 B |
| 4x4 | anonymous public owners | message bytes | 497 | 3080 | 3081 | 4096 | 23 | 3 | 1 B |
| 4x4 | confidential entry | messages | 6 | 3076 | 3071 | 4092 | 23 | 3 | 30 B |
| 4x4 | confidential entry | message bytes | 174 | 3080 | 3075 | 4096 | 23 | 3 | 1 B |
| 4x4 | anonymous entry | reply | none | - | - | - | - | - | 179 B |
| 4x4 | anonymous entry | messages | none | - | - | - | - | - | 179 B |
| 4x4 | anonymous entry | message bytes | none | - | - | - | - | - | 214 B |
| 4x4 | delegate | messages | 37 | 3266 | 3317 | 4086 | 19 | 2 | 24 B |
| 4x4 | delegate | message bytes | 1234 | 3276 | 3327 | 4096 | 19 | 2 | 1 B |
| 4x4 | anonymous delegate | reply | 358 | 3275 | 3333 | 4095 | 19 | 2 | 2 B |
| 4x4 | anonymous delegate | messages | 23 | 3275 | 3332 | 4095 | 19 | 2 | 33 B |
| 4x4 | anonymous delegate | message bytes | 749 | 3276 | 3333 | 4096 | 19 | 2 | 1 B |
| 4x8 | confidential signer | messages | none | - | - | - | - | - | 255 B |
| 4x8 | confidential signer | message bytes | none | - | - | - | - | - | 290 B |
| 4x8 | confidential in-proof | messages | none | - | - | - | - | - | 254 B |
| 4x8 | confidential in-proof | message bytes | none | - | - | - | - | - | 289 B |
| 4x8 | anonymous hidden | reply | none | - | - | - | - | - | 1127 B |
| 4x8 | anonymous hidden | messages | none | - | - | - | - | - | 1127 B |
| 4x8 | anonymous hidden | message bytes | none | - | - | - | - | - | 1162 B |
| 4x8 | anonymous public owners | reply | none | - | - | - | - | - | 1256 B |
| 4x8 | anonymous public owners | messages | none | - | - | - | - | - | 1256 B |
| 4x8 | anonymous public owners | message bytes | none | - | - | - | - | - | 1291 B |
| 4x8 | confidential entry | messages | none | - | - | - | - | - | 1063 B |
| 4x8 | confidential entry | message bytes | none | - | - | - | - | - | 1098 B |
| 4x8 | anonymous entry | reply | none | - | - | - | - | - | 1967 B |
| 4x8 | anonymous entry | messages | none | - | - | - | - | - | 1967 B |
| 4x8 | anonymous entry | message bytes | none | - | - | - | - | - | 2002 B |
| 5x2 | confidential signer | messages | 46 | 3024 | 2952 | 4073 | 24 | 3 | 11 B |
| 5x2 | confidential signer | message bytes | 1553 | 3047 | 2975 | 4096 | 24 | 3 | 1 B |
| 5x2 | confidential in-proof | messages | 46 | 3120 | 3049 | 4072 | 23 | 2 | 10 B |
| 5x2 | confidential in-proof | message bytes | 1554 | 3144 | 3073 | 4096 | 23 | 2 | 1 B |
| 5x2 | anonymous hidden | reply | 1587 | 3240 | 3208 | 4096 | 20 | 2 | 1 B |
| 5x2 | anonymous hidden | messages | 43 | 3213 | 3180 | 4069 | 20 | 2 | 7 B |
| 5x2 | anonymous hidden | message bytes | 1455 | 3240 | 3207 | 4096 | 20 | 2 | 1 B |
| 5x2 | anonymous public owners | reply | 1458 | 3047 | 2982 | 4096 | 24 | 3 | 1 B |
| 5x2 | anonymous public owners | messages | 40 | 3047 | 2981 | 4096 | 24 | 3 | 34 B |
| 5x2 | anonymous public owners | message bytes | 1326 | 3047 | 2981 | 4096 | 24 | 3 | 1 B |
| 5x2 | confidential entry | messages | 17 | 3046 | 2974 | 4095 | 24 | 3 | 33 B |
| 5x2 | confidential entry | message bytes | 545 | 3047 | 2975 | 4096 | 24 | 3 | 1 B |
| 5x2 | anonymous entry | reply | 547 | 3240 | 3176 | 4096 | 20 | 2 | 1 B |
| 5x2 | anonymous entry | messages | 13 | 3233 | 3168 | 4089 | 20 | 2 | 27 B |
| 5x2 | anonymous entry | message bytes | 415 | 3240 | 3175 | 4096 | 20 | 2 | 1 B |
| 5x4 | confidential signer | messages | 27 | 3014 | 3010 | 4063 | 24 | 3 | 1 B |
| 5x4 | confidential signer | message bytes | 917 | 3047 | 3043 | 4096 | 24 | 3 | 1 B |
| 5x4 | confidential in-proof | messages | 28 | 3144 | 3141 | 4096 | 23 | 2 | 34 B |
| 5x4 | confidential in-proof | message bytes | 918 | 3144 | 3141 | 4096 | 23 | 2 | 1 B |
| 5x4 | anonymous hidden | reply | 295 | 3238 | 3274 | 4094 | 20 | 2 | 1 B |
| 5x4 | anonymous hidden | messages | 17 | 3223 | 3258 | 4079 | 20 | 2 | 17 B |
| 5x4 | anonymous hidden | message bytes | 561 | 3240 | 3275 | 4096 | 20 | 2 | 1 B |
| 5x4 | anonymous public owners | reply | 252 | 3045 | 3048 | 4094 | 24 | 3 | 1 B |
| 5x4 | anonymous public owners | messages | 13 | 3023 | 3025 | 4072 | 24 | 3 | 10 B |
| 5x4 | anonymous public owners | message bytes | 432 | 3047 | 3049 | 4096 | 24 | 3 | 1 B |
| 5x4 | confidential entry | messages | none | - | - | - | - | - | 56 B |
| 5x4 | confidential entry | message bytes | none | - | - | - | - | - | 91 B |
| 5x4 | anonymous entry | reply | none | - | - | - | - | - | 444 B |
| 5x4 | anonymous entry | messages | none | - | - | - | - | - | 444 B |
| 5x4 | anonymous entry | message bytes | none | - | - | - | - | - | 479 B |
| 5x8 | confidential signer | messages | none | - | - | - | - | - | 320 B |
| 5x8 | confidential signer | message bytes | none | - | - | - | - | - | 355 B |
| 5x8 | confidential in-proof | messages | none | - | - | - | - | - | 319 B |
| 5x8 | confidential in-proof | message bytes | none | - | - | - | - | - | 354 B |
| 5x8 | anonymous hidden | reply | none | - | - | - | - | - | 1192 B |
| 5x8 | anonymous hidden | messages | none | - | - | - | - | - | 1192 B |
| 5x8 | anonymous hidden | message bytes | none | - | - | - | - | - | 1227 B |
| 5x8 | anonymous public owners | reply | none | - | - | - | - | - | 1321 B |
| 5x8 | anonymous public owners | messages | none | - | - | - | - | - | 1321 B |
| 5x8 | anonymous public owners | message bytes | none | - | - | - | - | - | 1356 B |
| 5x8 | confidential entry | messages | none | - | - | - | - | - | 1328 B |
| 5x8 | confidential entry | message bytes | none | - | - | - | - | - | 1363 B |
| 5x8 | anonymous entry | reply | none | - | - | - | - | - | 2232 B |
| 5x8 | anonymous entry | messages | none | - | - | - | - | - | 2232 B |
| 5x8 | anonymous entry | message bytes | none | - | - | - | - | - | 2267 B |
| 6x2 | confidential signer | messages | 44 | 2988 | 2917 | 4070 | 25 | 3 | 8 B |
| 6x2 | confidential signer | message bytes | 1488 | 3014 | 2943 | 4096 | 25 | 3 | 1 B |
| 6x2 | confidential in-proof | messages | 44 | 3084 | 3014 | 4069 | 24 | 2 | 7 B |
| 6x2 | confidential in-proof | message bytes | 1489 | 3111 | 3041 | 4096 | 24 | 2 | 1 B |
| 6x2 | anonymous hidden | reply | 1522 | 3207 | 3176 | 4096 | 21 | 2 | 1 B |
| 6x2 | anonymous hidden | messages | 41 | 3177 | 3145 | 4066 | 21 | 2 | 4 B |
| 6x2 | anonymous hidden | message bytes | 1390 | 3207 | 3175 | 4096 | 21 | 2 | 1 B |
| 6x2 | anonymous public owners | reply | 1393 | 3014 | 2950 | 4096 | 25 | 3 | 1 B |
| 6x2 | anonymous public owners | messages | 38 | 3011 | 2946 | 4093 | 25 | 3 | 31 B |
| 6x2 | anonymous public owners | message bytes | 1261 | 3014 | 2949 | 4096 | 25 | 3 | 1 B |
| 6x2 | confidential entry | messages | 9 | 3006 | 2935 | 4088 | 25 | 3 | 26 B |
| 6x2 | confidential entry | message bytes | 280 | 3014 | 2943 | 4096 | 25 | 3 | 1 B |
| 6x2 | anonymous entry | reply | 282 | 3207 | 3144 | 4096 | 21 | 2 | 1 B |
| 6x2 | anonymous entry | messages | 5 | 3193 | 3129 | 4082 | 21 | 2 | 20 B |
| 6x2 | anonymous entry | message bytes | 150 | 3207 | 3143 | 4096 | 21 | 2 | 1 B |
| 6x4 | confidential signer | messages | 26 | 3012 | 3009 | 4094 | 25 | 3 | 32 B |
| 6x4 | confidential signer | message bytes | 852 | 3014 | 3011 | 4096 | 25 | 3 | 1 B |
| 6x4 | confidential in-proof | messages | 26 | 3108 | 3106 | 4093 | 24 | 2 | 31 B |
| 6x4 | confidential in-proof | message bytes | 853 | 3111 | 3109 | 4096 | 24 | 2 | 1 B |
| 6x4 | anonymous hidden | reply | 274 | 3207 | 3244 | 4096 | 21 | 2 | 3 B |
| 6x4 | anonymous hidden | messages | 15 | 3187 | 3223 | 4076 | 21 | 2 | 14 B |
| 6x4 | anonymous hidden | message bytes | 496 | 3207 | 3243 | 4096 | 21 | 2 | 1 B |
| 6x4 | anonymous public owners | reply | 231 | 3014 | 3018 | 4096 | 25 | 3 | 3 B |
| 6x4 | anonymous public owners | messages | 11 | 2987 | 2990 | 4069 | 25 | 3 | 7 B |
| 6x4 | anonymous public owners | message bytes | 367 | 3014 | 3017 | 4096 | 25 | 3 | 1 B |
| 6x4 | confidential entry | messages | none | - | - | - | - | - | 321 B |
| 6x4 | confidential entry | message bytes | none | - | - | - | - | - | 356 B |
| 6x4 | anonymous entry | reply | none | - | - | - | - | - | 709 B |
| 6x4 | anonymous entry | messages | none | - | - | - | - | - | 709 B |
| 6x4 | anonymous entry | message bytes | none | - | - | - | - | - | 744 B |
| 6x8 | confidential signer | messages | none | - | - | - | - | - | 385 B |
| 6x8 | confidential signer | message bytes | none | - | - | - | - | - | 420 B |
| 6x8 | confidential in-proof | messages | none | - | - | - | - | - | 384 B |
| 6x8 | confidential in-proof | message bytes | none | - | - | - | - | - | 419 B |
| 6x8 | anonymous hidden | reply | none | - | - | - | - | - | 1257 B |
| 6x8 | anonymous hidden | messages | none | - | - | - | - | - | 1257 B |
| 6x8 | anonymous hidden | message bytes | none | - | - | - | - | - | 1292 B |
| 6x8 | anonymous public owners | reply | none | - | - | - | - | - | 1386 B |
| 6x8 | anonymous public owners | messages | none | - | - | - | - | - | 1386 B |
| 6x8 | anonymous public owners | message bytes | none | - | - | - | - | - | 1421 B |
| 6x8 | confidential entry | messages | none | - | - | - | - | - | 1593 B |
| 6x8 | confidential entry | message bytes | none | - | - | - | - | - | 1628 B |
| 6x8 | anonymous entry | reply | none | - | - | - | - | - | 2497 B |
| 6x8 | anonymous entry | messages | none | - | - | - | - | - | 2497 B |
| 6x8 | anonymous entry | message bytes | none | - | - | - | - | - | 2532 B |
| 8x2 | confidential signer | messages | 40 | 2916 | 2847 | 4064 | 27 | 3 | 2 B |
| 8x2 | confidential signer | message bytes | 1358 | 2948 | 2879 | 4096 | 27 | 3 | 1 B |
| 8x2 | confidential in-proof | messages | 40 | 3012 | 2944 | 4063 | 26 | 2 | 1 B |
| 8x2 | confidential in-proof | message bytes | 1359 | 3045 | 2977 | 4096 | 26 | 2 | 1 B |
| 8x2 | anonymous hidden | reply | 1392 | 3141 | 3112 | 4096 | 23 | 2 | 1 B |
| 8x2 | anonymous hidden | messages | 38 | 3139 | 3109 | 4094 | 23 | 2 | 32 B |
| 8x2 | anonymous hidden | message bytes | 1260 | 3141 | 3111 | 4096 | 23 | 2 | 1 B |
| 8x2 | anonymous public owners | reply | 1263 | 2948 | 2886 | 4096 | 27 | 3 | 1 B |
| 8x2 | anonymous public owners | messages | 34 | 2939 | 2876 | 4087 | 27 | 3 | 25 B |
| 8x2 | anonymous public owners | message bytes | 1131 | 2948 | 2885 | 4096 | 27 | 3 | 1 B |
| 8x2 | confidential entry | messages | none | - | - | - | - | - | 215 B |
| 8x2 | confidential entry | message bytes | none | - | - | - | - | - | 250 B |
| 8x2 | anonymous entry | reply | none | - | - | - | - | - | 345 B |
| 8x2 | anonymous entry | messages | none | - | - | - | - | - | 345 B |
| 8x2 | anonymous entry | message bytes | none | - | - | - | - | - | 380 B |
| 8x4 | confidential signer | messages | 22 | 2940 | 2939 | 4088 | 27 | 3 | 26 B |
| 8x4 | confidential signer | message bytes | 722 | 2948 | 2947 | 4096 | 27 | 3 | 1 B |
| 8x4 | confidential in-proof | messages | 22 | 3036 | 3036 | 4087 | 26 | 2 | 25 B |
| 8x4 | confidential in-proof | message bytes | 723 | 3045 | 3045 | 4096 | 26 | 2 | 1 B |
| 8x4 | anonymous hidden | reply | 230 | 3139 | 3178 | 4094 | 23 | 2 | 1 B |
| 8x4 | anonymous hidden | messages | 11 | 3115 | 3153 | 4070 | 23 | 2 | 8 B |
| 8x4 | anonymous hidden | message bytes | 366 | 3141 | 3179 | 4096 | 23 | 2 | 1 B |
| 8x4 | anonymous public owners | reply | 187 | 2946 | 2952 | 4094 | 27 | 3 | 1 B |
| 8x4 | anonymous public owners | messages | 7 | 2915 | 2920 | 4063 | 27 | 3 | 1 B |
| 8x4 | anonymous public owners | message bytes | 237 | 2948 | 2953 | 4096 | 27 | 3 | 1 B |
| 8x4 | confidential entry | messages | none | - | - | - | - | - | 851 B |
| 8x4 | confidential entry | message bytes | none | - | - | - | - | - | 886 B |
| 8x4 | anonymous entry | reply | none | - | - | - | - | - | 1239 B |
| 8x4 | anonymous entry | messages | none | - | - | - | - | - | 1239 B |
| 8x4 | anonymous entry | message bytes | none | - | - | - | - | - | 1274 B |
| 8x8 | confidential signer | messages | none | - | - | - | - | - | 515 B |
| 8x8 | confidential signer | message bytes | none | - | - | - | - | - | 550 B |
| 8x8 | confidential in-proof | messages | none | - | - | - | - | - | 514 B |
| 8x8 | confidential in-proof | message bytes | none | - | - | - | - | - | 549 B |
| 8x8 | anonymous hidden | reply | none | - | - | - | - | - | 1387 B |
| 8x8 | anonymous hidden | messages | none | - | - | - | - | - | 1387 B |
| 8x8 | anonymous hidden | message bytes | none | - | - | - | - | - | 1422 B |
| 8x8 | anonymous public owners | reply | none | - | - | - | - | - | 1516 B |
| 8x8 | anonymous public owners | messages | none | - | - | - | - | - | 1516 B |
| 8x8 | anonymous public owners | message bytes | none | - | - | - | - | - | 1551 B |
| 8x8 | confidential entry | messages | none | - | - | - | - | - | 2123 B |
| 8x8 | confidential entry | message bytes | none | - | - | - | - | - | 2158 B |
| 8x8 | anonymous entry | reply | none | - | - | - | - | - | 3027 B |
| 8x8 | anonymous entry | messages | none | - | - | - | - | - | 3027 B |
| 8x8 | anonymous entry | message bytes | none | - | - | - | - | - | 3062 B |
| 12x2 | confidential signer | messages | 33 | 2807 | 2741 | 4087 | 31 | 3 | 25 B |
| 12x2 | confidential signer | message bytes | 1097 | 2816 | 2750 | 4096 | 31 | 3 | 1 B |
| 12x2 | confidential in-proof | messages | 33 | 2903 | 2838 | 4086 | 30 | 2 | 24 B |
| 12x2 | confidential in-proof | message bytes | 1098 | 2913 | 2848 | 4096 | 30 | 2 | 1 B |
| 12x2 | anonymous hidden | reply | 1131 | 3009 | 2983 | 4096 | 27 | 2 | 1 B |
| 12x2 | anonymous hidden | messages | 30 | 2996 | 2969 | 4083 | 27 | 2 | 21 B |
| 12x2 | anonymous hidden | message bytes | 999 | 3009 | 2982 | 4096 | 27 | 2 | 1 B |
| 12x2 | anonymous public owners | reply | 1002 | 2816 | 2757 | 4096 | 31 | 3 | 1 B |
| 12x2 | anonymous public owners | messages | 26 | 2796 | 2736 | 4076 | 31 | 3 | 14 B |
| 12x2 | anonymous public owners | message bytes | 870 | 2816 | 2756 | 4096 | 31 | 3 | 1 B |
| 12x4 | confidential signer | messages | 14 | 2797 | 2799 | 4077 | 31 | 3 | 15 B |
| 12x4 | confidential signer | message bytes | 461 | 2816 | 2818 | 4096 | 31 | 3 | 1 B |
| 12x4 | confidential in-proof | messages | 14 | 2893 | 2896 | 4076 | 30 | 2 | 14 B |
| 12x4 | confidential in-proof | message bytes | 462 | 2913 | 2916 | 4096 | 30 | 2 | 1 B |
| 12x4 | anonymous hidden | reply | 143 | 3007 | 3049 | 4094 | 27 | 2 | 1 B |
| 12x4 | anonymous hidden | messages | 4 | 3006 | 3047 | 4093 | 27 | 2 | 31 B |
| 12x4 | anonymous hidden | message bytes | 105 | 3009 | 3050 | 4096 | 27 | 2 | 1 B |
| 12x4 | anonymous public owners | reply | 100 | 2814 | 2823 | 4094 | 31 | 3 | 1 B |
| 12x4 | anonymous public owners | messages | 0 | 2805 | 2814 | 4085 | 31 | 3 | 24 B |
| 12x4 | anonymous public owners | message bytes | none | - | - | - | - | - | 24 B |
| 12x8 | confidential signer | messages | none | - | - | - | - | - | 776 B |
| 12x8 | confidential signer | message bytes | none | - | - | - | - | - | 811 B |
| 12x8 | confidential in-proof | messages | none | - | - | - | - | - | 775 B |
| 12x8 | confidential in-proof | message bytes | none | - | - | - | - | - | 810 B |
| 12x8 | anonymous hidden | reply | none | - | - | - | - | - | 1648 B |
| 12x8 | anonymous hidden | messages | none | - | - | - | - | - | 1648 B |
| 12x8 | anonymous hidden | message bytes | none | - | - | - | - | - | 1683 B |
| 12x8 | anonymous public owners | reply | none | - | - | - | - | - | 1777 B |
| 12x8 | anonymous public owners | messages | none | - | - | - | - | - | 1777 B |
| 12x8 | anonymous public owners | message bytes | none | - | - | - | - | - | 1812 B |
| 16x2 | confidential signer | messages | 25 | 2663 | 2601 | 4075 | 35 | 3 | 13 B |
| 16x2 | confidential signer | message bytes | 837 | 2684 | 2622 | 4096 | 35 | 3 | 1 B |
| 16x2 | confidential in-proof | messages | 25 | 2759 | 2698 | 4074 | 34 | 2 | 12 B |
| 16x2 | confidential in-proof | message bytes | 838 | 2781 | 2720 | 4096 | 34 | 2 | 1 B |
| 16x2 | anonymous hidden | reply | 871 | 2877 | 2855 | 4096 | 31 | 2 | 1 B |
| 16x2 | anonymous hidden | messages | 22 | 2852 | 2829 | 4071 | 31 | 2 | 9 B |
| 16x2 | anonymous hidden | message bytes | 739 | 2877 | 2854 | 4096 | 31 | 2 | 1 B |
| 16x2 | anonymous public owners | reply | 742 | 2684 | 2629 | 4096 | 35 | 3 | 1 B |
| 16x2 | anonymous public owners | messages | 18 | 2652 | 2596 | 4064 | 35 | 3 | 2 B |
| 16x2 | anonymous public owners | message bytes | 610 | 2684 | 2628 | 4096 | 35 | 3 | 1 B |
| 16x4 | confidential signer | messages | 6 | 2653 | 2659 | 4065 | 35 | 3 | 3 B |
| 16x4 | confidential signer | message bytes | 201 | 2684 | 2690 | 4096 | 35 | 3 | 1 B |
| 16x4 | confidential in-proof | messages | 6 | 2749 | 2756 | 4064 | 34 | 2 | 2 B |
| 16x4 | confidential in-proof | message bytes | 202 | 2781 | 2788 | 4096 | 34 | 2 | 1 B |
| 16x4 | anonymous hidden | reply | none | - | - | - | - | - | 120 B |
| 16x4 | anonymous hidden | messages | none | - | - | - | - | - | 120 B |
| 16x4 | anonymous hidden | message bytes | none | - | - | - | - | - | 155 B |
| 16x4 | anonymous public owners | reply | none | - | - | - | - | - | 249 B |
| 16x4 | anonymous public owners | messages | none | - | - | - | - | - | 249 B |
| 16x4 | anonymous public owners | message bytes | none | - | - | - | - | - | 284 B |
| 16x8 | confidential signer | messages | none | - | - | - | - | - | 1036 B |
| 16x8 | confidential signer | message bytes | none | - | - | - | - | - | 1071 B |
| 16x8 | confidential in-proof | messages | none | - | - | - | - | - | 1035 B |
| 16x8 | confidential in-proof | message bytes | none | - | - | - | - | - | 1070 B |
| 16x8 | anonymous hidden | reply | none | - | - | - | - | - | 1908 B |
| 16x8 | anonymous hidden | messages | none | - | - | - | - | - | 1908 B |
| 16x8 | anonymous hidden | message bytes | none | - | - | - | - | - | 1943 B |
| 16x8 | anonymous public owners | reply | none | - | - | - | - | - | 2037 B |
| 16x8 | anonymous public owners | messages | none | - | - | - | - | - | 2037 B |
| 16x8 | anonymous public owners | message bytes | none | - | - | - | - | - | 2072 B |
| 24x2 | confidential signer | messages | 10 | 2410 | 2355 | 4086 | 43 | 3 | 24 B |
| 24x2 | confidential signer | message bytes | 316 | 2420 | 2365 | 4096 | 43 | 3 | 1 B |
| 24x2 | confidential in-proof | messages | 10 | 2506 | 2452 | 4085 | 42 | 2 | 23 B |
| 24x2 | confidential in-proof | message bytes | 317 | 2517 | 2463 | 4096 | 42 | 2 | 1 B |
| 24x2 | anonymous hidden | reply | 350 | 2613 | 2598 | 4096 | 39 | 2 | 1 B |
| 24x2 | anonymous hidden | messages | 7 | 2599 | 2583 | 4082 | 39 | 2 | 20 B |
| 24x2 | anonymous hidden | message bytes | 218 | 2613 | 2597 | 4096 | 39 | 2 | 1 B |
| 24x2 | anonymous public owners | reply | 221 | 2420 | 2372 | 4096 | 43 | 3 | 1 B |
| 24x2 | anonymous public owners | messages | 3 | 2399 | 2350 | 4075 | 43 | 3 | 13 B |
| 24x2 | anonymous public owners | message bytes | 89 | 2420 | 2371 | 4096 | 43 | 3 | 1 B |
| 24x4 | confidential signer | messages | none | - | - | - | - | - | 285 B |
| 24x4 | confidential signer | message bytes | none | - | - | - | - | - | 320 B |
| 24x4 | confidential in-proof | messages | none | - | - | - | - | - | 284 B |
| 24x4 | confidential in-proof | message bytes | none | - | - | - | - | - | 319 B |
| 24x4 | anonymous hidden | reply | none | - | - | - | - | - | 641 B |
| 24x4 | anonymous hidden | messages | none | - | - | - | - | - | 641 B |
| 24x4 | anonymous hidden | message bytes | none | - | - | - | - | - | 676 B |
| 24x4 | anonymous public owners | reply | none | - | - | - | - | - | 770 B |
| 24x4 | anonymous public owners | messages | none | - | - | - | - | - | 770 B |
| 24x4 | anonymous public owners | message bytes | none | - | - | - | - | - | 805 B |
| 32x2 | confidential signer | messages | none | - | - | - | - | - | 170 B |
| 32x2 | confidential signer | message bytes | none | - | - | - | - | - | 205 B |
| 32x2 | confidential in-proof | messages | none | - | - | - | - | - | 169 B |
| 32x2 | confidential in-proof | message bytes | none | - | - | - | - | - | 204 B |
| 32x2 | anonymous hidden | reply | none | - | - | - | - | - | 268 B |
| 32x2 | anonymous hidden | messages | none | - | - | - | - | - | 268 B |
| 32x2 | anonymous hidden | message bytes | none | - | - | - | - | - | 303 B |
| 32x2 | anonymous public owners | reply | none | - | - | - | - | - | 397 B |
| 32x2 | anonymous public owners | messages | none | - | - | - | - | - | 397 B |
| 32x2 | anonymous public owners | message bytes | none | - | - | - | - | - | 432 B |
| 40x2 | confidential signer | messages | none | - | - | - | - | - | 691 B |
| 40x2 | confidential signer | message bytes | none | - | - | - | - | - | 726 B |
| 40x2 | confidential in-proof | messages | none | - | - | - | - | - | 690 B |
| 40x2 | confidential in-proof | message bytes | none | - | - | - | - | - | 725 B |
| 40x2 | anonymous hidden | reply | none | - | - | - | - | - | 789 B |
| 40x2 | anonymous hidden | messages | none | - | - | - | - | - | 789 B |
| 40x2 | anonymous hidden | message bytes | none | - | - | - | - | - | 824 B |
| 40x2 | anonymous public owners | reply | none | - | - | - | - | - | 918 B |
| 40x2 | anonymous public owners | messages | none | - | - | - | - | - | 918 B |
| 40x2 | anonymous public owners | message bytes | none | - | - | - | - | - | 953 B |
