Measured with the frame encoders, SPP's account builders and the v1 compiler. Ceilings 4096 B, 64 accounts, 12 signatures.
min: tracking root, no co-signer, no leg, no fee, the payer an owner where it may be. full: own, curator and tracking roots, one co-signer, 4 SOL legs, a fee, an outside payer, a body on every slot and one exit. The owner run is the ceilings' bound under full, the key's rows bound it apart. A shape's every input and output slot is published.
Every row is one transaction. fits: the row clears the transaction and CPI ceilings. limit: what refuses a row, rail for a shape the rail has no SPP key for, else the excess in accounts, signatures, bytes or CPI data at that row's load. A missing catalog key has no encoded measurement.
| shape | rail | load | catalog key | bytes | accounts | signatures | owner run | frame | SPP CPI | fits | limit |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1x2 | confidential signer | min | yes | 1323 | 9 | 1 | - | 907 | 921 | yes |  |
| 1x2 | confidential signer | full | yes | 1950 | 19 | 3 | 1 | 1066 | 1038 | yes |  |
| 1x2 | confidential signer | full+spl | yes | 2318 | 26 | 3 | - | 1198 | 1042 | yes |  |
| 1x2 | confidential signer | full+data | yes | 2024 | 19 | 3 | - | 1140 | 1108 | yes |  |
| 1x2 | confidential signer | full+reply | yes | 1950 | 19 | 3 | - | 1066 | 1038 | yes |  |
| 1x2 | confidential signer | full+2tree | yes | 1988 | 20 | 3 | - | 1071 | 1042 | yes |  |
| 1x2 | confidential in-proof | min | yes | 1418 | 9 | 1 | - | 1003 | 1018 | yes |  |
| 1x2 | confidential in-proof | full | yes | 1949 | 18 | 2 | 1 | 1162 | 1135 | yes |  |
| 1x2 | confidential in-proof | full+spl | yes | 2317 | 25 | 2 | - | 1294 | 1139 | yes |  |
| 1x2 | confidential in-proof | full+data | yes | 2023 | 18 | 2 | - | 1236 | 1205 | yes |  |
| 1x2 | confidential in-proof | full+reply | yes | 1949 | 18 | 2 | - | 1162 | 1135 | yes |  |
| 1x2 | confidential in-proof | full+2tree | yes | 1987 | 19 | 2 | - | 1167 | 1139 | yes |  |
| 1x2 | anonymous hidden | min | yes | 1514 | 9 | 1 | - | 1099 | 1154 | yes |  |
| 1x2 | anonymous hidden | full | yes | 1949 | 15 | 2 | 1 | 1258 | 1271 | yes |  |
| 1x2 | anonymous hidden | full+spl | yes | 2317 | 22 | 2 | - | 1390 | 1275 | yes |  |
| 1x2 | anonymous hidden | full+data | yes | 2023 | 15 | 2 | - | 1332 | 1341 | yes |  |
| 1x2 | anonymous hidden | full+reply | yes | 2048 | 15 | 2 | - | 1357 | 1368 | yes |  |
| 1x2 | anonymous hidden | full+2tree | yes | 1987 | 16 | 2 | - | 1263 | 1275 | yes |  |
| 1x2 | anonymous public owners | min | yes | 1451 | 9 | 1 | - | 1035 | 1057 | yes |  |
| 1x2 | anonymous public owners | full | yes | 2078 | 19 | 3 | 1 | 1194 | 1174 | yes |  |
| 1x2 | anonymous public owners | full+spl | yes | 2446 | 26 | 3 | - | 1326 | 1178 | yes |  |
| 1x2 | anonymous public owners | full+data | yes | 2152 | 19 | 3 | - | 1268 | 1244 | yes |  |
| 1x2 | anonymous public owners | full+reply | yes | 2177 | 19 | 3 | - | 1293 | 1271 | yes |  |
| 1x2 | anonymous public owners | full+2tree | yes | 2116 | 20 | 3 | - | 1199 | 1178 | yes |  |
| 1x2 | confidential entry | min | yes | 1467 | 9 | 1 | - | 1051 | 1065 | yes |  |
| 1x2 | confidential entry | full | yes | 2094 | 19 | 3 | 1 | 1210 | 1182 | yes |  |
| 1x2 | confidential entry | full+spl | yes | 2462 | 26 | 3 | - | 1342 | 1186 | yes |  |
| 1x2 | confidential entry | full+data | yes | 2168 | 19 | 3 | - | 1284 | 1252 | yes |  |
| 1x2 | confidential entry | full+reply | yes | 2094 | 19 | 3 | - | 1210 | 1182 | yes |  |
| 1x2 | confidential entry | full+2tree | yes | 2132 | 20 | 3 | - | 1215 | 1186 | yes |  |
| 1x2 | anonymous entry | min | yes | 1690 | 9 | 1 | - | 1275 | 1298 | yes |  |
| 1x2 | anonymous entry | full | yes | 2125 | 15 | 2 | 1 | 1434 | 1415 | yes |  |
| 1x2 | anonymous entry | full+spl | yes | 2493 | 22 | 2 | - | 1566 | 1419 | yes |  |
| 1x2 | anonymous entry | full+data | yes | 2199 | 15 | 2 | - | 1508 | 1485 | yes |  |
| 1x2 | anonymous entry | full+reply | yes | 2224 | 15 | 2 | - | 1533 | 1512 | yes |  |
| 1x2 | anonymous entry | full+2tree | yes | 2163 | 16 | 2 | - | 1439 | 1419 | yes |  |
| 1x2 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 1x2 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 1x4 | confidential signer | min | yes | 1741 | 9 | 1 | - | 1325 | 1411 | yes |  |
| 1x4 | confidential signer | full | yes | 2368 | 19 | 3 | 1 | 1484 | 1528 | yes |  |
| 1x4 | confidential signer | full+spl | yes | 2736 | 26 | 3 | - | 1616 | 1532 | yes |  |
| 1x4 | confidential signer | full+data | yes | 2516 | 19 | 3 | - | 1632 | 1668 | yes |  |
| 1x4 | confidential signer | full+reply | yes | 2368 | 19 | 3 | - | 1484 | 1528 | yes |  |
| 1x4 | confidential signer | full+2tree | yes | 2406 | 20 | 3 | - | 1489 | 1532 | yes |  |
| 1x4 | confidential in-proof | min | yes | 1836 | 9 | 1 | - | 1421 | 1508 | yes |  |
| 1x4 | confidential in-proof | full | yes | 2367 | 18 | 2 | 1 | 1580 | 1625 | yes |  |
| 1x4 | confidential in-proof | full+spl | yes | 2735 | 25 | 2 | - | 1712 | 1629 | yes |  |
| 1x4 | confidential in-proof | full+data | yes | 2515 | 18 | 2 | - | 1728 | 1765 | yes |  |
| 1x4 | confidential in-proof | full+reply | yes | 2367 | 18 | 2 | - | 1580 | 1625 | yes |  |
| 1x4 | confidential in-proof | full+2tree | yes | 2405 | 19 | 2 | - | 1585 | 1629 | yes |  |
| 1x4 | anonymous hidden | min | yes | 1996 | 9 | 1 | - | 1581 | 1708 | yes |  |
| 1x4 | anonymous hidden | full | yes | 2431 | 15 | 2 | 1 | 1740 | 1825 | yes |  |
| 1x4 | anonymous hidden | full+spl | yes | 2799 | 22 | 2 | - | 1872 | 1829 | yes |  |
| 1x4 | anonymous hidden | full+data | yes | 2579 | 15 | 2 | - | 1888 | 1965 | yes |  |
| 1x4 | anonymous hidden | full+reply | yes | 2724 | 15 | 2 | - | 2033 | 2116 | yes |  |
| 1x4 | anonymous hidden | full+2tree | yes | 2469 | 16 | 2 | - | 1745 | 1829 | yes |  |
| 1x4 | anonymous public owners | min | yes | 1933 | 9 | 1 | - | 1517 | 1611 | yes |  |
| 1x4 | anonymous public owners | full | yes | 2560 | 19 | 3 | 1 | 1676 | 1728 | yes |  |
| 1x4 | anonymous public owners | full+spl | yes | 2928 | 26 | 3 | - | 1808 | 1732 | yes |  |
| 1x4 | anonymous public owners | full+data | yes | 2708 | 19 | 3 | - | 1824 | 1868 | yes |  |
| 1x4 | anonymous public owners | full+reply | yes | 2853 | 19 | 3 | - | 1969 | 2019 | yes |  |
| 1x4 | anonymous public owners | full+2tree | yes | 2598 | 20 | 3 | - | 1681 | 1732 | yes |  |
| 1x4 | confidential entry | min | yes | 1885 | 9 | 1 | - | 1469 | 1555 | yes |  |
| 1x4 | confidential entry | full | yes | 2512 | 19 | 3 | 1 | 1628 | 1672 | yes |  |
| 1x4 | confidential entry | full+spl | yes | 2880 | 26 | 3 | - | 1760 | 1676 | yes |  |
| 1x4 | confidential entry | full+data | yes | 2660 | 19 | 3 | - | 1776 | 1812 | yes |  |
| 1x4 | confidential entry | full+reply | yes | 2512 | 19 | 3 | - | 1628 | 1672 | yes |  |
| 1x4 | confidential entry | full+2tree | yes | 2550 | 20 | 3 | - | 1633 | 1676 | yes |  |
| 1x4 | anonymous entry | min | yes | 2172 | 9 | 1 | - | 1757 | 1852 | yes |  |
| 1x4 | anonymous entry | full | yes | 2607 | 15 | 2 | 1 | 1916 | 1969 | yes |  |
| 1x4 | anonymous entry | full+spl | yes | 2975 | 22 | 2 | - | 2048 | 1973 | yes |  |
| 1x4 | anonymous entry | full+data | yes | 2755 | 15 | 2 | - | 2064 | 2109 | yes |  |
| 1x4 | anonymous entry | full+reply | yes | 2900 | 15 | 2 | - | 2209 | 2260 | yes |  |
| 1x4 | anonymous entry | full+2tree | yes | 2645 | 16 | 2 | - | 1921 | 1973 | yes |  |
| 1x4 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 1x4 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 1x8 | confidential signer | min | yes | 2577 | 9 | 1 | - | 2161 | 2391 | yes |  |
| 1x8 | confidential signer | full | yes | 3204 | 19 | 3 | 1 | 2320 | 2508 | yes |  |
| 1x8 | confidential signer | full+spl | yes | 3572 | 26 | 3 | - | 2452 | 2512 | yes |  |
| 1x8 | confidential signer | full+data | yes | 3500 | 19 | 3 | - | 2616 | 2788 | yes |  |
| 1x8 | confidential signer | full+reply | yes | 3204 | 19 | 3 | - | 2320 | 2508 | yes |  |
| 1x8 | confidential signer | full+2tree | yes | 3242 | 20 | 3 | - | 2325 | 2512 | yes |  |
| 1x8 | confidential in-proof | min | yes | 2672 | 9 | 1 | - | 2257 | 2488 | yes |  |
| 1x8 | confidential in-proof | full | yes | 3203 | 18 | 2 | 1 | 2416 | 2605 | yes |  |
| 1x8 | confidential in-proof | full+spl | yes | 3571 | 25 | 2 | - | 2548 | 2609 | yes |  |
| 1x8 | confidential in-proof | full+data | yes | 3499 | 18 | 2 | - | 2712 | 2885 | yes |  |
| 1x8 | confidential in-proof | full+reply | yes | 3203 | 18 | 2 | - | 2416 | 2605 | yes |  |
| 1x8 | confidential in-proof | full+2tree | yes | 3241 | 19 | 2 | - | 2421 | 2609 | yes |  |
| 1x8 | anonymous hidden | min | yes | 2960 | 9 | 1 | - | 2545 | 2816 | yes |  |
| 1x8 | anonymous hidden | full | yes | 3395 | 15 | 2 | 1 | 2704 | 2933 | yes |  |
| 1x8 | anonymous hidden | full+spl | yes | 3763 | 22 | 2 | - | 2836 | 2937 | yes |  |
| 1x8 | anonymous hidden | full+data | yes | 3691 | 15 | 2 | - | 3000 | 3213 | yes |  |
| 1x8 | anonymous hidden | full+reply | yes | 4076 | 15 | 2 | - | 3385 | 3612 | yes |  |
| 1x8 | anonymous hidden | full+2tree | yes | 3433 | 16 | 2 | - | 2709 | 2937 | yes |  |
| 1x8 | anonymous public owners | min | yes | 2897 | 9 | 1 | - | 2481 | 2719 | yes |  |
| 1x8 | anonymous public owners | full | yes | 3524 | 19 | 3 | 1 | 2640 | 2836 | yes |  |
| 1x8 | anonymous public owners | full+spl | yes | 3892 | 26 | 3 | - | 2772 | 2840 | yes |  |
| 1x8 | anonymous public owners | full+data | yes | 3820 | 19 | 3 | - | 2936 | 3116 | yes |  |
| 1x8 | anonymous public owners | full+reply | yes | 4205 | 19 | 3 | - | 3321 | 3515 | no | 109 B |
| 1x8 | anonymous public owners | full+2tree | yes | 3562 | 20 | 3 | - | 2645 | 2840 | yes |  |
| 1x8 | confidential entry | min | yes | 2721 | 9 | 1 | - | 2305 | 2535 | yes |  |
| 1x8 | confidential entry | full | yes | 3348 | 19 | 3 | 1 | 2464 | 2652 | yes |  |
| 1x8 | confidential entry | full+spl | yes | 3716 | 26 | 3 | - | 2596 | 2656 | yes |  |
| 1x8 | confidential entry | full+data | yes | 3644 | 19 | 3 | - | 2760 | 2932 | yes |  |
| 1x8 | confidential entry | full+reply | yes | 3348 | 19 | 3 | - | 2464 | 2652 | yes |  |
| 1x8 | confidential entry | full+2tree | yes | 3386 | 20 | 3 | - | 2469 | 2656 | yes |  |
| 1x8 | anonymous entry | min | yes | 3136 | 9 | 1 | - | 2721 | 2960 | yes |  |
| 1x8 | anonymous entry | full | yes | 3571 | 15 | 2 | 1 | 2880 | 3077 | yes |  |
| 1x8 | anonymous entry | full+spl | yes | 3939 | 22 | 2 | - | 3012 | 3081 | yes |  |
| 1x8 | anonymous entry | full+data | yes | 3867 | 15 | 2 | - | 3176 | 3357 | yes |  |
| 1x8 | anonymous entry | full+reply | yes | 4252 | 15 | 2 | - | 3561 | 3756 | no | 156 B |
| 1x8 | anonymous entry | full+2tree | yes | 3609 | 16 | 2 | - | 2885 | 3081 | yes |  |
| 1x8 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 1x8 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 2x2 | confidential signer | min | yes | 1388 | 10 | 1 | - | 939 | 954 | yes |  |
| 2x2 | confidential signer | full | yes | 2015 | 20 | 3 | 2 | 1098 | 1071 | yes |  |
| 2x2 | confidential signer | full+spl | yes | 2383 | 27 | 3 | - | 1230 | 1075 | yes |  |
| 2x2 | confidential signer | full+data | yes | 2089 | 20 | 3 | - | 1172 | 1141 | yes |  |
| 2x2 | confidential signer | full+reply | yes | 2015 | 20 | 3 | - | 1098 | 1071 | yes |  |
| 2x2 | confidential signer | full+2tree | yes | 2053 | 21 | 3 | - | 1103 | 1075 | yes |  |
| 2x2 | confidential in-proof | min | yes | 1483 | 10 | 1 | - | 1035 | 1051 | yes |  |
| 2x2 | confidential in-proof | full | yes | 2014 | 19 | 2 | 2 | 1194 | 1168 | yes |  |
| 2x2 | confidential in-proof | full+spl | yes | 2382 | 26 | 2 | - | 1326 | 1172 | yes |  |
| 2x2 | confidential in-proof | full+data | yes | 2088 | 19 | 2 | - | 1268 | 1238 | yes |  |
| 2x2 | confidential in-proof | full+reply | yes | 2014 | 19 | 2 | - | 1194 | 1168 | yes |  |
| 2x2 | confidential in-proof | full+2tree | yes | 2052 | 20 | 2 | - | 1199 | 1172 | yes |  |
| 2x2 | anonymous hidden | min | yes | 1579 | 10 | 1 | - | 1131 | 1187 | yes |  |
| 2x2 | anonymous hidden | full | yes | 2014 | 16 | 2 | 2 | 1290 | 1304 | yes |  |
| 2x2 | anonymous hidden | full+spl | yes | 2382 | 23 | 2 | - | 1422 | 1308 | yes |  |
| 2x2 | anonymous hidden | full+data | yes | 2088 | 16 | 2 | - | 1364 | 1374 | yes |  |
| 2x2 | anonymous hidden | full+reply | yes | 2113 | 16 | 2 | - | 1389 | 1401 | yes |  |
| 2x2 | anonymous hidden | full+2tree | yes | 2052 | 17 | 2 | - | 1295 | 1308 | yes |  |
| 2x2 | anonymous public owners | min | yes | 1516 | 10 | 1 | - | 1067 | 1090 | yes |  |
| 2x2 | anonymous public owners | full | yes | 2143 | 20 | 3 | 2 | 1226 | 1207 | yes |  |
| 2x2 | anonymous public owners | full+spl | yes | 2511 | 27 | 3 | - | 1358 | 1211 | yes |  |
| 2x2 | anonymous public owners | full+data | yes | 2217 | 20 | 3 | - | 1300 | 1277 | yes |  |
| 2x2 | anonymous public owners | full+reply | yes | 2242 | 20 | 3 | - | 1325 | 1304 | yes |  |
| 2x2 | anonymous public owners | full+2tree | yes | 2181 | 21 | 3 | - | 1231 | 1211 | yes |  |
| 2x2 | confidential entry | min | yes | 1668 | 10 | 1 | - | 1219 | 1234 | yes |  |
| 2x2 | confidential entry | full | yes | 2295 | 20 | 3 | 2 | 1378 | 1351 | yes |  |
| 2x2 | confidential entry | full+spl | yes | 2663 | 27 | 3 | - | 1510 | 1355 | yes |  |
| 2x2 | confidential entry | full+data | yes | 2369 | 20 | 3 | - | 1452 | 1421 | yes |  |
| 2x2 | confidential entry | full+reply | yes | 2295 | 20 | 3 | - | 1378 | 1351 | yes |  |
| 2x2 | confidential entry | full+2tree | yes | 2333 | 21 | 3 | - | 1383 | 1355 | yes |  |
| 2x2 | anonymous entry | min | yes | 1891 | 10 | 1 | - | 1443 | 1467 | yes |  |
| 2x2 | anonymous entry | full | yes | 2326 | 16 | 2 | 2 | 1602 | 1584 | yes |  |
| 2x2 | anonymous entry | full+spl | yes | 2694 | 23 | 2 | - | 1734 | 1588 | yes |  |
| 2x2 | anonymous entry | full+data | yes | 2400 | 16 | 2 | - | 1676 | 1654 | yes |  |
| 2x2 | anonymous entry | full+reply | yes | 2425 | 16 | 2 | - | 1701 | 1681 | yes |  |
| 2x2 | anonymous entry | full+2tree | yes | 2364 | 17 | 2 | - | 1607 | 1588 | yes |  |
| 2x2 | delegate | min | yes | 1388 | 10 | 1 | - | 939 | 954 | yes |  |
| 2x2 | delegate | full | yes | 1803 | 16 | 2 | - | 1082 | 1071 | yes |  |
| 2x2 | delegate | full+spl | yes | 2043 | 23 | 2 | - | 1086 | 1075 | yes |  |
| 2x2 | delegate | full+data | yes | 1877 | 16 | 2 | - | 1156 | 1141 | yes |  |
| 2x2 | delegate | full+reply | yes | 1803 | 16 | 2 | - | 1082 | 1071 | yes |  |
| 2x2 | delegate | full+2tree | yes | 1841 | 17 | 2 | - | 1087 | 1075 | yes |  |
| 2x2 | anonymous delegate | min | yes | 1516 | 10 | 1 | - | 1067 | 1090 | yes |  |
| 2x2 | anonymous delegate | full | yes | 1931 | 16 | 2 | - | 1210 | 1207 | yes |  |
| 2x2 | anonymous delegate | full+spl | yes | 2171 | 23 | 2 | - | 1214 | 1211 | yes |  |
| 2x2 | anonymous delegate | full+data | yes | 2005 | 16 | 2 | - | 1284 | 1277 | yes |  |
| 2x2 | anonymous delegate | full+reply | yes | 2030 | 16 | 2 | - | 1309 | 1304 | yes |  |
| 2x2 | anonymous delegate | full+2tree | yes | 1969 | 17 | 2 | - | 1215 | 1211 | yes |  |
| 2x4 | confidential signer | min | yes | 1806 | 10 | 1 | - | 1357 | 1444 | yes |  |
| 2x4 | confidential signer | full | yes | 2433 | 20 | 3 | 2 | 1516 | 1561 | yes |  |
| 2x4 | confidential signer | full+spl | yes | 2801 | 27 | 3 | - | 1648 | 1565 | yes |  |
| 2x4 | confidential signer | full+data | yes | 2581 | 20 | 3 | - | 1664 | 1701 | yes |  |
| 2x4 | confidential signer | full+reply | yes | 2433 | 20 | 3 | - | 1516 | 1561 | yes |  |
| 2x4 | confidential signer | full+2tree | yes | 2471 | 21 | 3 | - | 1521 | 1565 | yes |  |
| 2x4 | confidential in-proof | min | yes | 1901 | 10 | 1 | - | 1453 | 1541 | yes |  |
| 2x4 | confidential in-proof | full | yes | 2432 | 19 | 2 | 2 | 1612 | 1658 | yes |  |
| 2x4 | confidential in-proof | full+spl | yes | 2800 | 26 | 2 | - | 1744 | 1662 | yes |  |
| 2x4 | confidential in-proof | full+data | yes | 2580 | 19 | 2 | - | 1760 | 1798 | yes |  |
| 2x4 | confidential in-proof | full+reply | yes | 2432 | 19 | 2 | - | 1612 | 1658 | yes |  |
| 2x4 | confidential in-proof | full+2tree | yes | 2470 | 20 | 2 | - | 1617 | 1662 | yes |  |
| 2x4 | anonymous hidden | min | yes | 2061 | 10 | 1 | - | 1613 | 1741 | yes |  |
| 2x4 | anonymous hidden | full | yes | 2496 | 16 | 2 | 2 | 1772 | 1858 | yes |  |
| 2x4 | anonymous hidden | full+spl | yes | 2864 | 23 | 2 | - | 1904 | 1862 | yes |  |
| 2x4 | anonymous hidden | full+data | yes | 2644 | 16 | 2 | - | 1920 | 1998 | yes |  |
| 2x4 | anonymous hidden | full+reply | yes | 2789 | 16 | 2 | - | 2065 | 2149 | yes |  |
| 2x4 | anonymous hidden | full+2tree | yes | 2534 | 17 | 2 | - | 1777 | 1862 | yes |  |
| 2x4 | anonymous public owners | min | yes | 1998 | 10 | 1 | - | 1549 | 1644 | yes |  |
| 2x4 | anonymous public owners | full | yes | 2625 | 20 | 3 | 2 | 1708 | 1761 | yes |  |
| 2x4 | anonymous public owners | full+spl | yes | 2993 | 27 | 3 | - | 1840 | 1765 | yes |  |
| 2x4 | anonymous public owners | full+data | yes | 2773 | 20 | 3 | - | 1856 | 1901 | yes |  |
| 2x4 | anonymous public owners | full+reply | yes | 2918 | 20 | 3 | - | 2001 | 2052 | yes |  |
| 2x4 | anonymous public owners | full+2tree | yes | 2663 | 21 | 3 | - | 1713 | 1765 | yes |  |
| 2x4 | confidential entry | min | yes | 2086 | 10 | 1 | - | 1637 | 1724 | yes |  |
| 2x4 | confidential entry | full | yes | 2713 | 20 | 3 | 2 | 1796 | 1841 | yes |  |
| 2x4 | confidential entry | full+spl | yes | 3081 | 27 | 3 | - | 1928 | 1845 | yes |  |
| 2x4 | confidential entry | full+data | yes | 2861 | 20 | 3 | - | 1944 | 1981 | yes |  |
| 2x4 | confidential entry | full+reply | yes | 2713 | 20 | 3 | - | 1796 | 1841 | yes |  |
| 2x4 | confidential entry | full+2tree | yes | 2751 | 21 | 3 | - | 1801 | 1845 | yes |  |
| 2x4 | anonymous entry | min | yes | 2373 | 10 | 1 | - | 1925 | 2021 | yes |  |
| 2x4 | anonymous entry | full | yes | 2808 | 16 | 2 | 2 | 2084 | 2138 | yes |  |
| 2x4 | anonymous entry | full+spl | yes | 3176 | 23 | 2 | - | 2216 | 2142 | yes |  |
| 2x4 | anonymous entry | full+data | yes | 2956 | 16 | 2 | - | 2232 | 2278 | yes |  |
| 2x4 | anonymous entry | full+reply | yes | 3101 | 16 | 2 | - | 2377 | 2429 | yes |  |
| 2x4 | anonymous entry | full+2tree | yes | 2846 | 17 | 2 | - | 2089 | 2142 | yes |  |
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
| 2x8 | confidential signer | min | yes | 2642 | 10 | 1 | - | 2193 | 2424 | yes |  |
| 2x8 | confidential signer | full | yes | 3269 | 20 | 3 | 2 | 2352 | 2541 | yes |  |
| 2x8 | confidential signer | full+spl | yes | 3637 | 27 | 3 | - | 2484 | 2545 | yes |  |
| 2x8 | confidential signer | full+data | yes | 3565 | 20 | 3 | - | 2648 | 2821 | yes |  |
| 2x8 | confidential signer | full+reply | yes | 3269 | 20 | 3 | - | 2352 | 2541 | yes |  |
| 2x8 | confidential signer | full+2tree | yes | 3307 | 21 | 3 | - | 2357 | 2545 | yes |  |
| 2x8 | confidential in-proof | min | yes | 2737 | 10 | 1 | - | 2289 | 2521 | yes |  |
| 2x8 | confidential in-proof | full | yes | 3268 | 19 | 2 | 2 | 2448 | 2638 | yes |  |
| 2x8 | confidential in-proof | full+spl | yes | 3636 | 26 | 2 | - | 2580 | 2642 | yes |  |
| 2x8 | confidential in-proof | full+data | yes | 3564 | 19 | 2 | - | 2744 | 2918 | yes |  |
| 2x8 | confidential in-proof | full+reply | yes | 3268 | 19 | 2 | - | 2448 | 2638 | yes |  |
| 2x8 | confidential in-proof | full+2tree | yes | 3306 | 20 | 2 | - | 2453 | 2642 | yes |  |
| 2x8 | anonymous hidden | min | yes | 3025 | 10 | 1 | - | 2577 | 2849 | yes |  |
| 2x8 | anonymous hidden | full | yes | 3460 | 16 | 2 | 2 | 2736 | 2966 | yes |  |
| 2x8 | anonymous hidden | full+spl | yes | 3828 | 23 | 2 | - | 2868 | 2970 | yes |  |
| 2x8 | anonymous hidden | full+data | yes | 3756 | 16 | 2 | - | 3032 | 3246 | yes |  |
| 2x8 | anonymous hidden | full+reply | yes | 4141 | 16 | 2 | - | 3417 | 3645 | no | 45 B |
| 2x8 | anonymous hidden | full+2tree | yes | 3498 | 17 | 2 | - | 2741 | 2970 | yes |  |
| 2x8 | anonymous public owners | min | yes | 2962 | 10 | 1 | - | 2513 | 2752 | yes |  |
| 2x8 | anonymous public owners | full | yes | 3589 | 20 | 3 | 2 | 2672 | 2869 | yes |  |
| 2x8 | anonymous public owners | full+spl | yes | 3957 | 27 | 3 | - | 2804 | 2873 | yes |  |
| 2x8 | anonymous public owners | full+data | yes | 3885 | 20 | 3 | - | 2968 | 3149 | yes |  |
| 2x8 | anonymous public owners | full+reply | yes | 4270 | 20 | 3 | - | 3353 | 3548 | no | 174 B |
| 2x8 | anonymous public owners | full+2tree | yes | 3627 | 21 | 3 | - | 2677 | 2873 | yes |  |
| 2x8 | confidential entry | min | yes | 2922 | 10 | 1 | - | 2473 | 2704 | yes |  |
| 2x8 | confidential entry | full | yes | 3549 | 20 | 3 | 2 | 2632 | 2821 | yes |  |
| 2x8 | confidential entry | full+spl | yes | 3917 | 27 | 3 | - | 2764 | 2825 | yes |  |
| 2x8 | confidential entry | full+data | yes | 3845 | 20 | 3 | - | 2928 | 3101 | yes |  |
| 2x8 | confidential entry | full+reply | yes | 3549 | 20 | 3 | - | 2632 | 2821 | yes |  |
| 2x8 | confidential entry | full+2tree | yes | 3587 | 21 | 3 | - | 2637 | 2825 | yes |  |
| 2x8 | anonymous entry | min | yes | 3337 | 10 | 1 | - | 2889 | 3129 | yes |  |
| 2x8 | anonymous entry | full | yes | 3772 | 16 | 2 | 2 | 3048 | 3246 | yes |  |
| 2x8 | anonymous entry | full+spl | yes | 4140 | 23 | 2 | - | 3180 | 3250 | no | 44 B |
| 2x8 | anonymous entry | full+data | yes | 4068 | 16 | 2 | - | 3344 | 3526 | yes |  |
| 2x8 | anonymous entry | full+reply | yes | 4453 | 16 | 2 | - | 3729 | 3925 | no | 357 B |
| 2x8 | anonymous entry | full+2tree | yes | 3810 | 17 | 2 | - | 3053 | 3250 | yes |  |
| 2x8 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 2x8 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 3x2 | confidential signer | min | yes | 1453 | 11 | 1 | - | 971 | 987 | yes |  |
| 3x2 | confidential signer | full | yes | 2080 | 21 | 3 | 3 | 1130 | 1104 | yes |  |
| 3x2 | confidential signer | full+spl | yes | 2448 | 28 | 3 | - | 1262 | 1108 | yes |  |
| 3x2 | confidential signer | full+data | yes | 2154 | 21 | 3 | - | 1204 | 1174 | yes |  |
| 3x2 | confidential signer | full+reply | yes | 2080 | 21 | 3 | - | 1130 | 1104 | yes |  |
| 3x2 | confidential signer | full+2tree | yes | 2118 | 22 | 3 | - | 1135 | 1108 | yes |  |
| 3x2 | confidential in-proof | min | yes | 1548 | 11 | 1 | - | 1067 | 1084 | yes |  |
| 3x2 | confidential in-proof | full | yes | 2079 | 20 | 2 | 3 | 1226 | 1201 | yes |  |
| 3x2 | confidential in-proof | full+spl | yes | 2447 | 27 | 2 | - | 1358 | 1205 | yes |  |
| 3x2 | confidential in-proof | full+data | yes | 2153 | 20 | 2 | - | 1300 | 1271 | yes |  |
| 3x2 | confidential in-proof | full+reply | yes | 2079 | 20 | 2 | - | 1226 | 1201 | yes |  |
| 3x2 | confidential in-proof | full+2tree | yes | 2117 | 21 | 2 | - | 1231 | 1205 | yes |  |
| 3x2 | anonymous hidden | min | yes | 1644 | 11 | 1 | - | 1163 | 1220 | yes |  |
| 3x2 | anonymous hidden | full | yes | 2079 | 17 | 2 | 3 | 1322 | 1337 | yes |  |
| 3x2 | anonymous hidden | full+spl | yes | 2447 | 24 | 2 | - | 1454 | 1341 | yes |  |
| 3x2 | anonymous hidden | full+data | yes | 2153 | 17 | 2 | - | 1396 | 1407 | yes |  |
| 3x2 | anonymous hidden | full+reply | yes | 2178 | 17 | 2 | - | 1421 | 1434 | yes |  |
| 3x2 | anonymous hidden | full+2tree | yes | 2117 | 18 | 2 | - | 1327 | 1341 | yes |  |
| 3x2 | anonymous public owners | min | yes | 1581 | 11 | 1 | - | 1099 | 1123 | yes |  |
| 3x2 | anonymous public owners | full | yes | 2208 | 21 | 3 | 3 | 1258 | 1240 | yes |  |
| 3x2 | anonymous public owners | full+spl | yes | 2576 | 28 | 3 | - | 1390 | 1244 | yes |  |
| 3x2 | anonymous public owners | full+data | yes | 2282 | 21 | 3 | - | 1332 | 1310 | yes |  |
| 3x2 | anonymous public owners | full+reply | yes | 2307 | 21 | 3 | - | 1357 | 1337 | yes |  |
| 3x2 | anonymous public owners | full+2tree | yes | 2246 | 22 | 3 | - | 1263 | 1244 | yes |  |
| 3x2 | confidential entry | min | yes | 1869 | 11 | 1 | - | 1387 | 1403 | yes |  |
| 3x2 | confidential entry | full | yes | 2496 | 21 | 3 | 3 | 1546 | 1520 | yes |  |
| 3x2 | confidential entry | full+spl | yes | 2864 | 28 | 3 | - | 1678 | 1524 | yes |  |
| 3x2 | confidential entry | full+data | yes | 2570 | 21 | 3 | - | 1620 | 1590 | yes |  |
| 3x2 | confidential entry | full+reply | yes | 2496 | 21 | 3 | - | 1546 | 1520 | yes |  |
| 3x2 | confidential entry | full+2tree | yes | 2534 | 22 | 3 | - | 1551 | 1524 | yes |  |
| 3x2 | anonymous entry | min | yes | 2092 | 11 | 1 | - | 1611 | 1636 | yes |  |
| 3x2 | anonymous entry | full | yes | 2527 | 17 | 2 | 3 | 1770 | 1753 | yes |  |
| 3x2 | anonymous entry | full+spl | yes | 2895 | 24 | 2 | - | 1902 | 1757 | yes |  |
| 3x2 | anonymous entry | full+data | yes | 2601 | 17 | 2 | - | 1844 | 1823 | yes |  |
| 3x2 | anonymous entry | full+reply | yes | 2626 | 17 | 2 | - | 1869 | 1850 | yes |  |
| 3x2 | anonymous entry | full+2tree | yes | 2565 | 18 | 2 | - | 1775 | 1757 | yes |  |
| 3x2 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 3x2 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 3x4 | confidential signer | min | yes | 1871 | 11 | 1 | - | 1389 | 1477 | yes |  |
| 3x4 | confidential signer | full | yes | 2498 | 21 | 3 | 3 | 1548 | 1594 | yes |  |
| 3x4 | confidential signer | full+spl | yes | 2866 | 28 | 3 | - | 1680 | 1598 | yes |  |
| 3x4 | confidential signer | full+data | yes | 2646 | 21 | 3 | - | 1696 | 1734 | yes |  |
| 3x4 | confidential signer | full+reply | yes | 2498 | 21 | 3 | - | 1548 | 1594 | yes |  |
| 3x4 | confidential signer | full+2tree | yes | 2536 | 22 | 3 | - | 1553 | 1598 | yes |  |
| 3x4 | confidential in-proof | min | yes | 1966 | 11 | 1 | - | 1485 | 1574 | yes |  |
| 3x4 | confidential in-proof | full | yes | 2497 | 20 | 2 | 3 | 1644 | 1691 | yes |  |
| 3x4 | confidential in-proof | full+spl | yes | 2865 | 27 | 2 | - | 1776 | 1695 | yes |  |
| 3x4 | confidential in-proof | full+data | yes | 2645 | 20 | 2 | - | 1792 | 1831 | yes |  |
| 3x4 | confidential in-proof | full+reply | yes | 2497 | 20 | 2 | - | 1644 | 1691 | yes |  |
| 3x4 | confidential in-proof | full+2tree | yes | 2535 | 21 | 2 | - | 1649 | 1695 | yes |  |
| 3x4 | anonymous hidden | min | yes | 2126 | 11 | 1 | - | 1645 | 1774 | yes |  |
| 3x4 | anonymous hidden | full | yes | 2561 | 17 | 2 | 3 | 1804 | 1891 | yes |  |
| 3x4 | anonymous hidden | full+spl | yes | 2929 | 24 | 2 | - | 1936 | 1895 | yes |  |
| 3x4 | anonymous hidden | full+data | yes | 2709 | 17 | 2 | - | 1952 | 2031 | yes |  |
| 3x4 | anonymous hidden | full+reply | yes | 2854 | 17 | 2 | - | 2097 | 2182 | yes |  |
| 3x4 | anonymous hidden | full+2tree | yes | 2599 | 18 | 2 | - | 1809 | 1895 | yes |  |
| 3x4 | anonymous public owners | min | yes | 2063 | 11 | 1 | - | 1581 | 1677 | yes |  |
| 3x4 | anonymous public owners | full | yes | 2690 | 21 | 3 | 3 | 1740 | 1794 | yes |  |
| 3x4 | anonymous public owners | full+spl | yes | 3058 | 28 | 3 | - | 1872 | 1798 | yes |  |
| 3x4 | anonymous public owners | full+data | yes | 2838 | 21 | 3 | - | 1888 | 1934 | yes |  |
| 3x4 | anonymous public owners | full+reply | yes | 2983 | 21 | 3 | - | 2033 | 2085 | yes |  |
| 3x4 | anonymous public owners | full+2tree | yes | 2728 | 22 | 3 | - | 1745 | 1798 | yes |  |
| 3x4 | confidential entry | min | yes | 2287 | 11 | 1 | - | 1805 | 1893 | yes |  |
| 3x4 | confidential entry | full | yes | 2914 | 21 | 3 | 3 | 1964 | 2010 | yes |  |
| 3x4 | confidential entry | full+spl | yes | 3282 | 28 | 3 | - | 2096 | 2014 | yes |  |
| 3x4 | confidential entry | full+data | yes | 3062 | 21 | 3 | - | 2112 | 2150 | yes |  |
| 3x4 | confidential entry | full+reply | yes | 2914 | 21 | 3 | - | 1964 | 2010 | yes |  |
| 3x4 | confidential entry | full+2tree | yes | 2952 | 22 | 3 | - | 1969 | 2014 | yes |  |
| 3x4 | anonymous entry | min | yes | 2574 | 11 | 1 | - | 2093 | 2190 | yes |  |
| 3x4 | anonymous entry | full | yes | 3009 | 17 | 2 | 3 | 2252 | 2307 | yes |  |
| 3x4 | anonymous entry | full+spl | yes | 3377 | 24 | 2 | - | 2384 | 2311 | yes |  |
| 3x4 | anonymous entry | full+data | yes | 3157 | 17 | 2 | - | 2400 | 2447 | yes |  |
| 3x4 | anonymous entry | full+reply | yes | 3302 | 17 | 2 | - | 2545 | 2598 | yes |  |
| 3x4 | anonymous entry | full+2tree | yes | 3047 | 18 | 2 | - | 2257 | 2311 | yes |  |
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
| 3x8 | confidential signer | min | yes | 2707 | 11 | 1 | - | 2225 | 2457 | yes |  |
| 3x8 | confidential signer | full | yes | 3334 | 21 | 3 | 3 | 2384 | 2574 | yes |  |
| 3x8 | confidential signer | full+spl | yes | 3702 | 28 | 3 | - | 2516 | 2578 | yes |  |
| 3x8 | confidential signer | full+data | yes | 3630 | 21 | 3 | - | 2680 | 2854 | yes |  |
| 3x8 | confidential signer | full+reply | yes | 3334 | 21 | 3 | - | 2384 | 2574 | yes |  |
| 3x8 | confidential signer | full+2tree | yes | 3372 | 22 | 3 | - | 2389 | 2578 | yes |  |
| 3x8 | confidential in-proof | min | yes | 2802 | 11 | 1 | - | 2321 | 2554 | yes |  |
| 3x8 | confidential in-proof | full | yes | 3333 | 20 | 2 | 3 | 2480 | 2671 | yes |  |
| 3x8 | confidential in-proof | full+spl | yes | 3701 | 27 | 2 | - | 2612 | 2675 | yes |  |
| 3x8 | confidential in-proof | full+data | yes | 3629 | 20 | 2 | - | 2776 | 2951 | yes |  |
| 3x8 | confidential in-proof | full+reply | yes | 3333 | 20 | 2 | - | 2480 | 2671 | yes |  |
| 3x8 | confidential in-proof | full+2tree | yes | 3371 | 21 | 2 | - | 2485 | 2675 | yes |  |
| 3x8 | anonymous hidden | min | yes | 3090 | 11 | 1 | - | 2609 | 2882 | yes |  |
| 3x8 | anonymous hidden | full | yes | 3525 | 17 | 2 | 3 | 2768 | 2999 | yes |  |
| 3x8 | anonymous hidden | full+spl | yes | 3893 | 24 | 2 | - | 2900 | 3003 | yes |  |
| 3x8 | anonymous hidden | full+data | yes | 3821 | 17 | 2 | - | 3064 | 3279 | yes |  |
| 3x8 | anonymous hidden | full+reply | yes | 4206 | 17 | 2 | - | 3449 | 3678 | no | 110 B |
| 3x8 | anonymous hidden | full+2tree | yes | 3563 | 18 | 2 | - | 2773 | 3003 | yes |  |
| 3x8 | anonymous public owners | min | yes | 3027 | 11 | 1 | - | 2545 | 2785 | yes |  |
| 3x8 | anonymous public owners | full | yes | 3654 | 21 | 3 | 3 | 2704 | 2902 | yes |  |
| 3x8 | anonymous public owners | full+spl | yes | 4022 | 28 | 3 | - | 2836 | 2906 | yes |  |
| 3x8 | anonymous public owners | full+data | yes | 3950 | 21 | 3 | - | 3000 | 3182 | yes |  |
| 3x8 | anonymous public owners | full+reply | yes | 4335 | 21 | 3 | - | 3385 | 3581 | no | 239 B |
| 3x8 | anonymous public owners | full+2tree | yes | 3692 | 22 | 3 | - | 2709 | 2906 | yes |  |
| 3x8 | confidential entry | min | yes | 3123 | 11 | 1 | - | 2641 | 2873 | yes |  |
| 3x8 | confidential entry | full | yes | 3750 | 21 | 3 | 3 | 2800 | 2990 | yes |  |
| 3x8 | confidential entry | full+spl | yes | 4118 | 28 | 3 | - | 2932 | 2994 | no | 22 B |
| 3x8 | confidential entry | full+data | yes | 4046 | 21 | 3 | - | 3096 | 3270 | yes |  |
| 3x8 | confidential entry | full+reply | yes | 3750 | 21 | 3 | - | 2800 | 2990 | yes |  |
| 3x8 | confidential entry | full+2tree | yes | 3788 | 22 | 3 | - | 2805 | 2994 | yes |  |
| 3x8 | anonymous entry | min | yes | 3538 | 11 | 1 | - | 3057 | 3298 | yes |  |
| 3x8 | anonymous entry | full | yes | 3973 | 17 | 2 | 1 | 3216 | 3415 | yes |  |
| 3x8 | anonymous entry | full+spl | yes | 4341 | 24 | 2 | - | 3348 | 3419 | no | 245 B |
| 3x8 | anonymous entry | full+data | yes | 4269 | 17 | 2 | - | 3512 | 3695 | no | 173 B |
| 3x8 | anonymous entry | full+reply | yes | 4654 | 17 | 2 | - | 3897 | 4094 | no | 558 B |
| 3x8 | anonymous entry | full+2tree | yes | 4011 | 18 | 2 | - | 3221 | 3419 | yes |  |
| 3x8 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 3x8 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 4x2 | confidential signer | min | yes | 1518 | 12 | 1 | - | 1003 | 1020 | yes |  |
| 4x2 | confidential signer | full | yes | 2145 | 22 | 3 | 4 | 1162 | 1137 | yes |  |
| 4x2 | confidential signer | full+spl | yes | 2513 | 29 | 3 | - | 1294 | 1141 | yes |  |
| 4x2 | confidential signer | full+data | yes | 2219 | 22 | 3 | - | 1236 | 1207 | yes |  |
| 4x2 | confidential signer | full+reply | yes | 2145 | 22 | 3 | - | 1162 | 1137 | yes |  |
| 4x2 | confidential signer | full+2tree | yes | 2183 | 23 | 3 | - | 1167 | 1141 | yes |  |
| 4x2 | confidential in-proof | min | yes | 1613 | 12 | 1 | - | 1099 | 1117 | yes |  |
| 4x2 | confidential in-proof | full | yes | 2144 | 21 | 2 | 4 | 1258 | 1234 | yes |  |
| 4x2 | confidential in-proof | full+spl | yes | 2512 | 28 | 2 | - | 1390 | 1238 | yes |  |
| 4x2 | confidential in-proof | full+data | yes | 2218 | 21 | 2 | - | 1332 | 1304 | yes |  |
| 4x2 | confidential in-proof | full+reply | yes | 2144 | 21 | 2 | - | 1258 | 1234 | yes |  |
| 4x2 | confidential in-proof | full+2tree | yes | 2182 | 22 | 2 | - | 1263 | 1238 | yes |  |
| 4x2 | anonymous hidden | min | yes | 1709 | 12 | 1 | - | 1195 | 1253 | yes |  |
| 4x2 | anonymous hidden | full | yes | 2144 | 18 | 2 | 4 | 1354 | 1370 | yes |  |
| 4x2 | anonymous hidden | full+spl | yes | 2512 | 25 | 2 | - | 1486 | 1374 | yes |  |
| 4x2 | anonymous hidden | full+data | yes | 2218 | 18 | 2 | - | 1428 | 1440 | yes |  |
| 4x2 | anonymous hidden | full+reply | yes | 2243 | 18 | 2 | - | 1453 | 1467 | yes |  |
| 4x2 | anonymous hidden | full+2tree | yes | 2182 | 19 | 2 | - | 1359 | 1374 | yes |  |
| 4x2 | anonymous public owners | min | yes | 1646 | 12 | 1 | - | 1131 | 1156 | yes |  |
| 4x2 | anonymous public owners | full | yes | 2273 | 22 | 3 | 4 | 1290 | 1273 | yes |  |
| 4x2 | anonymous public owners | full+spl | yes | 2641 | 29 | 3 | - | 1422 | 1277 | yes |  |
| 4x2 | anonymous public owners | full+data | yes | 2347 | 22 | 3 | - | 1364 | 1343 | yes |  |
| 4x2 | anonymous public owners | full+reply | yes | 2372 | 22 | 3 | - | 1389 | 1370 | yes |  |
| 4x2 | anonymous public owners | full+2tree | yes | 2311 | 23 | 3 | - | 1295 | 1277 | yes |  |
| 4x2 | confidential entry | min | yes | 2070 | 12 | 1 | - | 1555 | 1572 | yes |  |
| 4x2 | confidential entry | full | yes | 2697 | 22 | 3 | 4 | 1714 | 1689 | yes |  |
| 4x2 | confidential entry | full+spl | yes | 3065 | 29 | 3 | - | 1846 | 1693 | yes |  |
| 4x2 | confidential entry | full+data | yes | 2771 | 22 | 3 | - | 1788 | 1759 | yes |  |
| 4x2 | confidential entry | full+reply | yes | 2697 | 22 | 3 | - | 1714 | 1689 | yes |  |
| 4x2 | confidential entry | full+2tree | yes | 2735 | 23 | 3 | - | 1719 | 1693 | yes |  |
| 4x2 | anonymous entry | min | yes | 2293 | 12 | 1 | - | 1779 | 1805 | yes |  |
| 4x2 | anonymous entry | full | yes | 2728 | 18 | 2 | 4 | 1938 | 1922 | yes |  |
| 4x2 | anonymous entry | full+spl | yes | 3096 | 25 | 2 | - | 2070 | 1926 | yes |  |
| 4x2 | anonymous entry | full+data | yes | 2802 | 18 | 2 | - | 2012 | 1992 | yes |  |
| 4x2 | anonymous entry | full+reply | yes | 2827 | 18 | 2 | - | 2037 | 2019 | yes |  |
| 4x2 | anonymous entry | full+2tree | yes | 2766 | 19 | 2 | - | 1943 | 1926 | yes |  |
| 4x2 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 4x2 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 4x4 | confidential signer | min | yes | 1936 | 12 | 1 | - | 1421 | 1510 | yes |  |
| 4x4 | confidential signer | full | yes | 2563 | 22 | 3 | 4 | 1580 | 1627 | yes |  |
| 4x4 | confidential signer | full+spl | yes | 2931 | 29 | 3 | - | 1712 | 1631 | yes |  |
| 4x4 | confidential signer | full+data | yes | 2711 | 22 | 3 | - | 1728 | 1767 | yes |  |
| 4x4 | confidential signer | full+reply | yes | 2563 | 22 | 3 | - | 1580 | 1627 | yes |  |
| 4x4 | confidential signer | full+2tree | yes | 2601 | 23 | 3 | - | 1585 | 1631 | yes |  |
| 4x4 | confidential in-proof | min | yes | 2031 | 12 | 1 | - | 1517 | 1607 | yes |  |
| 4x4 | confidential in-proof | full | yes | 2562 | 21 | 2 | 4 | 1676 | 1724 | yes |  |
| 4x4 | confidential in-proof | full+spl | yes | 2930 | 28 | 2 | - | 1808 | 1728 | yes |  |
| 4x4 | confidential in-proof | full+data | yes | 2710 | 21 | 2 | - | 1824 | 1864 | yes |  |
| 4x4 | confidential in-proof | full+reply | yes | 2562 | 21 | 2 | - | 1676 | 1724 | yes |  |
| 4x4 | confidential in-proof | full+2tree | yes | 2600 | 22 | 2 | - | 1681 | 1728 | yes |  |
| 4x4 | anonymous hidden | min | yes | 2191 | 12 | 1 | - | 1677 | 1807 | yes |  |
| 4x4 | anonymous hidden | full | yes | 2626 | 18 | 2 | 4 | 1836 | 1924 | yes |  |
| 4x4 | anonymous hidden | full+spl | yes | 2994 | 25 | 2 | - | 1968 | 1928 | yes |  |
| 4x4 | anonymous hidden | full+data | yes | 2774 | 18 | 2 | - | 1984 | 2064 | yes |  |
| 4x4 | anonymous hidden | full+reply | yes | 2919 | 18 | 2 | - | 2129 | 2215 | yes |  |
| 4x4 | anonymous hidden | full+2tree | yes | 2664 | 19 | 2 | - | 1841 | 1928 | yes |  |
| 4x4 | anonymous public owners | min | yes | 2128 | 12 | 1 | - | 1613 | 1710 | yes |  |
| 4x4 | anonymous public owners | full | yes | 2755 | 22 | 3 | 4 | 1772 | 1827 | yes |  |
| 4x4 | anonymous public owners | full+spl | yes | 3123 | 29 | 3 | - | 1904 | 1831 | yes |  |
| 4x4 | anonymous public owners | full+data | yes | 2903 | 22 | 3 | - | 1920 | 1967 | yes |  |
| 4x4 | anonymous public owners | full+reply | yes | 3048 | 22 | 3 | - | 2065 | 2118 | yes |  |
| 4x4 | anonymous public owners | full+2tree | yes | 2793 | 23 | 3 | - | 1777 | 1831 | yes |  |
| 4x4 | confidential entry | min | yes | 2488 | 12 | 1 | - | 1973 | 2062 | yes |  |
| 4x4 | confidential entry | full | yes | 3115 | 22 | 3 | 4 | 2132 | 2179 | yes |  |
| 4x4 | confidential entry | full+spl | yes | 3483 | 29 | 3 | - | 2264 | 2183 | yes |  |
| 4x4 | confidential entry | full+data | yes | 3263 | 22 | 3 | - | 2280 | 2319 | yes |  |
| 4x4 | confidential entry | full+reply | yes | 3115 | 22 | 3 | - | 2132 | 2179 | yes |  |
| 4x4 | confidential entry | full+2tree | yes | 3153 | 23 | 3 | - | 2137 | 2183 | yes |  |
| 4x4 | anonymous entry | min | yes | 2775 | 12 | 1 | - | 2261 | 2359 | yes |  |
| 4x4 | anonymous entry | full | yes | 3210 | 18 | 2 | 4 | 2420 | 2476 | yes |  |
| 4x4 | anonymous entry | full+spl | yes | 3578 | 25 | 2 | - | 2552 | 2480 | yes |  |
| 4x4 | anonymous entry | full+data | yes | 3358 | 18 | 2 | - | 2568 | 2616 | yes |  |
| 4x4 | anonymous entry | full+reply | yes | 3503 | 18 | 2 | - | 2713 | 2767 | yes |  |
| 4x4 | anonymous entry | full+2tree | yes | 3248 | 19 | 2 | - | 2425 | 2480 | yes |  |
| 4x4 | delegate | min | yes | 1936 | 12 | 1 | - | 1421 | 1510 | yes |  |
| 4x4 | delegate | full | yes | 2351 | 18 | 2 | - | 1564 | 1627 | yes |  |
| 4x4 | delegate | full+spl | yes | 2591 | 25 | 2 | - | 1568 | 1631 | yes |  |
| 4x4 | delegate | full+data | yes | 2499 | 18 | 2 | - | 1712 | 1767 | yes |  |
| 4x4 | delegate | full+reply | yes | 2351 | 18 | 2 | - | 1564 | 1627 | yes |  |
| 4x4 | delegate | full+2tree | yes | 2389 | 19 | 2 | - | 1569 | 1631 | yes |  |
| 4x4 | anonymous delegate | min | yes | 2128 | 12 | 1 | - | 1613 | 1710 | yes |  |
| 4x4 | anonymous delegate | full | yes | 2543 | 18 | 2 | - | 1756 | 1827 | yes |  |
| 4x4 | anonymous delegate | full+spl | yes | 2783 | 25 | 2 | - | 1760 | 1831 | yes |  |
| 4x4 | anonymous delegate | full+data | yes | 2691 | 18 | 2 | - | 1904 | 1967 | yes |  |
| 4x4 | anonymous delegate | full+reply | yes | 2836 | 18 | 2 | - | 2049 | 2118 | yes |  |
| 4x4 | anonymous delegate | full+2tree | yes | 2581 | 19 | 2 | - | 1761 | 1831 | yes |  |
| 4x8 | confidential signer | min | yes | 2772 | 12 | 1 | - | 2257 | 2490 | yes |  |
| 4x8 | confidential signer | full | yes | 3399 | 22 | 3 | 4 | 2416 | 2607 | yes |  |
| 4x8 | confidential signer | full+spl | yes | 3767 | 29 | 3 | - | 2548 | 2611 | yes |  |
| 4x8 | confidential signer | full+data | yes | 3695 | 22 | 3 | - | 2712 | 2887 | yes |  |
| 4x8 | confidential signer | full+reply | yes | 3399 | 22 | 3 | - | 2416 | 2607 | yes |  |
| 4x8 | confidential signer | full+2tree | yes | 3437 | 23 | 3 | - | 2421 | 2611 | yes |  |
| 4x8 | confidential in-proof | min | yes | 2867 | 12 | 1 | - | 2353 | 2587 | yes |  |
| 4x8 | confidential in-proof | full | yes | 3398 | 21 | 2 | 4 | 2512 | 2704 | yes |  |
| 4x8 | confidential in-proof | full+spl | yes | 3766 | 28 | 2 | - | 2644 | 2708 | yes |  |
| 4x8 | confidential in-proof | full+data | yes | 3694 | 21 | 2 | - | 2808 | 2984 | yes |  |
| 4x8 | confidential in-proof | full+reply | yes | 3398 | 21 | 2 | - | 2512 | 2704 | yes |  |
| 4x8 | confidential in-proof | full+2tree | yes | 3436 | 22 | 2 | - | 2517 | 2708 | yes |  |
| 4x8 | anonymous hidden | min | yes | 3155 | 12 | 1 | - | 2641 | 2915 | yes |  |
| 4x8 | anonymous hidden | full | yes | 3590 | 18 | 2 | 4 | 2800 | 3032 | yes |  |
| 4x8 | anonymous hidden | full+spl | yes | 3958 | 25 | 2 | - | 2932 | 3036 | yes |  |
| 4x8 | anonymous hidden | full+data | yes | 3886 | 18 | 2 | - | 3096 | 3312 | yes |  |
| 4x8 | anonymous hidden | full+reply | yes | 4271 | 18 | 2 | - | 3481 | 3711 | no | 175 B |
| 4x8 | anonymous hidden | full+2tree | yes | 3628 | 19 | 2 | - | 2805 | 3036 | yes |  |
| 4x8 | anonymous public owners | min | yes | 3092 | 12 | 1 | - | 2577 | 2818 | yes |  |
| 4x8 | anonymous public owners | full | yes | 3719 | 22 | 3 | 4 | 2736 | 2935 | yes |  |
| 4x8 | anonymous public owners | full+spl | yes | 4087 | 29 | 3 | - | 2868 | 2939 | yes |  |
| 4x8 | anonymous public owners | full+data | yes | 4015 | 22 | 3 | - | 3032 | 3215 | yes |  |
| 4x8 | anonymous public owners | full+reply | yes | 4400 | 22 | 3 | - | 3417 | 3614 | no | 304 B |
| 4x8 | anonymous public owners | full+2tree | yes | 3757 | 23 | 3 | - | 2741 | 2939 | yes |  |
| 4x8 | confidential entry | min | yes | 3324 | 12 | 1 | - | 2809 | 3042 | yes |  |
| 4x8 | confidential entry | full | yes | 3951 | 22 | 3 | 2 | 2968 | 3159 | yes |  |
| 4x8 | confidential entry | full+spl | yes | 4319 | 29 | 3 | - | 3100 | 3163 | no | 223 B |
| 4x8 | confidential entry | full+data | yes | 4247 | 22 | 3 | - | 3264 | 3439 | no | 151 B |
| 4x8 | confidential entry | full+reply | yes | 3951 | 22 | 3 | - | 2968 | 3159 | yes |  |
| 4x8 | confidential entry | full+2tree | yes | 3989 | 23 | 3 | - | 2973 | 3163 | yes |  |
| 4x8 | anonymous entry | min | yes | 3739 | 12 | 1 | - | 3225 | 3467 | yes |  |
| 4x8 | anonymous entry | full | yes | 4174 | 18 | 2 | none | 3384 | 3584 | no | 78 B |
| 4x8 | anonymous entry | full+spl | yes | 4542 | 25 | 2 | - | 3516 | 3588 | no | 446 B |
| 4x8 | anonymous entry | full+data | yes | 4470 | 18 | 2 | - | 3680 | 3864 | no | 374 B |
| 4x8 | anonymous entry | full+reply | yes | 4855 | 18 | 2 | - | 4065 | 4263 | no | 759 B |
| 4x8 | anonymous entry | full+2tree | yes | 4212 | 19 | 2 | - | 3389 | 3588 | no | 116 B |
| 4x8 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 4x8 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 5x2 | confidential signer | min | yes | 1583 | 13 | 1 | - | 1035 | 1053 | yes |  |
| 5x2 | confidential signer | full | yes | 2210 | 23 | 3 | 5 | 1194 | 1170 | yes |  |
| 5x2 | confidential signer | full+spl | yes | 2578 | 30 | 3 | - | 1326 | 1174 | yes |  |
| 5x2 | confidential signer | full+data | yes | 2284 | 23 | 3 | - | 1268 | 1240 | yes |  |
| 5x2 | confidential signer | full+reply | yes | 2210 | 23 | 3 | - | 1194 | 1170 | yes |  |
| 5x2 | confidential signer | full+2tree | yes | 2248 | 24 | 3 | - | 1199 | 1174 | yes |  |
| 5x2 | confidential in-proof | min | yes | 1678 | 13 | 1 | - | 1131 | 1150 | yes |  |
| 5x2 | confidential in-proof | full | yes | 2209 | 22 | 2 | 5 | 1290 | 1267 | yes |  |
| 5x2 | confidential in-proof | full+spl | yes | 2577 | 29 | 2 | - | 1422 | 1271 | yes |  |
| 5x2 | confidential in-proof | full+data | yes | 2283 | 22 | 2 | - | 1364 | 1337 | yes |  |
| 5x2 | confidential in-proof | full+reply | yes | 2209 | 22 | 2 | - | 1290 | 1267 | yes |  |
| 5x2 | confidential in-proof | full+2tree | yes | 2247 | 23 | 2 | - | 1295 | 1271 | yes |  |
| 5x2 | anonymous hidden | min | yes | 1774 | 13 | 1 | - | 1227 | 1286 | yes |  |
| 5x2 | anonymous hidden | full | yes | 2209 | 19 | 2 | 5 | 1386 | 1403 | yes |  |
| 5x2 | anonymous hidden | full+spl | yes | 2577 | 26 | 2 | - | 1518 | 1407 | yes |  |
| 5x2 | anonymous hidden | full+data | yes | 2283 | 19 | 2 | - | 1460 | 1473 | yes |  |
| 5x2 | anonymous hidden | full+reply | yes | 2308 | 19 | 2 | - | 1485 | 1500 | yes |  |
| 5x2 | anonymous hidden | full+2tree | yes | 2247 | 20 | 2 | - | 1391 | 1407 | yes |  |
| 5x2 | anonymous public owners | min | yes | 1711 | 13 | 1 | - | 1163 | 1189 | yes |  |
| 5x2 | anonymous public owners | full | yes | 2338 | 23 | 3 | 5 | 1322 | 1306 | yes |  |
| 5x2 | anonymous public owners | full+spl | yes | 2706 | 30 | 3 | - | 1454 | 1310 | yes |  |
| 5x2 | anonymous public owners | full+data | yes | 2412 | 23 | 3 | - | 1396 | 1376 | yes |  |
| 5x2 | anonymous public owners | full+reply | yes | 2437 | 23 | 3 | - | 1421 | 1403 | yes |  |
| 5x2 | anonymous public owners | full+2tree | yes | 2376 | 24 | 3 | - | 1327 | 1310 | yes |  |
| 5x2 | confidential entry | min | yes | 2271 | 13 | 1 | - | 1723 | 1741 | yes |  |
| 5x2 | confidential entry | full | yes | 2898 | 23 | 3 | 5 | 1882 | 1858 | yes |  |
| 5x2 | confidential entry | full+spl | yes | 3266 | 30 | 3 | - | 2014 | 1862 | yes |  |
| 5x2 | confidential entry | full+data | yes | 2972 | 23 | 3 | - | 1956 | 1928 | yes |  |
| 5x2 | confidential entry | full+reply | yes | 2898 | 23 | 3 | - | 1882 | 1858 | yes |  |
| 5x2 | confidential entry | full+2tree | yes | 2936 | 24 | 3 | - | 1887 | 1862 | yes |  |
| 5x2 | anonymous entry | min | yes | 2494 | 13 | 1 | - | 1947 | 1974 | yes |  |
| 5x2 | anonymous entry | full | yes | 2929 | 19 | 2 | 5 | 2106 | 2091 | yes |  |
| 5x2 | anonymous entry | full+spl | yes | 3297 | 26 | 2 | - | 2238 | 2095 | yes |  |
| 5x2 | anonymous entry | full+data | yes | 3003 | 19 | 2 | - | 2180 | 2161 | yes |  |
| 5x2 | anonymous entry | full+reply | yes | 3028 | 19 | 2 | - | 2205 | 2188 | yes |  |
| 5x2 | anonymous entry | full+2tree | yes | 2967 | 20 | 2 | - | 2111 | 2095 | yes |  |
| 5x2 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 5x2 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 5x4 | confidential signer | min | yes | 2001 | 13 | 1 | - | 1453 | 1543 | yes |  |
| 5x4 | confidential signer | full | yes | 2628 | 23 | 3 | 5 | 1612 | 1660 | yes |  |
| 5x4 | confidential signer | full+spl | yes | 2996 | 30 | 3 | - | 1744 | 1664 | yes |  |
| 5x4 | confidential signer | full+data | yes | 2776 | 23 | 3 | - | 1760 | 1800 | yes |  |
| 5x4 | confidential signer | full+reply | yes | 2628 | 23 | 3 | - | 1612 | 1660 | yes |  |
| 5x4 | confidential signer | full+2tree | yes | 2666 | 24 | 3 | - | 1617 | 1664 | yes |  |
| 5x4 | confidential in-proof | min | yes | 2096 | 13 | 1 | - | 1549 | 1640 | yes |  |
| 5x4 | confidential in-proof | full | yes | 2627 | 22 | 2 | 5 | 1708 | 1757 | yes |  |
| 5x4 | confidential in-proof | full+spl | yes | 2995 | 29 | 2 | - | 1840 | 1761 | yes |  |
| 5x4 | confidential in-proof | full+data | yes | 2775 | 22 | 2 | - | 1856 | 1897 | yes |  |
| 5x4 | confidential in-proof | full+reply | yes | 2627 | 22 | 2 | - | 1708 | 1757 | yes |  |
| 5x4 | confidential in-proof | full+2tree | yes | 2665 | 23 | 2 | - | 1713 | 1761 | yes |  |
| 5x4 | anonymous hidden | min | yes | 2256 | 13 | 1 | - | 1709 | 1840 | yes |  |
| 5x4 | anonymous hidden | full | yes | 2691 | 19 | 2 | 5 | 1868 | 1957 | yes |  |
| 5x4 | anonymous hidden | full+spl | yes | 3059 | 26 | 2 | - | 2000 | 1961 | yes |  |
| 5x4 | anonymous hidden | full+data | yes | 2839 | 19 | 2 | - | 2016 | 2097 | yes |  |
| 5x4 | anonymous hidden | full+reply | yes | 2984 | 19 | 2 | - | 2161 | 2248 | yes |  |
| 5x4 | anonymous hidden | full+2tree | yes | 2729 | 20 | 2 | - | 1873 | 1961 | yes |  |
| 5x4 | anonymous public owners | min | yes | 2193 | 13 | 1 | - | 1645 | 1743 | yes |  |
| 5x4 | anonymous public owners | full | yes | 2820 | 23 | 3 | 5 | 1804 | 1860 | yes |  |
| 5x4 | anonymous public owners | full+spl | yes | 3188 | 30 | 3 | - | 1936 | 1864 | yes |  |
| 5x4 | anonymous public owners | full+data | yes | 2968 | 23 | 3 | - | 1952 | 2000 | yes |  |
| 5x4 | anonymous public owners | full+reply | yes | 3113 | 23 | 3 | - | 2097 | 2151 | yes |  |
| 5x4 | anonymous public owners | full+2tree | yes | 2858 | 24 | 3 | - | 1809 | 1864 | yes |  |
| 5x4 | confidential entry | min | yes | 2689 | 13 | 1 | - | 2141 | 2231 | yes |  |
| 5x4 | confidential entry | full | yes | 3316 | 23 | 3 | 5 | 2300 | 2348 | yes |  |
| 5x4 | confidential entry | full+spl | yes | 3684 | 30 | 3 | - | 2432 | 2352 | yes |  |
| 5x4 | confidential entry | full+data | yes | 3464 | 23 | 3 | - | 2448 | 2488 | yes |  |
| 5x4 | confidential entry | full+reply | yes | 3316 | 23 | 3 | - | 2300 | 2348 | yes |  |
| 5x4 | confidential entry | full+2tree | yes | 3354 | 24 | 3 | - | 2305 | 2352 | yes |  |
| 5x4 | anonymous entry | min | yes | 2976 | 13 | 1 | - | 2429 | 2528 | yes |  |
| 5x4 | anonymous entry | full | yes | 3411 | 19 | 2 | 5 | 2588 | 2645 | yes |  |
| 5x4 | anonymous entry | full+spl | yes | 3779 | 26 | 2 | - | 2720 | 2649 | yes |  |
| 5x4 | anonymous entry | full+data | yes | 3559 | 19 | 2 | - | 2736 | 2785 | yes |  |
| 5x4 | anonymous entry | full+reply | yes | 3704 | 19 | 2 | - | 2881 | 2936 | yes |  |
| 5x4 | anonymous entry | full+2tree | yes | 3449 | 20 | 2 | - | 2593 | 2649 | yes |  |
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
| 5x8 | confidential signer | min | yes | 2837 | 13 | 1 | - | 2289 | 2523 | yes |  |
| 5x8 | confidential signer | full | yes | 3464 | 23 | 3 | 5 | 2448 | 2640 | yes |  |
| 5x8 | confidential signer | full+spl | yes | 3832 | 30 | 3 | - | 2580 | 2644 | yes |  |
| 5x8 | confidential signer | full+data | yes | 3760 | 23 | 3 | - | 2744 | 2920 | yes |  |
| 5x8 | confidential signer | full+reply | yes | 3464 | 23 | 3 | - | 2448 | 2640 | yes |  |
| 5x8 | confidential signer | full+2tree | yes | 3502 | 24 | 3 | - | 2453 | 2644 | yes |  |
| 5x8 | confidential in-proof | min | yes | 2932 | 13 | 1 | - | 2385 | 2620 | yes |  |
| 5x8 | confidential in-proof | full | yes | 3463 | 22 | 2 | 5 | 2544 | 2737 | yes |  |
| 5x8 | confidential in-proof | full+spl | yes | 3831 | 29 | 2 | - | 2676 | 2741 | yes |  |
| 5x8 | confidential in-proof | full+data | yes | 3759 | 22 | 2 | - | 2840 | 3017 | yes |  |
| 5x8 | confidential in-proof | full+reply | yes | 3463 | 22 | 2 | - | 2544 | 2737 | yes |  |
| 5x8 | confidential in-proof | full+2tree | yes | 3501 | 23 | 2 | - | 2549 | 2741 | yes |  |
| 5x8 | anonymous hidden | min | yes | 3220 | 13 | 1 | - | 2673 | 2948 | yes |  |
| 5x8 | anonymous hidden | full | yes | 3655 | 19 | 2 | 4 | 2832 | 3065 | yes |  |
| 5x8 | anonymous hidden | full+spl | yes | 4023 | 26 | 2 | - | 2964 | 3069 | yes |  |
| 5x8 | anonymous hidden | full+data | yes | 3951 | 19 | 2 | - | 3128 | 3345 | yes |  |
| 5x8 | anonymous hidden | full+reply | yes | 4336 | 19 | 2 | - | 3513 | 3744 | no | 240 B |
| 5x8 | anonymous hidden | full+2tree | yes | 3693 | 20 | 2 | - | 2837 | 3069 | yes |  |
| 5x8 | anonymous public owners | min | yes | 3157 | 13 | 1 | - | 2609 | 2851 | yes |  |
| 5x8 | anonymous public owners | full | yes | 3784 | 23 | 3 | 4 | 2768 | 2968 | yes |  |
| 5x8 | anonymous public owners | full+spl | yes | 4152 | 30 | 3 | - | 2900 | 2972 | no | 56 B |
| 5x8 | anonymous public owners | full+data | yes | 4080 | 23 | 3 | - | 3064 | 3248 | yes |  |
| 5x8 | anonymous public owners | full+reply | yes | 4465 | 23 | 3 | - | 3449 | 3647 | no | 369 B |
| 5x8 | anonymous public owners | full+2tree | yes | 3822 | 24 | 3 | - | 2773 | 2972 | yes |  |
| 5x8 | confidential entry | min | yes | 3525 | 13 | 1 | - | 2977 | 3211 | yes |  |
| 5x8 | confidential entry | full | yes | 4152 | 23 | 3 | none | 3136 | 3328 | no | 56 B |
| 5x8 | confidential entry | full+spl | yes | 4520 | 30 | 3 | - | 3268 | 3332 | no | 424 B |
| 5x8 | confidential entry | full+data | yes | 4448 | 23 | 3 | - | 3432 | 3608 | no | 352 B |
| 5x8 | confidential entry | full+reply | yes | 4152 | 23 | 3 | - | 3136 | 3328 | no | 56 B |
| 5x8 | confidential entry | full+2tree | yes | 4190 | 24 | 3 | - | 3141 | 3332 | no | 94 B |
| 5x8 | anonymous entry | min | yes | 3940 | 13 | 1 | - | 3393 | 3636 | yes |  |
| 5x8 | anonymous entry | full | yes | 4375 | 19 | 2 | none | 3552 | 3753 | no | 279 B |
| 5x8 | anonymous entry | full+spl | yes | 4743 | 26 | 2 | - | 3684 | 3757 | no | 647 B |
| 5x8 | anonymous entry | full+data | yes | 4671 | 19 | 2 | - | 3848 | 4033 | no | 575 B |
| 5x8 | anonymous entry | full+reply | yes | 5056 | 19 | 2 | - | 4233 | 4432 | no | 960 B |
| 5x8 | anonymous entry | full+2tree | yes | 4413 | 20 | 2 | - | 3557 | 3757 | no | 317 B |
| 5x8 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 5x8 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 6x2 | confidential signer | min | yes | 1648 | 14 | 1 | - | 1067 | 1086 | yes |  |
| 6x2 | confidential signer | full | yes | 2275 | 24 | 3 | 6 | 1226 | 1203 | yes |  |
| 6x2 | confidential signer | full+spl | yes | 2643 | 31 | 3 | - | 1358 | 1207 | yes |  |
| 6x2 | confidential signer | full+data | yes | 2349 | 24 | 3 | - | 1300 | 1273 | yes |  |
| 6x2 | confidential signer | full+reply | yes | 2275 | 24 | 3 | - | 1226 | 1203 | yes |  |
| 6x2 | confidential signer | full+2tree | yes | 2313 | 25 | 3 | - | 1231 | 1207 | yes |  |
| 6x2 | confidential in-proof | min | yes | 1743 | 14 | 1 | - | 1163 | 1183 | yes |  |
| 6x2 | confidential in-proof | full | yes | 2274 | 23 | 2 | 6 | 1322 | 1300 | yes |  |
| 6x2 | confidential in-proof | full+spl | yes | 2642 | 30 | 2 | - | 1454 | 1304 | yes |  |
| 6x2 | confidential in-proof | full+data | yes | 2348 | 23 | 2 | - | 1396 | 1370 | yes |  |
| 6x2 | confidential in-proof | full+reply | yes | 2274 | 23 | 2 | - | 1322 | 1300 | yes |  |
| 6x2 | confidential in-proof | full+2tree | yes | 2312 | 24 | 2 | - | 1327 | 1304 | yes |  |
| 6x2 | anonymous hidden | min | yes | 1839 | 14 | 1 | - | 1259 | 1319 | yes |  |
| 6x2 | anonymous hidden | full | yes | 2274 | 20 | 2 | 6 | 1418 | 1436 | yes |  |
| 6x2 | anonymous hidden | full+spl | yes | 2642 | 27 | 2 | - | 1550 | 1440 | yes |  |
| 6x2 | anonymous hidden | full+data | yes | 2348 | 20 | 2 | - | 1492 | 1506 | yes |  |
| 6x2 | anonymous hidden | full+reply | yes | 2373 | 20 | 2 | - | 1517 | 1533 | yes |  |
| 6x2 | anonymous hidden | full+2tree | yes | 2312 | 21 | 2 | - | 1423 | 1440 | yes |  |
| 6x2 | anonymous public owners | min | yes | 1776 | 14 | 1 | - | 1195 | 1222 | yes |  |
| 6x2 | anonymous public owners | full | yes | 2403 | 24 | 3 | 6 | 1354 | 1339 | yes |  |
| 6x2 | anonymous public owners | full+spl | yes | 2771 | 31 | 3 | - | 1486 | 1343 | yes |  |
| 6x2 | anonymous public owners | full+data | yes | 2477 | 24 | 3 | - | 1428 | 1409 | yes |  |
| 6x2 | anonymous public owners | full+reply | yes | 2502 | 24 | 3 | - | 1453 | 1436 | yes |  |
| 6x2 | anonymous public owners | full+2tree | yes | 2441 | 25 | 3 | - | 1359 | 1343 | yes |  |
| 6x2 | confidential entry | min | yes | 2472 | 14 | 1 | - | 1891 | 1910 | yes |  |
| 6x2 | confidential entry | full | yes | 3099 | 24 | 3 | 6 | 2050 | 2027 | yes |  |
| 6x2 | confidential entry | full+spl | yes | 3467 | 31 | 3 | - | 2182 | 2031 | yes |  |
| 6x2 | confidential entry | full+data | yes | 3173 | 24 | 3 | - | 2124 | 2097 | yes |  |
| 6x2 | confidential entry | full+reply | yes | 3099 | 24 | 3 | - | 2050 | 2027 | yes |  |
| 6x2 | confidential entry | full+2tree | yes | 3137 | 25 | 3 | - | 2055 | 2031 | yes |  |
| 6x2 | anonymous entry | min | yes | 2695 | 14 | 1 | - | 2115 | 2143 | yes |  |
| 6x2 | anonymous entry | full | yes | 3130 | 20 | 2 | 6 | 2274 | 2260 | yes |  |
| 6x2 | anonymous entry | full+spl | yes | 3498 | 27 | 2 | - | 2406 | 2264 | yes |  |
| 6x2 | anonymous entry | full+data | yes | 3204 | 20 | 2 | - | 2348 | 2330 | yes |  |
| 6x2 | anonymous entry | full+reply | yes | 3229 | 20 | 2 | - | 2373 | 2357 | yes |  |
| 6x2 | anonymous entry | full+2tree | yes | 3168 | 21 | 2 | - | 2279 | 2264 | yes |  |
| 6x2 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 6x2 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 6x4 | confidential signer | min | yes | 2066 | 14 | 1 | - | 1485 | 1576 | yes |  |
| 6x4 | confidential signer | full | yes | 2693 | 24 | 3 | 6 | 1644 | 1693 | yes |  |
| 6x4 | confidential signer | full+spl | yes | 3061 | 31 | 3 | - | 1776 | 1697 | yes |  |
| 6x4 | confidential signer | full+data | yes | 2841 | 24 | 3 | - | 1792 | 1833 | yes |  |
| 6x4 | confidential signer | full+reply | yes | 2693 | 24 | 3 | - | 1644 | 1693 | yes |  |
| 6x4 | confidential signer | full+2tree | yes | 2731 | 25 | 3 | - | 1649 | 1697 | yes |  |
| 6x4 | confidential in-proof | min | yes | 2161 | 14 | 1 | - | 1581 | 1673 | yes |  |
| 6x4 | confidential in-proof | full | yes | 2692 | 23 | 2 | 6 | 1740 | 1790 | yes |  |
| 6x4 | confidential in-proof | full+spl | yes | 3060 | 30 | 2 | - | 1872 | 1794 | yes |  |
| 6x4 | confidential in-proof | full+data | yes | 2840 | 23 | 2 | - | 1888 | 1930 | yes |  |
| 6x4 | confidential in-proof | full+reply | yes | 2692 | 23 | 2 | - | 1740 | 1790 | yes |  |
| 6x4 | confidential in-proof | full+2tree | yes | 2730 | 24 | 2 | - | 1745 | 1794 | yes |  |
| 6x4 | anonymous hidden | min | yes | 2321 | 14 | 1 | - | 1741 | 1873 | yes |  |
| 6x4 | anonymous hidden | full | yes | 2756 | 20 | 2 | 6 | 1900 | 1990 | yes |  |
| 6x4 | anonymous hidden | full+spl | yes | 3124 | 27 | 2 | - | 2032 | 1994 | yes |  |
| 6x4 | anonymous hidden | full+data | yes | 2904 | 20 | 2 | - | 2048 | 2130 | yes |  |
| 6x4 | anonymous hidden | full+reply | yes | 3049 | 20 | 2 | - | 2193 | 2281 | yes |  |
| 6x4 | anonymous hidden | full+2tree | yes | 2794 | 21 | 2 | - | 1905 | 1994 | yes |  |
| 6x4 | anonymous public owners | min | yes | 2258 | 14 | 1 | - | 1677 | 1776 | yes |  |
| 6x4 | anonymous public owners | full | yes | 2885 | 24 | 3 | 6 | 1836 | 1893 | yes |  |
| 6x4 | anonymous public owners | full+spl | yes | 3253 | 31 | 3 | - | 1968 | 1897 | yes |  |
| 6x4 | anonymous public owners | full+data | yes | 3033 | 24 | 3 | - | 1984 | 2033 | yes |  |
| 6x4 | anonymous public owners | full+reply | yes | 3178 | 24 | 3 | - | 2129 | 2184 | yes |  |
| 6x4 | anonymous public owners | full+2tree | yes | 2923 | 25 | 3 | - | 1841 | 1897 | yes |  |
| 6x4 | confidential entry | min | yes | 2890 | 14 | 1 | - | 2309 | 2400 | yes |  |
| 6x4 | confidential entry | full | yes | 3517 | 24 | 3 | 6 | 2468 | 2517 | yes |  |
| 6x4 | confidential entry | full+spl | yes | 3885 | 31 | 3 | - | 2600 | 2521 | yes |  |
| 6x4 | confidential entry | full+data | yes | 3665 | 24 | 3 | - | 2616 | 2657 | yes |  |
| 6x4 | confidential entry | full+reply | yes | 3517 | 24 | 3 | - | 2468 | 2517 | yes |  |
| 6x4 | confidential entry | full+2tree | yes | 3555 | 25 | 3 | - | 2473 | 2521 | yes |  |
| 6x4 | anonymous entry | min | yes | 3177 | 14 | 1 | - | 2597 | 2697 | yes |  |
| 6x4 | anonymous entry | full | yes | 3612 | 20 | 2 | 4 | 2756 | 2814 | yes |  |
| 6x4 | anonymous entry | full+spl | yes | 3980 | 27 | 2 | - | 2888 | 2818 | yes |  |
| 6x4 | anonymous entry | full+data | yes | 3760 | 20 | 2 | - | 2904 | 2954 | yes |  |
| 6x4 | anonymous entry | full+reply | yes | 3905 | 20 | 2 | - | 3049 | 3105 | yes |  |
| 6x4 | anonymous entry | full+2tree | yes | 3650 | 21 | 2 | - | 2761 | 2818 | yes |  |
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
| 6x8 | confidential signer | min | yes | 2902 | 14 | 1 | - | 2321 | 2556 | yes |  |
| 6x8 | confidential signer | full | yes | 3529 | 24 | 3 | 6 | 2480 | 2673 | yes |  |
| 6x8 | confidential signer | full+spl | yes | 3897 | 31 | 3 | - | 2612 | 2677 | yes |  |
| 6x8 | confidential signer | full+data | yes | 3825 | 24 | 3 | - | 2776 | 2953 | yes |  |
| 6x8 | confidential signer | full+reply | yes | 3529 | 24 | 3 | - | 2480 | 2673 | yes |  |
| 6x8 | confidential signer | full+2tree | yes | 3567 | 25 | 3 | - | 2485 | 2677 | yes |  |
| 6x8 | confidential in-proof | min | yes | 2997 | 14 | 1 | - | 2417 | 2653 | yes |  |
| 6x8 | confidential in-proof | full | yes | 3528 | 23 | 2 | 5 | 2576 | 2770 | yes |  |
| 6x8 | confidential in-proof | full+spl | yes | 3896 | 30 | 2 | - | 2708 | 2774 | yes |  |
| 6x8 | confidential in-proof | full+data | yes | 3824 | 23 | 2 | - | 2872 | 3050 | yes |  |
| 6x8 | confidential in-proof | full+reply | yes | 3528 | 23 | 2 | - | 2576 | 2770 | yes |  |
| 6x8 | confidential in-proof | full+2tree | yes | 3566 | 24 | 2 | - | 2581 | 2774 | yes |  |
| 6x8 | anonymous hidden | min | yes | 3285 | 14 | 1 | - | 2705 | 2981 | yes |  |
| 6x8 | anonymous hidden | full | yes | 3720 | 20 | 2 | 3 | 2864 | 3098 | yes |  |
| 6x8 | anonymous hidden | full+spl | yes | 4088 | 27 | 2 | - | 2996 | 3102 | yes |  |
| 6x8 | anonymous hidden | full+data | yes | 4016 | 20 | 2 | - | 3160 | 3378 | yes |  |
| 6x8 | anonymous hidden | full+reply | yes | 4401 | 20 | 2 | - | 3545 | 3777 | no | 305 B |
| 6x8 | anonymous hidden | full+2tree | yes | 3758 | 21 | 2 | - | 2869 | 3102 | yes |  |
| 6x8 | anonymous public owners | min | yes | 3222 | 14 | 1 | - | 2641 | 2884 | yes |  |
| 6x8 | anonymous public owners | full | yes | 3849 | 24 | 3 | 3 | 2800 | 3001 | yes |  |
| 6x8 | anonymous public owners | full+spl | yes | 4217 | 31 | 3 | - | 2932 | 3005 | no | 121 B |
| 6x8 | anonymous public owners | full+data | yes | 4145 | 24 | 3 | - | 3096 | 3281 | no | 49 B |
| 6x8 | anonymous public owners | full+reply | yes | 4530 | 24 | 3 | - | 3481 | 3680 | no | 434 B |
| 6x8 | anonymous public owners | full+2tree | yes | 3887 | 25 | 3 | - | 2805 | 3005 | yes |  |
| 6x8 | confidential entry | min | yes | 3726 | 14 | 1 | - | 3145 | 3380 | yes |  |
| 6x8 | confidential entry | full | yes | 4353 | 24 | 3 | none | 3304 | 3497 | no | 257 B |
| 6x8 | confidential entry | full+spl | yes | 4721 | 31 | 3 | - | 3436 | 3501 | no | 625 B |
| 6x8 | confidential entry | full+data | yes | 4649 | 24 | 3 | - | 3600 | 3777 | no | 553 B |
| 6x8 | confidential entry | full+reply | yes | 4353 | 24 | 3 | - | 3304 | 3497 | no | 257 B |
| 6x8 | confidential entry | full+2tree | yes | 4391 | 25 | 3 | - | 3309 | 3501 | no | 295 B |
| 6x8 | anonymous entry | min | yes | 4141 | 14 | 1 | - | 3561 | 3805 | no | 45 B |
| 6x8 | anonymous entry | full | yes | 4576 | 20 | 2 | none | 3720 | 3922 | no | 480 B |
| 6x8 | anonymous entry | full+spl | yes | 4944 | 27 | 2 | - | 3852 | 3926 | no | 848 B |
| 6x8 | anonymous entry | full+data | yes | 4872 | 20 | 2 | - | 4016 | 4202 | no | 776 B |
| 6x8 | anonymous entry | full+reply | yes | 5257 | 20 | 2 | - | 4401 | 4601 | no | 1161 B |
| 6x8 | anonymous entry | full+2tree | yes | 4614 | 21 | 2 | - | 3725 | 3926 | no | 518 B |
| 6x8 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 6x8 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 8x2 | confidential signer | min | yes | 1778 | 16 | 1 | - | 1131 | 1152 | yes |  |
| 8x2 | confidential signer | full | yes | 2405 | 26 | 3 | 8 | 1290 | 1269 | yes |  |
| 8x2 | confidential signer | full+spl | yes | 2773 | 33 | 3 | - | 1422 | 1273 | yes |  |
| 8x2 | confidential signer | full+data | yes | 2479 | 26 | 3 | - | 1364 | 1339 | yes |  |
| 8x2 | confidential signer | full+reply | yes | 2405 | 26 | 3 | - | 1290 | 1269 | yes |  |
| 8x2 | confidential signer | full+2tree | yes | 2443 | 27 | 3 | - | 1295 | 1273 | yes |  |
| 8x2 | confidential in-proof | min | yes | 1873 | 16 | 1 | - | 1227 | 1249 | yes |  |
| 8x2 | confidential in-proof | full | yes | 2404 | 25 | 2 | 8 | 1386 | 1366 | yes |  |
| 8x2 | confidential in-proof | full+spl | yes | 2772 | 32 | 2 | - | 1518 | 1370 | yes |  |
| 8x2 | confidential in-proof | full+data | yes | 2478 | 25 | 2 | - | 1460 | 1436 | yes |  |
| 8x2 | confidential in-proof | full+reply | yes | 2404 | 25 | 2 | - | 1386 | 1366 | yes |  |
| 8x2 | confidential in-proof | full+2tree | yes | 2442 | 26 | 2 | - | 1391 | 1370 | yes |  |
| 8x2 | anonymous hidden | min | yes | 1969 | 16 | 1 | - | 1323 | 1385 | yes |  |
| 8x2 | anonymous hidden | full | yes | 2404 | 22 | 2 | 8 | 1482 | 1502 | yes |  |
| 8x2 | anonymous hidden | full+spl | yes | 2772 | 29 | 2 | - | 1614 | 1506 | yes |  |
| 8x2 | anonymous hidden | full+data | yes | 2478 | 22 | 2 | - | 1556 | 1572 | yes |  |
| 8x2 | anonymous hidden | full+reply | yes | 2503 | 22 | 2 | - | 1581 | 1599 | yes |  |
| 8x2 | anonymous hidden | full+2tree | yes | 2442 | 23 | 2 | - | 1487 | 1506 | yes |  |
| 8x2 | anonymous public owners | min | yes | 1906 | 16 | 1 | - | 1259 | 1288 | yes |  |
| 8x2 | anonymous public owners | full | yes | 2533 | 26 | 3 | 8 | 1418 | 1405 | yes |  |
| 8x2 | anonymous public owners | full+spl | yes | 2901 | 33 | 3 | - | 1550 | 1409 | yes |  |
| 8x2 | anonymous public owners | full+data | yes | 2607 | 26 | 3 | - | 1492 | 1475 | yes |  |
| 8x2 | anonymous public owners | full+reply | yes | 2632 | 26 | 3 | - | 1517 | 1502 | yes |  |
| 8x2 | anonymous public owners | full+2tree | yes | 2571 | 27 | 3 | - | 1423 | 1409 | yes |  |
| 8x2 | confidential entry | min | yes | 2874 | 16 | 1 | - | 2227 | 2248 | yes |  |
| 8x2 | confidential entry | full | yes | 3501 | 26 | 3 | 7 | 2386 | 2365 | yes |  |
| 8x2 | confidential entry | full+spl | yes | 3869 | 33 | 3 | - | 2518 | 2369 | yes |  |
| 8x2 | confidential entry | full+data | yes | 3575 | 26 | 3 | - | 2460 | 2435 | yes |  |
| 8x2 | confidential entry | full+reply | yes | 3501 | 26 | 3 | - | 2386 | 2365 | yes |  |
| 8x2 | confidential entry | full+2tree | yes | 3539 | 27 | 3 | - | 2391 | 2369 | yes |  |
| 8x2 | anonymous entry | min | yes | 3097 | 16 | 1 | - | 2451 | 2481 | yes |  |
| 8x2 | anonymous entry | full | yes | 3532 | 22 | 2 | 5 | 2610 | 2598 | yes |  |
| 8x2 | anonymous entry | full+spl | yes | 3900 | 29 | 2 | - | 2742 | 2602 | yes |  |
| 8x2 | anonymous entry | full+data | yes | 3606 | 22 | 2 | - | 2684 | 2668 | yes |  |
| 8x2 | anonymous entry | full+reply | yes | 3631 | 22 | 2 | - | 2709 | 2695 | yes |  |
| 8x2 | anonymous entry | full+2tree | yes | 3570 | 23 | 2 | - | 2615 | 2602 | yes |  |
| 8x2 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 8x2 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 8x4 | confidential signer | min | yes | 2196 | 16 | 1 | - | 1549 | 1642 | yes |  |
| 8x4 | confidential signer | full | yes | 2823 | 26 | 3 | 8 | 1708 | 1759 | yes |  |
| 8x4 | confidential signer | full+spl | yes | 3191 | 33 | 3 | - | 1840 | 1763 | yes |  |
| 8x4 | confidential signer | full+data | yes | 2971 | 26 | 3 | - | 1856 | 1899 | yes |  |
| 8x4 | confidential signer | full+reply | yes | 2823 | 26 | 3 | - | 1708 | 1759 | yes |  |
| 8x4 | confidential signer | full+2tree | yes | 2861 | 27 | 3 | - | 1713 | 1763 | yes |  |
| 8x4 | confidential in-proof | min | yes | 2291 | 16 | 1 | - | 1645 | 1739 | yes |  |
| 8x4 | confidential in-proof | full | yes | 2822 | 25 | 2 | 8 | 1804 | 1856 | yes |  |
| 8x4 | confidential in-proof | full+spl | yes | 3190 | 32 | 2 | - | 1936 | 1860 | yes |  |
| 8x4 | confidential in-proof | full+data | yes | 2970 | 25 | 2 | - | 1952 | 1996 | yes |  |
| 8x4 | confidential in-proof | full+reply | yes | 2822 | 25 | 2 | - | 1804 | 1856 | yes |  |
| 8x4 | confidential in-proof | full+2tree | yes | 2860 | 26 | 2 | - | 1809 | 1860 | yes |  |
| 8x4 | anonymous hidden | min | yes | 2451 | 16 | 1 | - | 1805 | 1939 | yes |  |
| 8x4 | anonymous hidden | full | yes | 2886 | 22 | 2 | 8 | 1964 | 2056 | yes |  |
| 8x4 | anonymous hidden | full+spl | yes | 3254 | 29 | 2 | - | 2096 | 2060 | yes |  |
| 8x4 | anonymous hidden | full+data | yes | 3034 | 22 | 2 | - | 2112 | 2196 | yes |  |
| 8x4 | anonymous hidden | full+reply | yes | 3179 | 22 | 2 | - | 2257 | 2347 | yes |  |
| 8x4 | anonymous hidden | full+2tree | yes | 2924 | 23 | 2 | - | 1969 | 2060 | yes |  |
| 8x4 | anonymous public owners | min | yes | 2388 | 16 | 1 | - | 1741 | 1842 | yes |  |
| 8x4 | anonymous public owners | full | yes | 3015 | 26 | 3 | 8 | 1900 | 1959 | yes |  |
| 8x4 | anonymous public owners | full+spl | yes | 3383 | 33 | 3 | - | 2032 | 1963 | yes |  |
| 8x4 | anonymous public owners | full+data | yes | 3163 | 26 | 3 | - | 2048 | 2099 | yes |  |
| 8x4 | anonymous public owners | full+reply | yes | 3308 | 26 | 3 | - | 2193 | 2250 | yes |  |
| 8x4 | anonymous public owners | full+2tree | yes | 3053 | 27 | 3 | - | 1905 | 1963 | yes |  |
| 8x4 | confidential entry | min | yes | 3292 | 16 | 1 | - | 2645 | 2738 | yes |  |
| 8x4 | confidential entry | full | yes | 3919 | 26 | 3 | 2 | 2804 | 2855 | yes |  |
| 8x4 | confidential entry | full+spl | yes | 4287 | 33 | 3 | - | 2936 | 2859 | no | 191 B |
| 8x4 | confidential entry | full+data | yes | 4067 | 26 | 3 | - | 2952 | 2995 | yes |  |
| 8x4 | confidential entry | full+reply | yes | 3919 | 26 | 3 | - | 2804 | 2855 | yes |  |
| 8x4 | confidential entry | full+2tree | yes | 3957 | 27 | 3 | - | 2809 | 2859 | yes |  |
| 8x4 | anonymous entry | min | yes | 3579 | 16 | 1 | - | 2933 | 3035 | yes |  |
| 8x4 | anonymous entry | full | yes | 4014 | 22 | 2 | 0 | 3092 | 3152 | yes |  |
| 8x4 | anonymous entry | full+spl | yes | 4382 | 29 | 2 | - | 3224 | 3156 | no | 286 B |
| 8x4 | anonymous entry | full+data | yes | 4162 | 22 | 2 | - | 3240 | 3292 | no | 66 B |
| 8x4 | anonymous entry | full+reply | yes | 4307 | 22 | 2 | - | 3385 | 3443 | no | 211 B |
| 8x4 | anonymous entry | full+2tree | yes | 4052 | 23 | 2 | - | 3097 | 3156 | yes |  |
| 8x4 | delegate | - | - | - | - | - | - | - | - | no | rail |
| 8x4 | anonymous delegate | - | - | - | - | - | - | - | - | no | rail |
| 8x8 | confidential signer | min | yes | 3032 | 16 | 1 | - | 2385 | 2622 | yes |  |
| 8x8 | confidential signer | full | yes | 3659 | 26 | 3 | 5 | 2544 | 2739 | yes |  |
| 8x8 | confidential signer | full+spl | yes | 4027 | 33 | 3 | - | 2676 | 2743 | yes |  |
| 8x8 | confidential signer | full+data | yes | 3955 | 26 | 3 | - | 2840 | 3019 | yes |  |
| 8x8 | confidential signer | full+reply | yes | 3659 | 26 | 3 | - | 2544 | 2739 | yes |  |
| 8x8 | confidential signer | full+2tree | yes | 3697 | 27 | 3 | - | 2549 | 2743 | yes |  |
| 8x8 | confidential in-proof | min | yes | 3127 | 16 | 1 | - | 2481 | 2719 | yes |  |
| 8x8 | confidential in-proof | full | yes | 3658 | 25 | 2 | 4 | 2640 | 2836 | yes |  |
| 8x8 | confidential in-proof | full+spl | yes | 4026 | 32 | 2 | - | 2772 | 2840 | yes |  |
| 8x8 | confidential in-proof | full+data | yes | 3954 | 25 | 2 | - | 2936 | 3116 | yes |  |
| 8x8 | confidential in-proof | full+reply | yes | 3658 | 25 | 2 | - | 2640 | 2836 | yes |  |
| 8x8 | confidential in-proof | full+2tree | yes | 3696 | 26 | 2 | - | 2645 | 2840 | yes |  |
| 8x8 | anonymous hidden | min | yes | 3415 | 16 | 1 | - | 2769 | 3047 | yes |  |
| 8x8 | anonymous hidden | full | yes | 3850 | 22 | 2 | 2 | 2928 | 3164 | yes |  |
| 8x8 | anonymous hidden | full+spl | yes | 4218 | 29 | 2 | - | 3060 | 3168 | no | 122 B |
| 8x8 | anonymous hidden | full+data | yes | 4146 | 22 | 2 | - | 3224 | 3444 | no | 50 B |
| 8x8 | anonymous hidden | full+reply | yes | 4531 | 22 | 2 | - | 3609 | 3843 | no | 435 B |
| 8x8 | anonymous hidden | full+2tree | yes | 3888 | 23 | 2 | - | 2933 | 3168 | yes |  |
| 8x8 | anonymous public owners | min | yes | 3352 | 16 | 1 | - | 2705 | 2950 | yes |  |
| 8x8 | anonymous public owners | full | yes | 3979 | 26 | 3 | 2 | 2864 | 3067 | yes |  |
| 8x8 | anonymous public owners | full+spl | yes | 4347 | 33 | 3 | - | 2996 | 3071 | no | 251 B |
| 8x8 | anonymous public owners | full+data | yes | 4275 | 26 | 3 | - | 3160 | 3347 | no | 179 B |
| 8x8 | anonymous public owners | full+reply | yes | 4660 | 26 | 3 | - | 3545 | 3746 | no | 564 B |
| 8x8 | anonymous public owners | full+2tree | yes | 4017 | 27 | 3 | - | 2869 | 3071 | yes |  |
| 8x8 | confidential entry | min | yes | 4128 | 16 | 1 | - | 3481 | 3718 | no | 32 B |
| 8x8 | confidential entry | full | yes | 4755 | 26 | 3 | none | 3640 | 3835 | no | 659 B |
| 8x8 | confidential entry | full+spl | yes | 5123 | 33 | 3 | - | 3772 | 3839 | no | 1027 B |
| 8x8 | confidential entry | full+data | yes | 5051 | 26 | 3 | - | 3936 | 4115 | no | 955 B |
| 8x8 | confidential entry | full+reply | yes | 4755 | 26 | 3 | - | 3640 | 3835 | no | 659 B |
| 8x8 | confidential entry | full+2tree | yes | 4793 | 27 | 3 | - | 3645 | 3839 | no | 697 B |
| 8x8 | anonymous entry | min | yes | 4543 | 16 | 1 | - | 3897 | 4143 | no | 447 B |
| 8x8 | anonymous entry | full | yes | 4978 | 22 | 2 | none | 4056 | 4260 | no | 882 B |
| 8x8 | anonymous entry | full+spl | yes | 5346 | 29 | 2 | - | 4188 | 4264 | no | 1250 B |
| 8x8 | anonymous entry | full+data | yes | 5274 | 22 | 2 | - | 4352 | 4540 | no | 1178 B |
| 8x8 | anonymous entry | full+reply | yes | 5659 | 22 | 2 | - | 4737 | 4939 | no | 1563 B |
| 8x8 | anonymous entry | full+2tree | yes | 5016 | 23 | 2 | - | 4061 | 4264 | no | 920 B |
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
| 12x2 | confidential signer | min | yes | 2038 | 20 | 1 | - | 1259 | 1284 | yes |  |
| 12x2 | confidential signer | full | yes | 2665 | 30 | 3 | 10 | 1418 | 1401 | yes |  |
| 12x2 | confidential signer | full+spl | yes | 3033 | 37 | 3 | - | 1550 | 1405 | yes |  |
| 12x2 | confidential signer | full+data | yes | 2739 | 30 | 3 | - | 1492 | 1471 | yes |  |
| 12x2 | confidential signer | full+reply | yes | 2665 | 30 | 3 | - | 1418 | 1401 | yes |  |
| 12x2 | confidential signer | full+2tree | yes | 2704 | 31 | 3 | - | 1424 | 1405 | yes |  |
| 12x2 | confidential in-proof | min | yes | 2133 | 20 | 1 | - | 1355 | 1381 | yes |  |
| 12x2 | confidential in-proof | full | yes | 2664 | 29 | 2 | 10 | 1514 | 1498 | yes |  |
| 12x2 | confidential in-proof | full+spl | yes | 3032 | 36 | 2 | - | 1646 | 1502 | yes |  |
| 12x2 | confidential in-proof | full+data | yes | 2738 | 29 | 2 | - | 1588 | 1568 | yes |  |
| 12x2 | confidential in-proof | full+reply | yes | 2664 | 29 | 2 | - | 1514 | 1498 | yes |  |
| 12x2 | confidential in-proof | full+2tree | yes | 2703 | 30 | 2 | - | 1520 | 1502 | yes |  |
| 12x2 | anonymous hidden | min | yes | 2229 | 20 | 1 | - | 1451 | 1517 | yes |  |
| 12x2 | anonymous hidden | full | yes | 2664 | 26 | 2 | 10 | 1610 | 1634 | yes |  |
| 12x2 | anonymous hidden | full+spl | yes | 3032 | 33 | 2 | - | 1742 | 1638 | yes |  |
| 12x2 | anonymous hidden | full+data | yes | 2738 | 26 | 2 | - | 1684 | 1704 | yes |  |
| 12x2 | anonymous hidden | full+reply | yes | 2763 | 26 | 2 | - | 1709 | 1731 | yes |  |
| 12x2 | anonymous hidden | full+2tree | yes | 2703 | 27 | 2 | - | 1616 | 1638 | yes |  |
| 12x2 | anonymous public owners | min | yes | 2166 | 20 | 1 | - | 1387 | 1420 | yes |  |
| 12x2 | anonymous public owners | full | yes | 2793 | 30 | 3 | 10 | 1546 | 1537 | yes |  |
| 12x2 | anonymous public owners | full+spl | yes | 3161 | 37 | 3 | - | 1678 | 1541 | yes |  |
| 12x2 | anonymous public owners | full+data | yes | 2867 | 30 | 3 | - | 1620 | 1607 | yes |  |
| 12x2 | anonymous public owners | full+reply | yes | 2892 | 30 | 3 | - | 1645 | 1634 | yes |  |
| 12x2 | anonymous public owners | full+2tree | yes | 2832 | 31 | 3 | - | 1552 | 1541 | yes |  |
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
| 12x4 | confidential signer | min | yes | 2456 | 20 | 1 | - | 1677 | 1774 | yes |  |
| 12x4 | confidential signer | full | yes | 3083 | 30 | 3 | 10 | 1836 | 1891 | yes |  |
| 12x4 | confidential signer | full+spl | yes | 3451 | 37 | 3 | - | 1968 | 1895 | yes |  |
| 12x4 | confidential signer | full+data | yes | 3231 | 30 | 3 | - | 1984 | 2031 | yes |  |
| 12x4 | confidential signer | full+reply | yes | 3083 | 30 | 3 | - | 1836 | 1891 | yes |  |
| 12x4 | confidential signer | full+2tree | yes | 3122 | 31 | 3 | - | 1842 | 1895 | yes |  |
| 12x4 | confidential in-proof | min | yes | 2551 | 20 | 1 | - | 1773 | 1871 | yes |  |
| 12x4 | confidential in-proof | full | yes | 3082 | 29 | 2 | 10 | 1932 | 1988 | yes |  |
| 12x4 | confidential in-proof | full+spl | yes | 3450 | 36 | 2 | - | 2064 | 1992 | yes |  |
| 12x4 | confidential in-proof | full+data | yes | 3230 | 29 | 2 | - | 2080 | 2128 | yes |  |
| 12x4 | confidential in-proof | full+reply | yes | 3082 | 29 | 2 | - | 1932 | 1988 | yes |  |
| 12x4 | confidential in-proof | full+2tree | yes | 3121 | 30 | 2 | - | 1938 | 1992 | yes |  |
| 12x4 | anonymous hidden | min | yes | 2711 | 20 | 1 | - | 1933 | 2071 | yes |  |
| 12x4 | anonymous hidden | full | yes | 3146 | 26 | 2 | 9 | 2092 | 2188 | yes |  |
| 12x4 | anonymous hidden | full+spl | yes | 3514 | 33 | 2 | - | 2224 | 2192 | yes |  |
| 12x4 | anonymous hidden | full+data | yes | 3294 | 26 | 2 | - | 2240 | 2328 | yes |  |
| 12x4 | anonymous hidden | full+reply | yes | 3439 | 26 | 2 | - | 2385 | 2479 | yes |  |
| 12x4 | anonymous hidden | full+2tree | yes | 3185 | 27 | 2 | - | 2098 | 2192 | yes |  |
| 12x4 | anonymous public owners | min | yes | 2648 | 20 | 1 | - | 1869 | 1974 | yes |  |
| 12x4 | anonymous public owners | full | yes | 3275 | 30 | 3 | 9 | 2028 | 2091 | yes |  |
| 12x4 | anonymous public owners | full+spl | yes | 3643 | 37 | 3 | - | 2160 | 2095 | yes |  |
| 12x4 | anonymous public owners | full+data | yes | 3423 | 30 | 3 | - | 2176 | 2231 | yes |  |
| 12x4 | anonymous public owners | full+reply | yes | 3568 | 30 | 3 | - | 2321 | 2382 | yes |  |
| 12x4 | anonymous public owners | full+2tree | yes | 3314 | 31 | 3 | - | 2034 | 2095 | yes |  |
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
| 12x8 | confidential signer | min | yes | 3292 | 20 | 1 | - | 2513 | 2754 | yes |  |
| 12x8 | confidential signer | full | yes | 3919 | 30 | 3 | 2 | 2672 | 2871 | yes |  |
| 12x8 | confidential signer | full+spl | yes | 4287 | 37 | 3 | - | 2804 | 2875 | no | 191 B |
| 12x8 | confidential signer | full+data | yes | 4215 | 30 | 3 | - | 2968 | 3151 | no | 119 B |
| 12x8 | confidential signer | full+reply | yes | 3919 | 30 | 3 | - | 2672 | 2871 | yes |  |
| 12x8 | confidential signer | full+2tree | yes | 3958 | 31 | 3 | - | 2678 | 2875 | yes |  |
| 12x8 | confidential in-proof | min | yes | 3387 | 20 | 1 | - | 2609 | 2851 | yes |  |
| 12x8 | confidential in-proof | full | yes | 3918 | 29 | 2 | 1 | 2768 | 2968 | yes |  |
| 12x8 | confidential in-proof | full+spl | yes | 4286 | 36 | 2 | - | 2900 | 2972 | no | 190 B |
| 12x8 | confidential in-proof | full+data | yes | 4214 | 29 | 2 | - | 3064 | 3248 | no | 118 B |
| 12x8 | confidential in-proof | full+reply | yes | 3918 | 29 | 2 | - | 2768 | 2968 | yes |  |
| 12x8 | confidential in-proof | full+2tree | yes | 3957 | 30 | 2 | - | 2774 | 2972 | yes |  |
| 12x8 | anonymous hidden | min | yes | 3675 | 20 | 1 | - | 2897 | 3179 | yes |  |
| 12x8 | anonymous hidden | full | yes | 4110 | 26 | 2 | none | 3056 | 3296 | no | 14 B |
| 12x8 | anonymous hidden | full+spl | yes | 4478 | 33 | 2 | - | 3188 | 3300 | no | 382 B |
| 12x8 | anonymous hidden | full+data | yes | 4406 | 26 | 2 | - | 3352 | 3576 | no | 310 B |
| 12x8 | anonymous hidden | full+reply | yes | 4791 | 26 | 2 | - | 3737 | 3975 | no | 695 B |
| 12x8 | anonymous hidden | full+2tree | yes | 4149 | 27 | 2 | - | 3062 | 3300 | no | 53 B |
| 12x8 | anonymous public owners | min | yes | 3612 | 20 | 1 | - | 2833 | 3082 | yes |  |
| 12x8 | anonymous public owners | full | yes | 4239 | 30 | 3 | none | 2992 | 3199 | no | 143 B |
| 12x8 | anonymous public owners | full+spl | yes | 4607 | 37 | 3 | - | 3124 | 3203 | no | 511 B |
| 12x8 | anonymous public owners | full+data | yes | 4535 | 30 | 3 | - | 3288 | 3479 | no | 439 B |
| 12x8 | anonymous public owners | full+reply | yes | 4920 | 30 | 3 | - | 3673 | 3878 | no | 824 B |
| 12x8 | anonymous public owners | full+2tree | yes | 4278 | 31 | 3 | - | 2998 | 3203 | no | 182 B |
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
| 16x2 | confidential signer | min | yes | 2298 | 24 | 1 | - | 1387 | 1416 | yes |  |
| 16x2 | confidential signer | full | yes | 2925 | 34 | 3 | 10 | 1546 | 1533 | yes |  |
| 16x2 | confidential signer | full+spl | yes | 3293 | 41 | 3 | - | 1678 | 1537 | yes |  |
| 16x2 | confidential signer | full+data | yes | 2999 | 34 | 3 | - | 1620 | 1603 | yes |  |
| 16x2 | confidential signer | full+reply | yes | 2925 | 34 | 3 | - | 1546 | 1533 | yes |  |
| 16x2 | confidential signer | full+2tree | yes | 2964 | 35 | 3 | - | 1552 | 1537 | yes |  |
| 16x2 | confidential in-proof | min | yes | 2393 | 24 | 1 | - | 1483 | 1513 | yes |  |
| 16x2 | confidential in-proof | full | yes | 2924 | 33 | 2 | 10 | 1642 | 1630 | yes |  |
| 16x2 | confidential in-proof | full+spl | yes | 3292 | 40 | 2 | - | 1774 | 1634 | yes |  |
| 16x2 | confidential in-proof | full+data | yes | 2998 | 33 | 2 | - | 1716 | 1700 | yes |  |
| 16x2 | confidential in-proof | full+reply | yes | 2924 | 33 | 2 | - | 1642 | 1630 | yes |  |
| 16x2 | confidential in-proof | full+2tree | yes | 2963 | 34 | 2 | - | 1648 | 1634 | yes |  |
| 16x2 | anonymous hidden | min | yes | 2489 | 24 | 1 | - | 1579 | 1649 | yes |  |
| 16x2 | anonymous hidden | full | yes | 2924 | 30 | 2 | 10 | 1738 | 1766 | yes |  |
| 16x2 | anonymous hidden | full+spl | yes | 3292 | 37 | 2 | - | 1870 | 1770 | yes |  |
| 16x2 | anonymous hidden | full+data | yes | 2998 | 30 | 2 | - | 1812 | 1836 | yes |  |
| 16x2 | anonymous hidden | full+reply | yes | 3023 | 30 | 2 | - | 1837 | 1863 | yes |  |
| 16x2 | anonymous hidden | full+2tree | yes | 2963 | 31 | 2 | - | 1744 | 1770 | yes |  |
| 16x2 | anonymous public owners | min | yes | 2426 | 24 | 1 | - | 1515 | 1552 | yes |  |
| 16x2 | anonymous public owners | full | yes | 3053 | 34 | 3 | 10 | 1674 | 1669 | yes |  |
| 16x2 | anonymous public owners | full+spl | yes | 3421 | 41 | 3 | - | 1806 | 1673 | yes |  |
| 16x2 | anonymous public owners | full+data | yes | 3127 | 34 | 3 | - | 1748 | 1739 | yes |  |
| 16x2 | anonymous public owners | full+reply | yes | 3152 | 34 | 3 | - | 1773 | 1766 | yes |  |
| 16x2 | anonymous public owners | full+2tree | yes | 3092 | 35 | 3 | - | 1680 | 1673 | yes |  |
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
| 16x4 | confidential signer | min | yes | 2716 | 24 | 1 | - | 1805 | 1906 | yes |  |
| 16x4 | confidential signer | full | yes | 3343 | 34 | 3 | 8 | 1964 | 2023 | yes |  |
| 16x4 | confidential signer | full+spl | yes | 3711 | 41 | 3 | - | 2096 | 2027 | yes |  |
| 16x4 | confidential signer | full+data | yes | 3491 | 34 | 3 | - | 2112 | 2163 | yes |  |
| 16x4 | confidential signer | full+reply | yes | 3343 | 34 | 3 | - | 1964 | 2023 | yes |  |
| 16x4 | confidential signer | full+2tree | yes | 3382 | 35 | 3 | - | 1970 | 2027 | yes |  |
| 16x4 | confidential in-proof | min | yes | 2811 | 24 | 1 | - | 1901 | 2003 | yes |  |
| 16x4 | confidential in-proof | full | yes | 3342 | 33 | 2 | 7 | 2060 | 2120 | yes |  |
| 16x4 | confidential in-proof | full+spl | yes | 3710 | 40 | 2 | - | 2192 | 2124 | yes |  |
| 16x4 | confidential in-proof | full+data | yes | 3490 | 33 | 2 | - | 2208 | 2260 | yes |  |
| 16x4 | confidential in-proof | full+reply | yes | 3342 | 33 | 2 | - | 2060 | 2120 | yes |  |
| 16x4 | confidential in-proof | full+2tree | yes | 3381 | 34 | 2 | - | 2066 | 2124 | yes |  |
| 16x4 | anonymous hidden | min | yes | 2971 | 24 | 1 | - | 2061 | 2203 | yes |  |
| 16x4 | anonymous hidden | full | yes | 3406 | 30 | 2 | 7 | 2220 | 2320 | yes |  |
| 16x4 | anonymous hidden | full+spl | yes | 3774 | 37 | 2 | - | 2352 | 2324 | yes |  |
| 16x4 | anonymous hidden | full+data | yes | 3554 | 30 | 2 | - | 2368 | 2460 | yes |  |
| 16x4 | anonymous hidden | full+reply | yes | 3699 | 30 | 2 | - | 2513 | 2611 | yes |  |
| 16x4 | anonymous hidden | full+2tree | yes | 3445 | 31 | 2 | - | 2226 | 2324 | yes |  |
| 16x4 | anonymous public owners | min | yes | 2908 | 24 | 1 | - | 1997 | 2106 | yes |  |
| 16x4 | anonymous public owners | full | yes | 3535 | 34 | 3 | 6 | 2156 | 2223 | yes |  |
| 16x4 | anonymous public owners | full+spl | yes | 3903 | 41 | 3 | - | 2288 | 2227 | yes |  |
| 16x4 | anonymous public owners | full+data | yes | 3683 | 34 | 3 | - | 2304 | 2363 | yes |  |
| 16x4 | anonymous public owners | full+reply | yes | 3828 | 34 | 3 | - | 2449 | 2514 | yes |  |
| 16x4 | anonymous public owners | full+2tree | yes | 3574 | 35 | 3 | - | 2162 | 2227 | yes |  |
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
| 16x8 | confidential signer | min | yes | 3552 | 24 | 1 | - | 2641 | 2886 | yes |  |
| 16x8 | confidential signer | full | yes | 4179 | 34 | 3 | none | 2800 | 3003 | no | 83 B |
| 16x8 | confidential signer | full+spl | yes | 4547 | 41 | 3 | - | 2932 | 3007 | no | 451 B |
| 16x8 | confidential signer | full+data | yes | 4475 | 34 | 3 | - | 3096 | 3283 | no | 379 B |
| 16x8 | confidential signer | full+reply | yes | 4179 | 34 | 3 | - | 2800 | 3003 | no | 83 B |
| 16x8 | confidential signer | full+2tree | yes | 4218 | 35 | 3 | - | 2806 | 3007 | no | 122 B |
| 16x8 | confidential in-proof | min | yes | 3647 | 24 | 1 | - | 2737 | 2983 | yes |  |
| 16x8 | confidential in-proof | full | yes | 4178 | 33 | 2 | none | 2896 | 3100 | no | 82 B |
| 16x8 | confidential in-proof | full+spl | yes | 4546 | 40 | 2 | - | 3028 | 3104 | no | 450 B |
| 16x8 | confidential in-proof | full+data | yes | 4474 | 33 | 2 | - | 3192 | 3380 | no | 378 B |
| 16x8 | confidential in-proof | full+reply | yes | 4178 | 33 | 2 | - | 2896 | 3100 | no | 82 B |
| 16x8 | confidential in-proof | full+2tree | yes | 4217 | 34 | 2 | - | 2902 | 3104 | no | 121 B |
| 16x8 | anonymous hidden | min | yes | 3935 | 24 | 1 | - | 3025 | 3311 | yes |  |
| 16x8 | anonymous hidden | full | yes | 4370 | 30 | 2 | none | 3184 | 3428 | no | 274 B |
| 16x8 | anonymous hidden | full+spl | yes | 4738 | 37 | 2 | - | 3316 | 3432 | no | 642 B |
| 16x8 | anonymous hidden | full+data | yes | 4666 | 30 | 2 | - | 3480 | 3708 | no | 570 B |
| 16x8 | anonymous hidden | full+reply | yes | 5051 | 30 | 2 | - | 3865 | 4107 | no | 955 B |
| 16x8 | anonymous hidden | full+2tree | yes | 4409 | 31 | 2 | - | 3190 | 3432 | no | 313 B |
| 16x8 | anonymous public owners | min | yes | 3872 | 24 | 1 | - | 2961 | 3214 | yes |  |
| 16x8 | anonymous public owners | full | yes | 4499 | 34 | 3 | none | 3120 | 3331 | no | 403 B |
| 16x8 | anonymous public owners | full+spl | yes | 4867 | 41 | 3 | - | 3252 | 3335 | no | 771 B |
| 16x8 | anonymous public owners | full+data | yes | 4795 | 34 | 3 | - | 3416 | 3611 | no | 699 B |
| 16x8 | anonymous public owners | full+reply | yes | 5180 | 34 | 3 | - | 3801 | 4010 | no | 1084 B |
| 16x8 | anonymous public owners | full+2tree | yes | 4538 | 35 | 3 | - | 3126 | 3335 | no | 442 B |
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
| 24x2 | confidential signer | min | yes | 2818 | 32 | 1 | - | 1643 | 1680 | yes |  |
| 24x2 | confidential signer | full | yes | 3445 | 42 | 3 | 7 | 1802 | 1797 | yes |  |
| 24x2 | confidential signer | full+spl | yes | 3813 | 49 | 3 | - | 1934 | 1801 | yes |  |
| 24x2 | confidential signer | full+data | yes | 3519 | 42 | 3 | - | 1876 | 1867 | yes |  |
| 24x2 | confidential signer | full+reply | yes | 3445 | 42 | 3 | - | 1802 | 1797 | yes |  |
| 24x2 | confidential signer | full+2tree | yes | 3485 | 43 | 3 | - | 1809 | 1801 | yes |  |
| 24x2 | confidential in-proof | min | yes | 2913 | 32 | 1 | - | 1739 | 1777 | yes |  |
| 24x2 | confidential in-proof | full | yes | 3444 | 41 | 2 | 6 | 1898 | 1894 | yes |  |
| 24x2 | confidential in-proof | full+spl | yes | 3812 | 48 | 2 | - | 2030 | 1898 | yes |  |
| 24x2 | confidential in-proof | full+data | yes | 3518 | 41 | 2 | - | 1972 | 1964 | yes |  |
| 24x2 | confidential in-proof | full+reply | yes | 3444 | 41 | 2 | - | 1898 | 1894 | yes |  |
| 24x2 | confidential in-proof | full+2tree | yes | 3484 | 42 | 2 | - | 1905 | 1898 | yes |  |
| 24x2 | anonymous hidden | min | yes | 3009 | 32 | 1 | - | 1835 | 1913 | yes |  |
| 24x2 | anonymous hidden | full | yes | 3444 | 38 | 2 | 6 | 1994 | 2030 | yes |  |
| 24x2 | anonymous hidden | full+spl | yes | 3812 | 45 | 2 | - | 2126 | 2034 | yes |  |
| 24x2 | anonymous hidden | full+data | yes | 3518 | 38 | 2 | - | 2068 | 2100 | yes |  |
| 24x2 | anonymous hidden | full+reply | yes | 3543 | 38 | 2 | - | 2093 | 2127 | yes |  |
| 24x2 | anonymous hidden | full+2tree | yes | 3484 | 39 | 2 | - | 2001 | 2034 | yes |  |
| 24x2 | anonymous public owners | min | yes | 2946 | 32 | 1 | - | 1771 | 1816 | yes |  |
| 24x2 | anonymous public owners | full | yes | 3573 | 42 | 3 | 6 | 1930 | 1933 | yes |  |
| 24x2 | anonymous public owners | full+spl | yes | 3941 | 49 | 3 | - | 2062 | 1937 | yes |  |
| 24x2 | anonymous public owners | full+data | yes | 3647 | 42 | 3 | - | 2004 | 2003 | yes |  |
| 24x2 | anonymous public owners | full+reply | yes | 3672 | 42 | 3 | - | 2029 | 2030 | yes |  |
| 24x2 | anonymous public owners | full+2tree | yes | 3613 | 43 | 3 | - | 1937 | 1937 | yes |  |
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
| 24x4 | confidential signer | min | yes | 3236 | 32 | 1 | - | 2061 | 2170 | yes |  |
| 24x4 | confidential signer | full | yes | 3863 | 42 | 3 | 3 | 2220 | 2287 | yes |  |
| 24x4 | confidential signer | full+spl | yes | 4231 | 49 | 3 | - | 2352 | 2291 | no | 135 B |
| 24x4 | confidential signer | full+data | yes | 4011 | 42 | 3 | - | 2368 | 2427 | yes |  |
| 24x4 | confidential signer | full+reply | yes | 3863 | 42 | 3 | - | 2220 | 2287 | yes |  |
| 24x4 | confidential signer | full+2tree | yes | 3903 | 43 | 3 | - | 2227 | 2291 | yes |  |
| 24x4 | confidential in-proof | min | yes | 3331 | 32 | 1 | - | 2157 | 2267 | yes |  |
| 24x4 | confidential in-proof | full | yes | 3862 | 41 | 2 | 2 | 2316 | 2384 | yes |  |
| 24x4 | confidential in-proof | full+spl | yes | 4230 | 48 | 2 | - | 2448 | 2388 | no | 134 B |
| 24x4 | confidential in-proof | full+data | yes | 4010 | 41 | 2 | - | 2464 | 2524 | yes |  |
| 24x4 | confidential in-proof | full+reply | yes | 3862 | 41 | 2 | - | 2316 | 2384 | yes |  |
| 24x4 | confidential in-proof | full+2tree | yes | 3902 | 42 | 2 | - | 2323 | 2388 | yes |  |
| 24x4 | anonymous hidden | min | yes | 3491 | 32 | 1 | - | 2317 | 2467 | yes |  |
| 24x4 | anonymous hidden | full | yes | 3926 | 38 | 2 | 1 | 2476 | 2584 | yes |  |
| 24x4 | anonymous hidden | full+spl | yes | 4294 | 45 | 2 | - | 2608 | 2588 | no | 198 B |
| 24x4 | anonymous hidden | full+data | yes | 4074 | 38 | 2 | - | 2624 | 2724 | yes |  |
| 24x4 | anonymous hidden | full+reply | yes | 4219 | 38 | 2 | - | 2769 | 2875 | no | 123 B |
| 24x4 | anonymous hidden | full+2tree | yes | 3966 | 39 | 2 | - | 2483 | 2588 | yes |  |
| 24x4 | anonymous public owners | min | yes | 3428 | 32 | 1 | - | 2253 | 2370 | yes |  |
| 24x4 | anonymous public owners | full | yes | 4055 | 42 | 3 | 1 | 2412 | 2487 | yes |  |
| 24x4 | anonymous public owners | full+spl | yes | 4423 | 49 | 3 | - | 2544 | 2491 | no | 327 B |
| 24x4 | anonymous public owners | full+data | yes | 4203 | 42 | 3 | - | 2560 | 2627 | no | 107 B |
| 24x4 | anonymous public owners | full+reply | yes | 4348 | 42 | 3 | - | 2705 | 2778 | no | 252 B |
| 24x4 | anonymous public owners | full+2tree | yes | 4095 | 43 | 3 | - | 2419 | 2491 | yes |  |
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
| 32x2 | confidential signer | min | yes | 3338 | 40 | 1 | - | 1899 | 1944 | yes |  |
| 32x2 | confidential signer | full | yes | 3965 | 50 | 3 | 2 | 2058 | 2061 | yes |  |
| 32x2 | confidential signer | full+spl | yes | 4333 | 57 | 3 | - | 2190 | 2065 | no | 237 B |
| 32x2 | confidential signer | full+data | yes | 4039 | 50 | 3 | - | 2132 | 2131 | yes |  |
| 32x2 | confidential signer | full+reply | yes | 3965 | 50 | 3 | - | 2058 | 2061 | yes |  |
| 32x2 | confidential signer | full+2tree | yes | 4006 | 51 | 3 | - | 2066 | 2065 | yes |  |
| 32x2 | confidential in-proof | min | yes | 3433 | 40 | 1 | - | 1995 | 2041 | yes |  |
| 32x2 | confidential in-proof | full | yes | 3964 | 49 | 2 | 1 | 2154 | 2158 | yes |  |
| 32x2 | confidential in-proof | full+spl | yes | 4332 | 56 | 2 | - | 2286 | 2162 | no | 236 B |
| 32x2 | confidential in-proof | full+data | yes | 4038 | 49 | 2 | - | 2228 | 2228 | yes |  |
| 32x2 | confidential in-proof | full+reply | yes | 3964 | 49 | 2 | - | 2154 | 2158 | yes |  |
| 32x2 | confidential in-proof | full+2tree | yes | 4005 | 50 | 2 | - | 2162 | 2162 | yes |  |
| 32x2 | anonymous hidden | min | yes | 3529 | 40 | 1 | - | 2091 | 2177 | yes |  |
| 32x2 | anonymous hidden | full | yes | 3964 | 46 | 2 | 1 | 2250 | 2294 | yes |  |
| 32x2 | anonymous hidden | full+spl | yes | 4332 | 53 | 2 | - | 2382 | 2298 | no | 236 B |
| 32x2 | anonymous hidden | full+data | yes | 4038 | 46 | 2 | - | 2324 | 2364 | yes |  |
| 32x2 | anonymous hidden | full+reply | yes | 4063 | 46 | 2 | - | 2349 | 2391 | yes |  |
| 32x2 | anonymous hidden | full+2tree | yes | 4005 | 47 | 2 | - | 2258 | 2298 | yes |  |
| 32x2 | anonymous public owners | min | yes | 3466 | 40 | 1 | - | 2027 | 2080 | yes |  |
| 32x2 | anonymous public owners | full | yes | 4093 | 50 | 3 | 1 | 2186 | 2197 | yes |  |
| 32x2 | anonymous public owners | full+spl | yes | 4461 | 57 | 3 | - | 2318 | 2201 | no | 365 B |
| 32x2 | anonymous public owners | full+data | yes | 4167 | 50 | 3 | - | 2260 | 2267 | no | 71 B |
| 32x2 | anonymous public owners | full+reply | yes | 4192 | 50 | 3 | - | 2285 | 2294 | no | 96 B |
| 32x2 | anonymous public owners | full+2tree | yes | 4134 | 51 | 3 | - | 2194 | 2201 | no | 38 B |
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
| 40x2 | confidential signer | min | yes | 3858 | 48 | 1 | - | 2155 | 2208 | yes |  |
| 40x2 | confidential signer | full | yes | 4485 | 58 | 3 | none | 2314 | 2325 | no | 389 B |
| 40x2 | confidential signer | full+spl | yes | 4853 | 65 | 3 | - | 2446 | 2329 | no | 757 B, 1 accounts |
| 40x2 | confidential signer | full+data | yes | 4559 | 58 | 3 | - | 2388 | 2395 | no | 463 B |
| 40x2 | confidential signer | full+reply | yes | 4485 | 58 | 3 | - | 2314 | 2325 | no | 389 B |
| 40x2 | confidential signer | full+2tree | yes | 4527 | 59 | 3 | - | 2323 | 2329 | no | 431 B |
| 40x2 | confidential in-proof | min | yes | 3953 | 48 | 1 | - | 2251 | 2305 | yes |  |
| 40x2 | confidential in-proof | full | yes | 4484 | 57 | 2 | none | 2410 | 2422 | no | 388 B |
| 40x2 | confidential in-proof | full+spl | yes | 4852 | 64 | 2 | - | 2542 | 2426 | no | 756 B |
| 40x2 | confidential in-proof | full+data | yes | 4558 | 57 | 2 | - | 2484 | 2492 | no | 462 B |
| 40x2 | confidential in-proof | full+reply | yes | 4484 | 57 | 2 | - | 2410 | 2422 | no | 388 B |
| 40x2 | confidential in-proof | full+2tree | yes | 4526 | 58 | 2 | - | 2419 | 2426 | no | 430 B |
| 40x2 | anonymous hidden | min | yes | 4049 | 48 | 1 | - | 2347 | 2441 | yes |  |
| 40x2 | anonymous hidden | full | yes | 4484 | 54 | 2 | none | 2506 | 2558 | no | 388 B |
| 40x2 | anonymous hidden | full+spl | yes | 4852 | 61 | 2 | - | 2638 | 2562 | no | 756 B |
| 40x2 | anonymous hidden | full+data | yes | 4558 | 54 | 2 | - | 2580 | 2628 | no | 462 B |
| 40x2 | anonymous hidden | full+reply | yes | 4583 | 54 | 2 | - | 2605 | 2655 | no | 487 B |
| 40x2 | anonymous hidden | full+2tree | yes | 4526 | 55 | 2 | - | 2515 | 2562 | no | 430 B |
| 40x2 | anonymous public owners | min | yes | 3986 | 48 | 1 | - | 2283 | 2344 | yes |  |
| 40x2 | anonymous public owners | full | yes | 4613 | 58 | 3 | none | 2442 | 2461 | no | 517 B |
| 40x2 | anonymous public owners | full+spl | yes | 4981 | 65 | 3 | - | 2574 | 2465 | no | 885 B, 1 accounts |
| 40x2 | anonymous public owners | full+data | yes | 4687 | 58 | 3 | - | 2516 | 2531 | no | 591 B |
| 40x2 | anonymous public owners | full+reply | yes | 4712 | 58 | 3 | - | 2541 | 2558 | no | 616 B |
| 40x2 | anonymous public owners | full+2tree | yes | 4655 | 59 | 3 | - | 2451 | 2465 | no | 559 B |
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
| 8x1 | merge | ring | yes | 1729 | 16 | 1 | - | - | - | yes |  |
| 8x1 | merge | owner signed | yes | 1826 | 17 | 2 | - | - | - | yes |  |
| 24x1 | merge | ring | yes | 2769 | 32 | 1 | - | - | - | yes |  |
| 24x1 | merge | owner signed | yes | 2866 | 33 | 2 | - | - | - | yes |  |
| 52x1 | merge | ring | yes | 4589 | 60 | 1 | - | - | - | no | 493 B |
| 52x1 | merge | owner signed | yes | 4686 | 61 | 2 | - | - | - | no | 590 B |

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

Maxima. Load max is full with recipient payloads, every extension but the cache, two SPP input trees, replies on anonymous frames. Each row widens one axis from that load to the largest value one transaction clears. reply: the reply length. messages: empty application messages. message bytes: one application message. over: what refuses one more step. Heap is not measured here.
| shape | rail | axis | widest | frame | SPP CPI | bytes | accounts | signatures | over |
|---|---|---|---|---|---|---|---|---|---|
| 1x2 | confidential signer | messages | 56 | 3147 | 3080 | 4064 | 20 | 3 | 2 B |
| 1x2 | confidential signer | message bytes | 1902 | 3179 | 3112 | 4096 | 20 | 3 | 1 B |
| 1x2 | confidential in-proof | messages | 56 | 3243 | 3177 | 4063 | 19 | 2 | 1 B |
| 1x2 | confidential in-proof | message bytes | 1903 | 3276 | 3210 | 4096 | 19 | 2 | 1 B |
| 1x2 | anonymous hidden | reply | 1936 | 3372 | 3345 | 4096 | 16 | 2 | 1 B |
| 1x2 | anonymous hidden | messages | 54 | 3370 | 3342 | 4094 | 16 | 2 | 32 B |
| 1x2 | anonymous hidden | message bytes | 1804 | 3372 | 3344 | 4096 | 16 | 2 | 1 B |
| 1x2 | anonymous public owners | reply | 1807 | 3179 | 3119 | 4096 | 20 | 3 | 1 B |
| 1x2 | anonymous public owners | messages | 50 | 3170 | 3109 | 4087 | 20 | 3 | 25 B |
| 1x2 | anonymous public owners | message bytes | 1675 | 3179 | 3118 | 4096 | 20 | 3 | 1 B |
| 1x2 | confidential entry | messages | 52 | 3155 | 3088 | 4072 | 20 | 3 | 10 B |
| 1x2 | confidential entry | message bytes | 1758 | 3179 | 3112 | 4096 | 20 | 3 | 1 B |
| 1x2 | anonymous entry | reply | 1760 | 3372 | 3313 | 4096 | 16 | 2 | 1 B |
| 1x2 | anonymous entry | messages | 48 | 3342 | 3282 | 4066 | 16 | 2 | 4 B |
| 1x2 | anonymous entry | message bytes | 1628 | 3372 | 3312 | 4096 | 16 | 2 | 1 B |
| 1x4 | confidential signer | messages | 42 | 3163 | 3164 | 4080 | 20 | 3 | 18 B |
| 1x4 | confidential signer | message bytes | 1410 | 3179 | 3180 | 4096 | 20 | 3 | 1 B |
| 1x4 | confidential in-proof | messages | 42 | 3259 | 3261 | 4079 | 19 | 2 | 17 B |
| 1x4 | confidential in-proof | message bytes | 1411 | 3276 | 3278 | 4096 | 19 | 2 | 1 B |
| 1x4 | anonymous hidden | reply | 460 | 3372 | 3413 | 4096 | 16 | 2 | 3 B |
| 1x4 | anonymous hidden | messages | 32 | 3372 | 3412 | 4096 | 16 | 2 | 34 B |
| 1x4 | anonymous hidden | message bytes | 1054 | 3372 | 3412 | 4096 | 16 | 2 | 1 B |
| 1x4 | anonymous public owners | reply | 417 | 3179 | 3187 | 4096 | 20 | 3 | 3 B |
| 1x4 | anonymous public owners | messages | 28 | 3172 | 3179 | 4089 | 20 | 3 | 27 B |
| 1x4 | anonymous public owners | message bytes | 925 | 3179 | 3186 | 4096 | 20 | 3 | 1 B |
| 1x4 | confidential entry | messages | 38 | 3171 | 3172 | 4088 | 20 | 3 | 26 B |
| 1x4 | confidential entry | message bytes | 1266 | 3179 | 3180 | 4096 | 20 | 3 | 1 B |
| 1x4 | anonymous entry | reply | 401 | 3371 | 3380 | 4095 | 16 | 2 | 2 B |
| 1x4 | anonymous entry | messages | 26 | 3344 | 3352 | 4068 | 16 | 2 | 6 B |
| 1x4 | anonymous entry | message bytes | 878 | 3372 | 3380 | 4096 | 16 | 2 | 1 B |
| 1x8 | confidential signer | messages | 13 | 3161 | 3298 | 4078 | 20 | 3 | 16 B |
| 1x8 | confidential signer | message bytes | 426 | 3179 | 3316 | 4096 | 20 | 3 | 1 B |
| 1x8 | confidential in-proof | messages | 13 | 3257 | 3395 | 4077 | 19 | 2 | 15 B |
| 1x8 | confidential in-proof | message bytes | 427 | 3276 | 3414 | 4096 | 19 | 2 | 1 B |
| 1x8 | anonymous hidden | reply | none | - | - | - | - | - | 411 B |
| 1x8 | anonymous hidden | messages | none | - | - | - | - | - | 411 B |
| 1x8 | anonymous hidden | message bytes | none | - | - | - | - | - | 446 B |
| 1x8 | anonymous public owners | reply | none | - | - | - | - | - | 540 B |
| 1x8 | anonymous public owners | messages | none | - | - | - | - | - | 540 B |
| 1x8 | anonymous public owners | message bytes | none | - | - | - | - | - | 575 B |
| 1x8 | confidential entry | messages | 9 | 3169 | 3306 | 4086 | 20 | 3 | 24 B |
| 1x8 | confidential entry | message bytes | 282 | 3179 | 3316 | 4096 | 20 | 3 | 1 B |
| 1x8 | anonymous entry | reply | none | - | - | - | - | - | 587 B |
| 1x8 | anonymous entry | messages | none | - | - | - | - | - | 587 B |
| 1x8 | anonymous entry | message bytes | none | - | - | - | - | - | 622 B |
| 2x2 | confidential signer | messages | 55 | 3145 | 3079 | 4095 | 21 | 3 | 33 B |
| 2x2 | confidential signer | message bytes | 1837 | 3146 | 3080 | 4096 | 21 | 3 | 1 B |
| 2x2 | confidential in-proof | messages | 55 | 3241 | 3176 | 4094 | 20 | 2 | 32 B |
| 2x2 | confidential in-proof | message bytes | 1838 | 3243 | 3178 | 4096 | 20 | 2 | 1 B |
| 2x2 | anonymous hidden | reply | 1871 | 3339 | 3313 | 4096 | 17 | 2 | 1 B |
| 2x2 | anonymous hidden | messages | 52 | 3334 | 3307 | 4091 | 17 | 2 | 29 B |
| 2x2 | anonymous hidden | message bytes | 1739 | 3339 | 3312 | 4096 | 17 | 2 | 1 B |
| 2x2 | anonymous public owners | reply | 1742 | 3146 | 3087 | 4096 | 21 | 3 | 1 B |
| 2x2 | anonymous public owners | messages | 48 | 3134 | 3074 | 4084 | 21 | 3 | 22 B |
| 2x2 | anonymous public owners | message bytes | 1610 | 3146 | 3086 | 4096 | 21 | 3 | 1 B |
| 2x2 | confidential entry | messages | 46 | 3119 | 3053 | 4069 | 21 | 3 | 7 B |
| 2x2 | confidential entry | message bytes | 1557 | 3146 | 3080 | 4096 | 21 | 3 | 1 B |
| 2x2 | anonymous entry | reply | 1559 | 3339 | 3281 | 4096 | 17 | 2 | 1 B |
| 2x2 | anonymous entry | messages | 42 | 3306 | 3247 | 4063 | 17 | 2 | 1 B |
| 2x2 | anonymous entry | message bytes | 1427 | 3339 | 3280 | 4096 | 17 | 2 | 1 B |
| 2x2 | delegate | messages | 62 | 3335 | 3317 | 4089 | 17 | 2 | 27 B |
| 2x2 | delegate | message bytes | 2081 | 3342 | 3324 | 4096 | 17 | 2 | 1 B |
| 2x2 | anonymous delegate | reply | 1986 | 3342 | 3331 | 4096 | 17 | 2 | 1 B |
| 2x2 | anonymous delegate | messages | 55 | 3324 | 3312 | 4078 | 17 | 2 | 16 B |
| 2x2 | anonymous delegate | message bytes | 1854 | 3342 | 3330 | 4096 | 17 | 2 | 1 B |
| 2x4 | confidential signer | messages | 40 | 3127 | 3129 | 4077 | 21 | 3 | 15 B |
| 2x4 | confidential signer | message bytes | 1345 | 3146 | 3148 | 4096 | 21 | 3 | 1 B |
| 2x4 | confidential in-proof | messages | 40 | 3223 | 3226 | 4076 | 20 | 2 | 14 B |
| 2x4 | confidential in-proof | message bytes | 1346 | 3243 | 3246 | 4096 | 20 | 2 | 1 B |
| 2x4 | anonymous hidden | reply | 438 | 3338 | 3380 | 4095 | 17 | 2 | 2 B |
| 2x4 | anonymous hidden | messages | 30 | 3336 | 3377 | 4093 | 17 | 2 | 31 B |
| 2x4 | anonymous hidden | message bytes | 989 | 3339 | 3380 | 4096 | 17 | 2 | 1 B |
| 2x4 | anonymous public owners | reply | 395 | 3145 | 3154 | 4095 | 21 | 3 | 2 B |
| 2x4 | anonymous public owners | messages | 26 | 3136 | 3144 | 4086 | 21 | 3 | 24 B |
| 2x4 | anonymous public owners | message bytes | 860 | 3146 | 3154 | 4096 | 21 | 3 | 1 B |
| 2x4 | confidential entry | messages | 32 | 3135 | 3137 | 4085 | 21 | 3 | 23 B |
| 2x4 | confidential entry | message bytes | 1065 | 3146 | 3148 | 4096 | 21 | 3 | 1 B |
| 2x4 | anonymous entry | reply | 334 | 3338 | 3348 | 4095 | 17 | 2 | 2 B |
| 2x4 | anonymous entry | messages | 20 | 3308 | 3317 | 4065 | 17 | 2 | 3 B |
| 2x4 | anonymous entry | message bytes | 677 | 3339 | 3348 | 4096 | 17 | 2 | 1 B |
| 2x8 | confidential signer | messages | 11 | 3125 | 3263 | 4075 | 21 | 3 | 13 B |
| 2x8 | confidential signer | message bytes | 361 | 3146 | 3284 | 4096 | 21 | 3 | 1 B |
| 2x8 | confidential in-proof | messages | 11 | 3221 | 3360 | 4074 | 20 | 2 | 12 B |
| 2x8 | confidential in-proof | message bytes | 362 | 3243 | 3382 | 4096 | 20 | 2 | 1 B |
| 2x8 | anonymous hidden | reply | none | - | - | - | - | - | 476 B |
| 2x8 | anonymous hidden | messages | none | - | - | - | - | - | 476 B |
| 2x8 | anonymous hidden | message bytes | none | - | - | - | - | - | 511 B |
| 2x8 | anonymous public owners | reply | none | - | - | - | - | - | 605 B |
| 2x8 | anonymous public owners | messages | none | - | - | - | - | - | 605 B |
| 2x8 | anonymous public owners | message bytes | none | - | - | - | - | - | 640 B |
| 2x8 | confidential entry | messages | 3 | 3133 | 3271 | 4083 | 21 | 3 | 21 B |
| 2x8 | confidential entry | message bytes | 81 | 3146 | 3284 | 4096 | 21 | 3 | 1 B |
| 2x8 | anonymous entry | reply | none | - | - | - | - | - | 788 B |
| 2x8 | anonymous entry | messages | none | - | - | - | - | - | 788 B |
| 2x8 | anonymous entry | message bytes | none | - | - | - | - | - | 823 B |
| 3x2 | confidential signer | messages | 53 | 3109 | 3044 | 4092 | 22 | 3 | 30 B |
| 3x2 | confidential signer | message bytes | 1772 | 3113 | 3048 | 4096 | 22 | 3 | 1 B |
| 3x2 | confidential in-proof | messages | 53 | 3205 | 3141 | 4091 | 21 | 2 | 29 B |
| 3x2 | confidential in-proof | message bytes | 1773 | 3210 | 3146 | 4096 | 21 | 2 | 1 B |
| 3x2 | anonymous hidden | reply | 1806 | 3306 | 3281 | 4096 | 18 | 2 | 1 B |
| 3x2 | anonymous hidden | messages | 50 | 3298 | 3272 | 4088 | 18 | 2 | 26 B |
| 3x2 | anonymous hidden | message bytes | 1674 | 3306 | 3280 | 4096 | 18 | 2 | 1 B |
| 3x2 | anonymous public owners | reply | 1677 | 3113 | 3055 | 4096 | 22 | 3 | 1 B |
| 3x2 | anonymous public owners | messages | 46 | 3098 | 3039 | 4081 | 22 | 3 | 19 B |
| 3x2 | anonymous public owners | message bytes | 1545 | 3113 | 3054 | 4096 | 22 | 3 | 1 B |
| 3x2 | confidential entry | messages | 40 | 3083 | 3018 | 4066 | 22 | 3 | 4 B |
| 3x2 | confidential entry | message bytes | 1356 | 3113 | 3048 | 4096 | 22 | 3 | 1 B |
| 3x2 | anonymous entry | reply | 1358 | 3306 | 3249 | 4096 | 18 | 2 | 1 B |
| 3x2 | anonymous entry | messages | 37 | 3304 | 3246 | 4094 | 18 | 2 | 32 B |
| 3x2 | anonymous entry | message bytes | 1226 | 3306 | 3248 | 4096 | 18 | 2 | 1 B |
| 3x4 | confidential signer | messages | 38 | 3091 | 3094 | 4074 | 22 | 3 | 12 B |
| 3x4 | confidential signer | message bytes | 1280 | 3113 | 3116 | 4096 | 22 | 3 | 1 B |
| 3x4 | confidential in-proof | messages | 38 | 3187 | 3191 | 4073 | 21 | 2 | 11 B |
| 3x4 | confidential in-proof | message bytes | 1281 | 3210 | 3214 | 4096 | 21 | 2 | 1 B |
| 3x4 | anonymous hidden | reply | 416 | 3304 | 3347 | 4094 | 18 | 2 | 1 B |
| 3x4 | anonymous hidden | messages | 28 | 3300 | 3342 | 4090 | 18 | 2 | 28 B |
| 3x4 | anonymous hidden | message bytes | 924 | 3306 | 3348 | 4096 | 18 | 2 | 1 B |
| 3x4 | anonymous public owners | reply | 373 | 3111 | 3121 | 4094 | 22 | 3 | 1 B |
| 3x4 | anonymous public owners | messages | 24 | 3100 | 3109 | 4083 | 22 | 3 | 21 B |
| 3x4 | anonymous public owners | message bytes | 795 | 3113 | 3122 | 4096 | 22 | 3 | 1 B |
| 3x4 | confidential entry | messages | 26 | 3099 | 3102 | 4082 | 22 | 3 | 20 B |
| 3x4 | confidential entry | message bytes | 864 | 3113 | 3116 | 4096 | 22 | 3 | 1 B |
| 3x4 | anonymous entry | reply | 267 | 3305 | 3316 | 4095 | 18 | 2 | 2 B |
| 3x4 | anonymous entry | messages | 15 | 3306 | 3316 | 4096 | 18 | 2 | 34 B |
| 3x4 | anonymous entry | message bytes | 476 | 3306 | 3316 | 4096 | 18 | 2 | 1 B |
| 3x8 | confidential signer | messages | 9 | 3089 | 3228 | 4072 | 22 | 3 | 10 B |
| 3x8 | confidential signer | message bytes | 296 | 3113 | 3252 | 4096 | 22 | 3 | 1 B |
| 3x8 | confidential in-proof | messages | 9 | 3185 | 3325 | 4071 | 21 | 2 | 9 B |
| 3x8 | confidential in-proof | message bytes | 297 | 3210 | 3350 | 4096 | 21 | 2 | 1 B |
| 3x8 | anonymous hidden | reply | none | - | - | - | - | - | 541 B |
| 3x8 | anonymous hidden | messages | none | - | - | - | - | - | 541 B |
| 3x8 | anonymous hidden | message bytes | none | - | - | - | - | - | 576 B |
| 3x8 | anonymous public owners | reply | none | - | - | - | - | - | 670 B |
| 3x8 | anonymous public owners | messages | none | - | - | - | - | - | 670 B |
| 3x8 | anonymous public owners | message bytes | none | - | - | - | - | - | 705 B |
| 3x8 | confidential entry | messages | none | - | - | - | - | - | 85 B |
| 3x8 | confidential entry | message bytes | none | - | - | - | - | - | 120 B |
| 3x8 | anonymous entry | reply | none | - | - | - | - | - | 989 B |
| 3x8 | anonymous entry | messages | none | - | - | - | - | - | 989 B |
| 3x8 | anonymous entry | message bytes | none | - | - | - | - | - | 1024 B |
| 4x2 | confidential signer | messages | 51 | 3073 | 3009 | 4089 | 23 | 3 | 27 B |
| 4x2 | confidential signer | message bytes | 1707 | 3080 | 3016 | 4096 | 23 | 3 | 1 B |
| 4x2 | confidential in-proof | messages | 51 | 3169 | 3106 | 4088 | 22 | 2 | 26 B |
| 4x2 | confidential in-proof | message bytes | 1708 | 3177 | 3114 | 4096 | 22 | 2 | 1 B |
| 4x2 | anonymous hidden | reply | 1741 | 3273 | 3249 | 4096 | 19 | 2 | 1 B |
| 4x2 | anonymous hidden | messages | 48 | 3262 | 3237 | 4085 | 19 | 2 | 23 B |
| 4x2 | anonymous hidden | message bytes | 1609 | 3273 | 3248 | 4096 | 19 | 2 | 1 B |
| 4x2 | anonymous public owners | reply | 1612 | 3080 | 3023 | 4096 | 23 | 3 | 1 B |
| 4x2 | anonymous public owners | messages | 44 | 3062 | 3004 | 4078 | 23 | 3 | 16 B |
| 4x2 | anonymous public owners | message bytes | 1480 | 3080 | 3022 | 4096 | 23 | 3 | 1 B |
| 4x2 | confidential entry | messages | 34 | 3047 | 2983 | 4063 | 23 | 3 | 1 B |
| 4x2 | confidential entry | message bytes | 1155 | 3080 | 3016 | 4096 | 23 | 3 | 1 B |
| 4x2 | anonymous entry | reply | 1157 | 3273 | 3217 | 4096 | 19 | 2 | 1 B |
| 4x2 | anonymous entry | messages | 31 | 3268 | 3211 | 4091 | 19 | 2 | 29 B |
| 4x2 | anonymous entry | message bytes | 1025 | 3273 | 3216 | 4096 | 19 | 2 | 1 B |
| 4x4 | confidential signer | messages | 36 | 3055 | 3059 | 4071 | 23 | 3 | 9 B |
| 4x4 | confidential signer | message bytes | 1215 | 3080 | 3084 | 4096 | 23 | 3 | 1 B |
| 4x4 | confidential in-proof | messages | 36 | 3151 | 3156 | 4070 | 22 | 2 | 8 B |
| 4x4 | confidential in-proof | message bytes | 1216 | 3177 | 3182 | 4096 | 22 | 2 | 1 B |
| 4x4 | anonymous hidden | reply | 395 | 3273 | 3317 | 4096 | 19 | 2 | 3 B |
| 4x4 | anonymous hidden | messages | 26 | 3264 | 3307 | 4087 | 19 | 2 | 25 B |
| 4x4 | anonymous hidden | message bytes | 859 | 3273 | 3316 | 4096 | 19 | 2 | 1 B |
| 4x4 | anonymous public owners | reply | 352 | 3080 | 3091 | 4096 | 23 | 3 | 3 B |
| 4x4 | anonymous public owners | messages | 22 | 3064 | 3074 | 4080 | 23 | 3 | 18 B |
| 4x4 | anonymous public owners | message bytes | 730 | 3080 | 3090 | 4096 | 23 | 3 | 1 B |
| 4x4 | confidential entry | messages | 20 | 3063 | 3067 | 4079 | 23 | 3 | 17 B |
| 4x4 | confidential entry | message bytes | 663 | 3080 | 3084 | 4096 | 23 | 3 | 1 B |
| 4x4 | anonymous entry | reply | 200 | 3272 | 3284 | 4095 | 19 | 2 | 2 B |
| 4x4 | anonymous entry | messages | 9 | 3270 | 3281 | 4093 | 19 | 2 | 31 B |
| 4x4 | anonymous entry | message bytes | 275 | 3273 | 3284 | 4096 | 19 | 2 | 1 B |
| 4x4 | delegate | messages | 43 | 3245 | 3297 | 4065 | 19 | 2 | 3 B |
| 4x4 | delegate | message bytes | 1459 | 3276 | 3328 | 4096 | 19 | 2 | 1 B |
| 4x4 | anonymous delegate | reply | 433 | 3275 | 3334 | 4095 | 19 | 2 | 2 B |
| 4x4 | anonymous delegate | messages | 29 | 3254 | 3312 | 4074 | 19 | 2 | 12 B |
| 4x4 | anonymous delegate | message bytes | 974 | 3276 | 3334 | 4096 | 19 | 2 | 1 B |
| 4x8 | confidential signer | messages | 7 | 3053 | 3193 | 4069 | 23 | 3 | 7 B |
| 4x8 | confidential signer | message bytes | 231 | 3080 | 3220 | 4096 | 23 | 3 | 1 B |
| 4x8 | confidential in-proof | messages | 7 | 3149 | 3290 | 4068 | 22 | 2 | 6 B |
| 4x8 | confidential in-proof | message bytes | 232 | 3177 | 3318 | 4096 | 22 | 2 | 1 B |
| 4x8 | anonymous hidden | reply | none | - | - | - | - | - | 606 B |
| 4x8 | anonymous hidden | messages | none | - | - | - | - | - | 606 B |
| 4x8 | anonymous hidden | message bytes | none | - | - | - | - | - | 641 B |
| 4x8 | anonymous public owners | reply | none | - | - | - | - | - | 735 B |
| 4x8 | anonymous public owners | messages | none | - | - | - | - | - | 735 B |
| 4x8 | anonymous public owners | message bytes | none | - | - | - | - | - | 770 B |
| 4x8 | confidential entry | messages | none | - | - | - | - | - | 286 B |
| 4x8 | confidential entry | message bytes | none | - | - | - | - | - | 321 B |
| 4x8 | anonymous entry | reply | none | - | - | - | - | - | 1190 B |
| 4x8 | anonymous entry | messages | none | - | - | - | - | - | 1190 B |
| 4x8 | anonymous entry | message bytes | none | - | - | - | - | - | 1225 B |
| 5x2 | confidential signer | messages | 49 | 3037 | 2974 | 4086 | 24 | 3 | 24 B |
| 5x2 | confidential signer | message bytes | 1642 | 3047 | 2984 | 4096 | 24 | 3 | 1 B |
| 5x2 | confidential in-proof | messages | 49 | 3133 | 3071 | 4085 | 23 | 2 | 23 B |
| 5x2 | confidential in-proof | message bytes | 1643 | 3144 | 3082 | 4096 | 23 | 2 | 1 B |
| 5x2 | anonymous hidden | reply | 1676 | 3240 | 3217 | 4096 | 20 | 2 | 1 B |
| 5x2 | anonymous hidden | messages | 46 | 3226 | 3202 | 4082 | 20 | 2 | 20 B |
| 5x2 | anonymous hidden | message bytes | 1544 | 3240 | 3216 | 4096 | 20 | 2 | 1 B |
| 5x2 | anonymous public owners | reply | 1547 | 3047 | 2991 | 4096 | 24 | 3 | 1 B |
| 5x2 | anonymous public owners | messages | 42 | 3026 | 2969 | 4075 | 24 | 3 | 13 B |
| 5x2 | anonymous public owners | message bytes | 1415 | 3047 | 2990 | 4096 | 24 | 3 | 1 B |
| 5x2 | confidential entry | messages | 29 | 3045 | 2982 | 4094 | 24 | 3 | 32 B |
| 5x2 | confidential entry | message bytes | 954 | 3047 | 2984 | 4096 | 24 | 3 | 1 B |
| 5x2 | anonymous entry | reply | 956 | 3240 | 3185 | 4096 | 20 | 2 | 1 B |
| 5x2 | anonymous entry | messages | 25 | 3232 | 3176 | 4088 | 20 | 2 | 26 B |
| 5x2 | anonymous entry | message bytes | 824 | 3240 | 3184 | 4096 | 20 | 2 | 1 B |
| 5x4 | confidential signer | messages | 34 | 3019 | 3024 | 4068 | 24 | 3 | 6 B |
| 5x4 | confidential signer | message bytes | 1150 | 3047 | 3052 | 4096 | 24 | 3 | 1 B |
| 5x4 | confidential in-proof | messages | 34 | 3115 | 3121 | 4067 | 23 | 2 | 5 B |
| 5x4 | confidential in-proof | message bytes | 1151 | 3144 | 3150 | 4096 | 23 | 2 | 1 B |
| 5x4 | anonymous hidden | reply | 373 | 3239 | 3284 | 4095 | 20 | 2 | 2 B |
| 5x4 | anonymous hidden | messages | 24 | 3228 | 3272 | 4084 | 20 | 2 | 22 B |
| 5x4 | anonymous hidden | message bytes | 794 | 3240 | 3284 | 4096 | 20 | 2 | 1 B |
| 5x4 | anonymous public owners | reply | 330 | 3046 | 3058 | 4095 | 24 | 3 | 2 B |
| 5x4 | anonymous public owners | messages | 20 | 3028 | 3039 | 4077 | 24 | 3 | 15 B |
| 5x4 | anonymous public owners | message bytes | 665 | 3047 | 3058 | 4096 | 24 | 3 | 1 B |
| 5x4 | confidential entry | messages | 14 | 3027 | 3032 | 4076 | 24 | 3 | 14 B |
| 5x4 | confidential entry | message bytes | 462 | 3047 | 3052 | 4096 | 24 | 3 | 1 B |
| 5x4 | anonymous entry | reply | 133 | 3239 | 3252 | 4095 | 20 | 2 | 2 B |
| 5x4 | anonymous entry | messages | 3 | 3234 | 3246 | 4090 | 20 | 2 | 28 B |
| 5x4 | anonymous entry | message bytes | 74 | 3240 | 3252 | 4096 | 20 | 2 | 1 B |
| 5x8 | confidential signer | messages | 5 | 3017 | 3158 | 4066 | 24 | 3 | 4 B |
| 5x8 | confidential signer | message bytes | 166 | 3047 | 3188 | 4096 | 24 | 3 | 1 B |
| 5x8 | confidential in-proof | messages | 5 | 3113 | 3255 | 4065 | 23 | 2 | 3 B |
| 5x8 | confidential in-proof | message bytes | 167 | 3144 | 3286 | 4096 | 23 | 2 | 1 B |
| 5x8 | anonymous hidden | reply | none | - | - | - | - | - | 671 B |
| 5x8 | anonymous hidden | messages | none | - | - | - | - | - | 671 B |
| 5x8 | anonymous hidden | message bytes | none | - | - | - | - | - | 706 B |
| 5x8 | anonymous public owners | reply | none | - | - | - | - | - | 800 B |
| 5x8 | anonymous public owners | messages | none | - | - | - | - | - | 800 B |
| 5x8 | anonymous public owners | message bytes | none | - | - | - | - | - | 835 B |
| 5x8 | confidential entry | messages | none | - | - | - | - | - | 487 B |
| 5x8 | confidential entry | message bytes | none | - | - | - | - | - | 522 B |
| 5x8 | anonymous entry | reply | none | - | - | - | - | - | 1391 B |
| 5x8 | anonymous entry | messages | none | - | - | - | - | - | 1391 B |
| 5x8 | anonymous entry | message bytes | none | - | - | - | - | - | 1426 B |
| 6x2 | confidential signer | messages | 47 | 3001 | 2939 | 4083 | 25 | 3 | 21 B |
| 6x2 | confidential signer | message bytes | 1577 | 3014 | 2952 | 4096 | 25 | 3 | 1 B |
| 6x2 | confidential in-proof | messages | 47 | 3097 | 3036 | 4082 | 24 | 2 | 20 B |
| 6x2 | confidential in-proof | message bytes | 1578 | 3111 | 3050 | 4096 | 24 | 2 | 1 B |
| 6x2 | anonymous hidden | reply | 1611 | 3207 | 3185 | 4096 | 21 | 2 | 1 B |
| 6x2 | anonymous hidden | messages | 44 | 3190 | 3167 | 4079 | 21 | 2 | 17 B |
| 6x2 | anonymous hidden | message bytes | 1479 | 3207 | 3184 | 4096 | 21 | 2 | 1 B |
| 6x2 | anonymous public owners | reply | 1482 | 3014 | 2959 | 4096 | 25 | 3 | 1 B |
| 6x2 | anonymous public owners | messages | 40 | 2990 | 2934 | 4072 | 25 | 3 | 10 B |
| 6x2 | anonymous public owners | message bytes | 1350 | 3014 | 2958 | 4096 | 25 | 3 | 1 B |
| 6x2 | confidential entry | messages | 23 | 3009 | 2947 | 4091 | 25 | 3 | 29 B |
| 6x2 | confidential entry | message bytes | 753 | 3014 | 2952 | 4096 | 25 | 3 | 1 B |
| 6x2 | anonymous entry | reply | 755 | 3207 | 3153 | 4096 | 21 | 2 | 1 B |
| 6x2 | anonymous entry | messages | 19 | 3196 | 3141 | 4085 | 21 | 2 | 23 B |
| 6x2 | anonymous entry | message bytes | 623 | 3207 | 3152 | 4096 | 21 | 2 | 1 B |
| 6x4 | confidential signer | messages | 32 | 2983 | 2989 | 4065 | 25 | 3 | 3 B |
| 6x4 | confidential signer | message bytes | 1085 | 3014 | 3020 | 4096 | 25 | 3 | 1 B |
| 6x4 | confidential in-proof | messages | 32 | 3079 | 3086 | 4064 | 24 | 2 | 2 B |
| 6x4 | confidential in-proof | message bytes | 1086 | 3111 | 3118 | 4096 | 24 | 2 | 1 B |
| 6x4 | anonymous hidden | reply | 351 | 3205 | 3251 | 4094 | 21 | 2 | 1 B |
| 6x4 | anonymous hidden | messages | 22 | 3192 | 3237 | 4081 | 21 | 2 | 19 B |
| 6x4 | anonymous hidden | message bytes | 729 | 3207 | 3252 | 4096 | 21 | 2 | 1 B |
| 6x4 | anonymous public owners | reply | 308 | 3012 | 3025 | 4094 | 25 | 3 | 1 B |
| 6x4 | anonymous public owners | messages | 18 | 2992 | 3004 | 4074 | 25 | 3 | 12 B |
| 6x4 | anonymous public owners | message bytes | 600 | 3014 | 3026 | 4096 | 25 | 3 | 1 B |
| 6x4 | confidential entry | messages | 8 | 2991 | 2997 | 4073 | 25 | 3 | 11 B |
| 6x4 | confidential entry | message bytes | 261 | 3014 | 3020 | 4096 | 25 | 3 | 1 B |
| 6x4 | anonymous entry | reply | none | - | - | - | - | - | 92 B |
| 6x4 | anonymous entry | messages | none | - | - | - | - | - | 92 B |
| 6x4 | anonymous entry | message bytes | none | - | - | - | - | - | 127 B |
| 6x8 | confidential signer | messages | 3 | 2981 | 3123 | 4063 | 25 | 3 | 1 B |
| 6x8 | confidential signer | message bytes | 101 | 3014 | 3156 | 4096 | 25 | 3 | 1 B |
| 6x8 | confidential in-proof | messages | 4 | 3111 | 3254 | 4096 | 24 | 2 | 34 B |
| 6x8 | confidential in-proof | message bytes | 102 | 3111 | 3254 | 4096 | 24 | 2 | 1 B |
| 6x8 | anonymous hidden | reply | none | - | - | - | - | - | 736 B |
| 6x8 | anonymous hidden | messages | none | - | - | - | - | - | 736 B |
| 6x8 | anonymous hidden | message bytes | none | - | - | - | - | - | 771 B |
| 6x8 | anonymous public owners | reply | none | - | - | - | - | - | 865 B |
| 6x8 | anonymous public owners | messages | none | - | - | - | - | - | 865 B |
| 6x8 | anonymous public owners | message bytes | none | - | - | - | - | - | 900 B |
| 6x8 | confidential entry | messages | none | - | - | - | - | - | 688 B |
| 6x8 | confidential entry | message bytes | none | - | - | - | - | - | 723 B |
| 6x8 | anonymous entry | reply | none | - | - | - | - | - | 1592 B |
| 6x8 | anonymous entry | messages | none | - | - | - | - | - | 1592 B |
| 6x8 | anonymous entry | message bytes | none | - | - | - | - | - | 1627 B |
| 8x2 | confidential signer | messages | 43 | 2929 | 2869 | 4077 | 27 | 3 | 15 B |
| 8x2 | confidential signer | message bytes | 1447 | 2948 | 2888 | 4096 | 27 | 3 | 1 B |
| 8x2 | confidential in-proof | messages | 43 | 3025 | 2966 | 4076 | 26 | 2 | 14 B |
| 8x2 | confidential in-proof | message bytes | 1448 | 3045 | 2986 | 4096 | 26 | 2 | 1 B |
| 8x2 | anonymous hidden | reply | 1481 | 3141 | 3121 | 4096 | 23 | 2 | 1 B |
| 8x2 | anonymous hidden | messages | 40 | 3118 | 3097 | 4073 | 23 | 2 | 11 B |
| 8x2 | anonymous hidden | message bytes | 1349 | 3141 | 3120 | 4096 | 23 | 2 | 1 B |
| 8x2 | anonymous public owners | reply | 1352 | 2948 | 2895 | 4096 | 27 | 3 | 1 B |
| 8x2 | anonymous public owners | messages | 36 | 2918 | 2864 | 4066 | 27 | 3 | 4 B |
| 8x2 | anonymous public owners | message bytes | 1220 | 2948 | 2894 | 4096 | 27 | 3 | 1 B |
| 8x2 | confidential entry | messages | 11 | 2937 | 2877 | 4085 | 27 | 3 | 23 B |
| 8x2 | confidential entry | message bytes | 351 | 2948 | 2888 | 4096 | 27 | 3 | 1 B |
| 8x2 | anonymous entry | reply | 353 | 3141 | 3089 | 4096 | 23 | 2 | 1 B |
| 8x2 | anonymous entry | messages | 7 | 3124 | 3071 | 4079 | 23 | 2 | 17 B |
| 8x2 | anonymous entry | message bytes | 221 | 3141 | 3088 | 4096 | 23 | 2 | 1 B |
| 8x4 | confidential signer | messages | 29 | 2945 | 2953 | 4093 | 27 | 3 | 31 B |
| 8x4 | confidential signer | message bytes | 955 | 2948 | 2956 | 4096 | 27 | 3 | 1 B |
| 8x4 | confidential in-proof | messages | 29 | 3041 | 3050 | 4092 | 26 | 2 | 30 B |
| 8x4 | confidential in-proof | message bytes | 956 | 3045 | 3054 | 4096 | 26 | 2 | 1 B |
| 8x4 | anonymous hidden | reply | 308 | 3140 | 3188 | 4095 | 23 | 2 | 2 B |
| 8x4 | anonymous hidden | messages | 18 | 3120 | 3167 | 4075 | 23 | 2 | 13 B |
| 8x4 | anonymous hidden | message bytes | 599 | 3141 | 3188 | 4096 | 23 | 2 | 1 B |
| 8x4 | anonymous public owners | reply | 265 | 2947 | 2962 | 4095 | 27 | 3 | 2 B |
| 8x4 | anonymous public owners | messages | 14 | 2920 | 2934 | 4068 | 27 | 3 | 6 B |
| 8x4 | anonymous public owners | message bytes | 470 | 2948 | 2962 | 4096 | 27 | 3 | 1 B |
| 8x4 | confidential entry | messages | none | - | - | - | - | - | 106 B |
| 8x4 | confidential entry | message bytes | none | - | - | - | - | - | 141 B |
| 8x4 | anonymous entry | reply | none | - | - | - | - | - | 494 B |
| 8x4 | anonymous entry | messages | none | - | - | - | - | - | 494 B |
| 8x4 | anonymous entry | message bytes | none | - | - | - | - | - | 529 B |
| 8x8 | confidential signer | messages | 0 | 2942 | 3087 | 4090 | 27 | 3 | 29 B |
| 8x8 | confidential signer | message bytes | none | - | - | - | - | - | 29 B |
| 8x8 | confidential in-proof | messages | 0 | 3038 | 3184 | 4089 | 26 | 2 | 28 B |
| 8x8 | confidential in-proof | message bytes | none | - | - | - | - | - | 28 B |
| 8x8 | anonymous hidden | reply | none | - | - | - | - | - | 866 B |
| 8x8 | anonymous hidden | messages | none | - | - | - | - | - | 866 B |
| 8x8 | anonymous hidden | message bytes | none | - | - | - | - | - | 901 B |
| 8x8 | anonymous public owners | reply | none | - | - | - | - | - | 995 B |
| 8x8 | anonymous public owners | messages | none | - | - | - | - | - | 995 B |
| 8x8 | anonymous public owners | message bytes | none | - | - | - | - | - | 1030 B |
| 8x8 | confidential entry | messages | none | - | - | - | - | - | 1090 B |
| 8x8 | confidential entry | message bytes | none | - | - | - | - | - | 1125 B |
| 8x8 | anonymous entry | reply | none | - | - | - | - | - | 1994 B |
| 8x8 | anonymous entry | messages | none | - | - | - | - | - | 1994 B |
| 8x8 | anonymous entry | message bytes | none | - | - | - | - | - | 2029 B |
| 12x2 | confidential signer | messages | 35 | 2786 | 2729 | 4066 | 31 | 3 | 4 B |
| 12x2 | confidential signer | message bytes | 1186 | 2816 | 2759 | 4096 | 31 | 3 | 1 B |
| 12x2 | confidential in-proof | messages | 35 | 2882 | 2826 | 4065 | 30 | 2 | 3 B |
| 12x2 | confidential in-proof | message bytes | 1187 | 2913 | 2857 | 4096 | 30 | 2 | 1 B |
| 12x2 | anonymous hidden | reply | 1220 | 3009 | 2992 | 4096 | 27 | 2 | 1 B |
| 12x2 | anonymous hidden | messages | 33 | 3009 | 2991 | 4096 | 27 | 2 | 34 B |
| 12x2 | anonymous hidden | message bytes | 1088 | 3009 | 2991 | 4096 | 27 | 2 | 1 B |
| 12x2 | anonymous public owners | reply | 1091 | 2816 | 2766 | 4096 | 31 | 3 | 1 B |
| 12x2 | anonymous public owners | messages | 29 | 2809 | 2758 | 4089 | 31 | 3 | 27 B |
| 12x2 | anonymous public owners | message bytes | 959 | 2816 | 2765 | 4096 | 31 | 3 | 1 B |
| 12x4 | confidential signer | messages | 21 | 2802 | 2813 | 4082 | 31 | 3 | 20 B |
| 12x4 | confidential signer | message bytes | 694 | 2816 | 2827 | 4096 | 31 | 3 | 1 B |
| 12x4 | confidential in-proof | messages | 21 | 2898 | 2910 | 4081 | 30 | 2 | 19 B |
| 12x4 | confidential in-proof | message bytes | 695 | 2913 | 2925 | 4096 | 30 | 2 | 1 B |
| 12x4 | anonymous hidden | reply | 221 | 3008 | 3059 | 4095 | 27 | 2 | 2 B |
| 12x4 | anonymous hidden | messages | 10 | 2977 | 3027 | 4064 | 27 | 2 | 2 B |
| 12x4 | anonymous hidden | message bytes | 338 | 3009 | 3059 | 4096 | 27 | 2 | 1 B |
| 12x4 | anonymous public owners | reply | 178 | 2815 | 2833 | 4095 | 31 | 3 | 2 B |
| 12x4 | anonymous public owners | messages | 7 | 2811 | 2828 | 4091 | 31 | 3 | 29 B |
| 12x4 | anonymous public owners | message bytes | 209 | 2816 | 2833 | 4096 | 31 | 3 | 1 B |
| 12x8 | confidential signer | messages | none | - | - | - | - | - | 255 B |
| 12x8 | confidential signer | message bytes | none | - | - | - | - | - | 290 B |
| 12x8 | confidential in-proof | messages | none | - | - | - | - | - | 254 B |
| 12x8 | confidential in-proof | message bytes | none | - | - | - | - | - | 289 B |
| 12x8 | anonymous hidden | reply | none | - | - | - | - | - | 1127 B |
| 12x8 | anonymous hidden | messages | none | - | - | - | - | - | 1127 B |
| 12x8 | anonymous hidden | message bytes | none | - | - | - | - | - | 1162 B |
| 12x8 | anonymous public owners | reply | none | - | - | - | - | - | 1256 B |
| 12x8 | anonymous public owners | messages | none | - | - | - | - | - | 1256 B |
| 12x8 | anonymous public owners | message bytes | none | - | - | - | - | - | 1291 B |
| 16x2 | confidential signer | messages | 28 | 2676 | 2623 | 4088 | 35 | 3 | 26 B |
| 16x2 | confidential signer | message bytes | 926 | 2684 | 2631 | 4096 | 35 | 3 | 1 B |
| 16x2 | confidential in-proof | messages | 28 | 2772 | 2720 | 4087 | 34 | 2 | 25 B |
| 16x2 | confidential in-proof | message bytes | 927 | 2781 | 2729 | 4096 | 34 | 2 | 1 B |
| 16x2 | anonymous hidden | reply | 960 | 2877 | 2864 | 4096 | 31 | 2 | 1 B |
| 16x2 | anonymous hidden | messages | 25 | 2865 | 2851 | 4084 | 31 | 2 | 22 B |
| 16x2 | anonymous hidden | message bytes | 828 | 2877 | 2863 | 4096 | 31 | 2 | 1 B |
| 16x2 | anonymous public owners | reply | 831 | 2684 | 2638 | 4096 | 35 | 3 | 1 B |
| 16x2 | anonymous public owners | messages | 21 | 2665 | 2618 | 4077 | 35 | 3 | 15 B |
| 16x2 | anonymous public owners | message bytes | 699 | 2684 | 2637 | 4096 | 35 | 3 | 1 B |
| 16x4 | confidential signer | messages | 13 | 2658 | 2673 | 4070 | 35 | 3 | 8 B |
| 16x4 | confidential signer | message bytes | 434 | 2684 | 2699 | 4096 | 35 | 3 | 1 B |
| 16x4 | confidential in-proof | messages | 13 | 2754 | 2770 | 4069 | 34 | 2 | 7 B |
| 16x4 | confidential in-proof | message bytes | 435 | 2781 | 2797 | 4096 | 34 | 2 | 1 B |
| 16x4 | anonymous hidden | reply | 134 | 2875 | 2930 | 4094 | 31 | 2 | 1 B |
| 16x4 | anonymous hidden | messages | 3 | 2867 | 2921 | 4086 | 31 | 2 | 24 B |
| 16x4 | anonymous hidden | message bytes | 78 | 2877 | 2931 | 4096 | 31 | 2 | 1 B |
| 16x4 | anonymous public owners | reply | none | - | - | - | - | - | 16 B |
| 16x4 | anonymous public owners | messages | none | - | - | - | - | - | 16 B |
| 16x4 | anonymous public owners | message bytes | none | - | - | - | - | - | 51 B |
| 16x8 | confidential signer | messages | none | - | - | - | - | - | 515 B |
| 16x8 | confidential signer | message bytes | none | - | - | - | - | - | 550 B |
| 16x8 | confidential in-proof | messages | none | - | - | - | - | - | 514 B |
| 16x8 | confidential in-proof | message bytes | none | - | - | - | - | - | 549 B |
| 16x8 | anonymous hidden | reply | none | - | - | - | - | - | 1387 B |
| 16x8 | anonymous hidden | messages | none | - | - | - | - | - | 1387 B |
| 16x8 | anonymous hidden | message bytes | none | - | - | - | - | - | 1422 B |
| 16x8 | anonymous public owners | reply | none | - | - | - | - | - | 1516 B |
| 16x8 | anonymous public owners | messages | none | - | - | - | - | - | 1516 B |
| 16x8 | anonymous public owners | message bytes | none | - | - | - | - | - | 1551 B |
| 24x2 | confidential signer | messages | 12 | 2389 | 2343 | 4065 | 43 | 3 | 3 B |
| 24x2 | confidential signer | message bytes | 405 | 2420 | 2374 | 4096 | 43 | 3 | 1 B |
| 24x2 | confidential in-proof | messages | 12 | 2485 | 2440 | 4064 | 42 | 2 | 2 B |
| 24x2 | confidential in-proof | message bytes | 406 | 2517 | 2472 | 4096 | 42 | 2 | 1 B |
| 24x2 | anonymous hidden | reply | 439 | 2613 | 2607 | 4096 | 39 | 2 | 1 B |
| 24x2 | anonymous hidden | messages | 10 | 2612 | 2605 | 4095 | 39 | 2 | 33 B |
| 24x2 | anonymous hidden | message bytes | 307 | 2613 | 2606 | 4096 | 39 | 2 | 1 B |
| 24x2 | anonymous public owners | reply | 310 | 2420 | 2381 | 4096 | 43 | 3 | 1 B |
| 24x2 | anonymous public owners | messages | 6 | 2412 | 2372 | 4088 | 43 | 3 | 26 B |
| 24x2 | anonymous public owners | message bytes | 178 | 2420 | 2380 | 4096 | 43 | 3 | 1 B |
| 24x4 | confidential signer | messages | none | - | - | - | - | - | 52 B |
| 24x4 | confidential signer | message bytes | none | - | - | - | - | - | 87 B |
| 24x4 | confidential in-proof | messages | none | - | - | - | - | - | 51 B |
| 24x4 | confidential in-proof | message bytes | none | - | - | - | - | - | 86 B |
| 24x4 | anonymous hidden | reply | none | - | - | - | - | - | 408 B |
| 24x4 | anonymous hidden | messages | none | - | - | - | - | - | 408 B |
| 24x4 | anonymous hidden | message bytes | none | - | - | - | - | - | 443 B |
| 24x4 | anonymous public owners | reply | none | - | - | - | - | - | 537 B |
| 24x4 | anonymous public owners | messages | none | - | - | - | - | - | 537 B |
| 24x4 | anonymous public owners | message bytes | none | - | - | - | - | - | 572 B |
| 32x2 | confidential signer | messages | none | - | - | - | - | - | 81 B |
| 32x2 | confidential signer | message bytes | none | - | - | - | - | - | 116 B |
| 32x2 | confidential in-proof | messages | none | - | - | - | - | - | 80 B |
| 32x2 | confidential in-proof | message bytes | none | - | - | - | - | - | 115 B |
| 32x2 | anonymous hidden | reply | none | - | - | - | - | - | 179 B |
| 32x2 | anonymous hidden | messages | none | - | - | - | - | - | 179 B |
| 32x2 | anonymous hidden | message bytes | none | - | - | - | - | - | 214 B |
| 32x2 | anonymous public owners | reply | none | - | - | - | - | - | 308 B |
| 32x2 | anonymous public owners | messages | none | - | - | - | - | - | 308 B |
| 32x2 | anonymous public owners | message bytes | none | - | - | - | - | - | 343 B |
| 40x2 | confidential signer | messages | none | - | - | - | - | - | 602 B |
| 40x2 | confidential signer | message bytes | none | - | - | - | - | - | 637 B |
| 40x2 | confidential in-proof | messages | none | - | - | - | - | - | 601 B |
| 40x2 | confidential in-proof | message bytes | none | - | - | - | - | - | 636 B |
| 40x2 | anonymous hidden | reply | none | - | - | - | - | - | 700 B |
| 40x2 | anonymous hidden | messages | none | - | - | - | - | - | 700 B |
| 40x2 | anonymous hidden | message bytes | none | - | - | - | - | - | 735 B |
| 40x2 | anonymous public owners | reply | none | - | - | - | - | - | 829 B |
| 40x2 | anonymous public owners | messages | none | - | - | - | - | - | 829 B |
| 40x2 | anonymous public owners | message bytes | none | - | - | - | - | - | 864 B |
