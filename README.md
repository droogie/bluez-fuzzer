# bluez-fuzzer

This is a fork of `aur/bluez-utils-compat` to quickly build modified deprecated bluez utilities to perform some generic dumb fuzzing. This has not been tested much at all, but I can tell you that 60% of the time it works every time.

The main changes at the moment are `./attrib/gatttool` having a `fuzz` command in the interactive mode which will automatically perform a discovery of primary services and perform fuzzing against the returned valid ranges of handles. The other being `./tool/l2ping` which just generically fuzzes l2cap packets. 

## Build

`./build.sh`, if it doesn't work check what dependencies are necessary for `aur/bluez-utils-compat`

Ubuntu users have reported the following packages being required:
```
sudo apt install libdbus-1-dev
sudo apt install libudev-dev
sudo apt install libjson-c-dev
sudo apt install libical-dev
sudo apt install libreadline-dev
sudo apt -y install python3-docutils
```

## Examples

gatt fuzzing:

```
$ sudo ./attrib/gatttool -b XX:XX:XX:XX:XX:XX -I
[XX:XX:XX:XX:XX:XX][LE]> connect
Attempting to connect to XX:XX:XX:XX:XX:XX
Connection successful
[XX:XX:XX:XX:XX:XX][LE]> fuzz
Fuzzer starting!
seed: 0x633be7c5
[XX:XX:XX:XX:XX:XX][LE]> 
total services discovered: 8
fuzzing handle: 0x003f len: 0x14
CA AC 17 DB 7A 76 CB A8  09 DE C4 77 B1 11 37 67  |  ....zv.....w..7g 
D2 B9 63 A7                                       |  ..c. 
fuzzing handle: 0x0031 len: 0x08
07 81 59 D7 4F A0 DA 19                           |  ..Y.O... 
fuzzing handle: 0x000e len: 0x08
68 BF 6F 71 9E 33 E8 4F                           |  h.oq.3.O 
fuzzing handle: 0x588d len: 0x08
D8 1A BE A1 A7 BD 04 AE                           |  ........ 
fuzzing handle: 0x003e len: 0x02
FD 5F                                             |  ._ 
...
```

l2cap fuzzing:

```
$ sudo ./tools/l2ping XX:XX:XX:XX:XX:XX
Fuzzer starting!
seed: 0x633be865
Ping: XX:XX:XX:XX:XX:XX from YY:YY:YY:YY:YY:YY (data size 44) ...
fuzzing code: 0x2
02 C8 1D 00 46 3C 3F F6  1A 95 80 A7 F2 C2 86 9C  |  ....F<?......... 
E3 30 D1 AB 50 6E 99 8C  D8 5A 55 18 FE 26 97 3D  |  .0..Pn...ZU..&.= 
A8                                                |  . 
.fuzzing code: 0x6
06 C8 A2 00 9A E5 BD 2F  65 64 21 27 EA BD 0B 1B  |  ......./ed!'.... 
8F B6 6B FD 4F F8 D6 A9  4D EE A7 73 85 E5 1C EB  |  ..k.O...M..s.... 
40 0B 8E DA F0 4B 09 55  AF 2A 7D 99 E7 88 B4 76  |  @....K.U.*}....v 
3E 20 74 8E 18 4A 37 65  38 DF D8 BE C4 F4 A9 04  |  > t..J7e8....... 
FF 37 DE EF 82 E7 45 31  11 C2 CB F8 4A 7F 6F 88  |  .7....E1....J.o. 
9F E3 16 B7 2D 4E 1C 65  2D F5 23 F1 E9 CD F5 E9  |  ....-N.e-.#..... 
04 D3 D8 87 BA 1D B8 CB  DF 83 C3 29 03 32 B2 A2  |  ...........).2.. 
15 C8 5A 42 16 76 A8 43  6B CB 34 55 98 29 3E 9D  |  ..ZB.v.Ck.4U.)>. 
FC 16 24 B6 34 DC 81 13  60 45 3D 63 77 EF 05 8D  |  ..$.4...`E=cw... 
B7 5F CF CE D6 77 11 41  43 46 96 DB 6F D4 78 6C  |  ._...w.ACF..o.xl 
EB 9C 22 1F 79 A4                                 |  ..".y. 
.fuzzing code: 0x11
11 ED 6F 00 3C 60 5E 41  ED 16 A1 BD E4 77 34 F5  |  ..o.<`^A.....w4. 
B8 77 3B 4F 53 AB 23 CB  17 0E 68 39 2D E1 DD 60  |  .w;OS.#...h9-..` 
BA C6 CF F6 27 2E 37 14  44 D8 D1 28 4F 06 1D 08  |  ....'.7.D..(O... 
7D 59 57 D0 04 7A 9C 1B  89 04 54 B6 E5 32 16 9F  |  }YW..z....T..2.. 
F8 E6 95 1F 14 CC 34 58  A5 05 80 F4 0B 9D FC 89  |  ......4X........ 
F6 53 59 FA CE F5 15 57  F9 6A 0D DE 9C 24 7D 94  |  .SY....W.j...$}. 
0A 12 B4 1E DF E8 76 84  ED F6 78 F9 93 75 82 8A  |  ......v...x..u.. 
C8 DB 84                                          |  ... 
.fuzzing code: 0xc
0C 85 CA 00 04 FB A9 A0  1F 26 34 29 39 E8 47 18  |  .........&4)9.G. 
D0 BD 9C BE B3 14 B7 46  89 39 D0 52 14 55 E8 E5  |  .......F.9.R.U.. 
EF D6 B0 F3 D1 59 93 F0  7F C7 19 B8 B0 60 D0 80  |  .....Y.......`.. 
1D 6C 3E D0 81 F5 16 0A  2E E7 5C 43 3C 45 28 2B  |  .l>.......\C<E(+ 
1B D8 1E EC 31 B1 DC B1  78 F5 69 28 55 3A A9 72  |  ....1...x.i(U:.r 
A6 E7 42 27 DD 58 32 0B  3F 8E 4E 7B D3 77 A6 EE  |  ..B'.X2.?.N{.w.. 
4F C4 DA 81 75 B6 32 EE  AB 9B 16 00 D5 BF 72 7C  |  O...u.2.......r| 
A7 B4 A3 84 0D D5 8F 4C  64 DE C8 37 55 6E 26 A4  |  .......Ld..7Un&. 
33 00 25 A8 B7 57 96 62  F3 AD 63 C8 6C D5 44 13  |  3.%..W.b..c.l.D. 
8A E8 97 97 BD 27 E3 21  05 AB 59 5A 1A 7F FE 4D  |  .....'.!..YZ...M 
7F 24 F5 36 7B 8C 99 6E  39 FC 37 A5 D1 7B B9 5B  |  .$.6{..n9.7..{.[ 
63 50 F2 21 77 D6 42 7C  81 9B D6 9B 1A D5 E8 9A  |  cP.!w.B|........ 
F9 DE D0 74 6A 69 E3 A3  65 1A 48 37 95 01        |  ...tji..e.H7.. 
.fuzzing code: 0xf
0F C8 1A 00 C9 5B 5C 46  DC F8 1C 78 12 F1 60 AC  |  .....[\F...x..`. 
EA 3E 7D 5F A8 E6 42 4B  4C 5C 94 83 F1 95        |  .>}_..BKL\.... 
```

