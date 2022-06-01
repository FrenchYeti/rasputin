# RASPutin

Ressources and papers related to my conferences and work on (un)RASPs.
These work is in progress, please be patient :) Don't hesitate to contribute / contact me / do PR !

## Talks

*Insomni'hack 2022 - Forging golden hammer against Android app protections*

This talk is the first from a new serie.

[[Slides](https://github.com/FrenchYeti/unrasp/blob/main/Slides/Forging_golden_hammer_against_android_app_protections_INSO22_FINAL.pdf)]
[[Abstract (Insomni'hack website)](https://insomnihack.ch/talks-2022/#MUX7KC)]

## Yara rules / RASP profiling

Several rules are active on Koodous. They can be used to detect trojanized version of legitimate apps. Follow [Dexcalibur account](https://koodous.com/profile/dexcalibur/followers) to stay tunned.

[[Dexguard 9.x](https://koodous.com/rules/oKByDd2YmXOY8mnP/general)]
[[Verimatrix Pattern](https://koodous.com/rules/N7QqMdLzegGAm4eW/general)]
[[Verimatrix Barriers + Cache Control instructions](https://koodous.com/rules/8J2m7OlMr6dvRPao/general)]

## Ghidra scripts

Several scripts are coming. Please find someone below, for each i encourage you to verify if it's your case before to run it.

### Inlined strings
These scripts can be run within a specified range of address or over the entire program. If your target program decipher and map executable code dynamically, you should require to dump final executable code before to execute these scripts.

[[Inlined strings 1](https://github.com/FrenchYeti/rasputin/blob/main/Ghidra/inlined_string_1.py)]

**Inlined_strings_1 : A flag holds the state of the string (deciphered or not), Not-NULL terminated, while  or do-while-switch**
Output example:
```
[Java_o_x_e] from 0x0010fabc . At 0x00128aaa (len:21) : /system/bin/nox-prop\x00
[Java_o_x_e] from 0x0010fadb . At 0x00128bbb (len:16) : /system/bin/noxd
[Java_o_x_e] from 0x0010faef . At 0x00128ccc (len:24) : /system/bin/nox-vbox-sf\x00
[Java_o_x_e] from 0x0010fa12 . At 0x00128ddd (len:23) : /system/bin/noxspeedup\x00
[Java_o_x_e] from 0x0010fa34 . At 0x00128eee (len:29) : /system/lib/libnoxspeedup.so\x00
[Java_o_x_e] from 0x0010fb21 . At 0x00128fff (len:23) : /system/lib/libnoxd.so\x00
Deciphering address --^^^              
                 Data address ----^^^
```

This script works well with *while* loops and do-while with nested switch.


```
  if ((DAT_00dead_flag & 1) == 0) {
    i = 0;
    cVar2 = '\0';
    while( true ) {
      while (cVar2 == '\x01') {
        DAT_00dead_flag = 1;
        cVar2 = '\x02';
      }
      if (cVar2 != '\0') break;
      (&DAT_00beef_string)[i] = (&DAT_00beef_string)[i] + <CONSTANT>;
      i = i + 1;
      cVar2 = i == 0xf;
    }
    if (cVar2 != '\x02') {
      do {} while( true );
    }
  }

```

```
  if ((DAT_00dead_flag & 1) == 0) {
    uVar16 = 0;
    cVar14 = '\0';
    while( true ) {
      while (cVar14 == '\x01') {
        DAT_00dead_flag = 1;
        cVar14 = '\x02';
      }
      if (cVar14 != '\0') break;
      (&DAT_00beef_string)[uVar16] = "<LOOOOOONNNNGGGG_XOR_KEY>"[uVar16 % 0x12] ^ (&DAT_00beef_string)[uVar16];
      uVar16 = uVar16 + 1;
      cVar14 = uVar16 == 0x18;
    }
    if (cVar14 != '\x02') {
      do {} while( true );
    }
  }
```


```
    if ((DAT_00dead_flag & 1) == 0) {
      uVar10 = 0;
      lVar15 = 0;
      lVar17 = extraout_x14;
      do {
        switch(uVar10) {
        case 0:
          uVar23 = *(ulong *)(lVar15 + 0x1abcde);
          uVar16 = *(ulong *)(&DAT_00beef_string + lVar15);
          uVar27 = *(ulong *)(lVar15 + 0x1283f5);
          uVar25 = *(ulong *)(&DAT_<ADDR_i> + lVar15);
          uVar10 = lVar15 == 0;
          *(ulong *)(lVar15 + <OFFSET_x>) =
               CONCAT17((char)((uVar23 & 0xffffff0000000000) >> 0x38) + -0x10,
                        CONCAT16((char)((uVar23 & 0xffffff0000000000) >> 0x30) + -0x10,
                                 CONCAT15((char)(uVar23 >> 0x28) + -0x10,
                                          CONCAT14((char)(uVar23 >> 0x20) + -0x10,
                                                   CONCAT13((char)(uVar23 >> 0x18) + -0x10,
                                                            CONCAT12((char)(uVar23 >> 0x10) + -0x10,
                                                                     CONCAT11((char)(uVar23 >> 8) +
                                                                              -0x10,(char)uVar23 +
                                                                                    -0x10)))))));
          *(ulong *)(&DAT_<ADDR_y> + lVar15) =
               CONCAT17((char)((uVar16 & 0xffffff0000000000) >> 0x38) + -0x10,
                        CONCAT16((char)((uVar16 & 0xffffff0000000000) >> 0x30) + -0x10,
                                 CONCAT15((char)(uVar16 >> 0x28) + -0x10,
                                          CONCAT14((char)(uVar16 >> 0x20) + -0x10,
                                                   CONCAT13((char)(uVar16 >> 0x18) + -0x10,
                                                            CONCAT12((char)(uVar16 >> 0x10) + -0x10,
                                                                     CONCAT11((char)(uVar16 >> 8) +
                                                                              -0x10,(char)uVar16 +
                                                                                    -0x10)))))));
          *(ulong *)(lVar15 + <OFFSET_z>) =
               CONCAT17((char)((uVar27 & 0xffffff0000000000) >> 0x38) + -0x10,
                        CONCAT16((char)((uVar27 & 0xffffff0000000000) >> 0x30) + -0x10,
                                 CONCAT15((char)(uVar27 >> 0x28) + -0x10,
                                          CONCAT14((char)(uVar27 >> 0x20) + -0x10,
                                                   CONCAT13((char)(uVar27 >> 0x18) + -0x10,
                                                            CONCAT12((char)(uVar27 >> 0x10) + -0x10,
                                                                     CONCAT11((char)(uVar27 >> 8) +
                                                                              -0x10,(char)uVar27 +
                                                                                    -0x10)))))));
          *(ulong *)(&DAT_<ADDR_i> + lVar15) =
               CONCAT17((char)((uVar25 & 0xffffff0000000000) >> 0x38) + -0x10,
                        CONCAT16((char)((uVar25 & 0xffffff0000000000) >> 0x30) + -0x10,
                                 CONCAT15((char)(uVar25 >> 0x28) + -0x10,
                                          CONCAT14((char)(uVar25 >> 0x20) + -0x10,
                                                   CONCAT13((char)(uVar25 >> 0x18) + -0x10,
                                                            CONCAT12((char)(uVar25 >> 0x10) + -0x10,
                                                                     CONCAT11((char)(uVar25 >> 8) +
                                                                              -0x10,(char)uVar25 +
                                                                                    -0x10)))))));
          lVar15 = lVar15 + 0x20;
          break;
        case 1:
          uVar10 = 2;
          lVar17 = 0x20;
          break;
        case 2:
          (&DAT_00beef_string)[lVar17] = (&DAT_00beef_string)[lVar17] + <CONSTANT>;
          lVar17 = lVar17 + 1;
          uVar10 = 2;
          if (lVar17 == 0x27) {
            uVar10 = 3;
          }
          break;
        case 3:
          DAT_00dead_flag = 1;
          uVar10 = 4;
          break;
        case 4:
          goto switchD_0010ee00_caseD_4;
        default:
          goto switchD_0010ee00_caseD_5;
        }
      } while( true );
    }
```



