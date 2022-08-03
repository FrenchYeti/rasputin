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

[[https://koodous.com/rules/N7QqMdLzegGAm4eW/general](https://koodous.com/rules/N7QqMdLzegGAm4eW/general)]
[[https://koodous.com/rules/8J2m7OlMr6dvRPao/general](https://koodous.com/rules/8J2m7OlMr6dvRPao/general)]

## Ghidra scripts

Several scripts are coming. Please find someone below, for each i encourage you to verify if it's your case before to run it.
Most of scripts use Ghidra's PCode emulation

### Inlined strings


These scripts can be run within a specified range of address or over the entire program. If your target program decipher and map executable code dynamically, you should require to dump final executable code before to execute these scripts.

[[Inlined strings 1](https://github.com/FrenchYeti/rasputin/blob/main/Ghidra/inlined_string_1.py)]



