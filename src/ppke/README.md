Command used to compile RELIC:

```sh
cd relic;
mkdir build;
cd build;
cmake -G "Unix Makefiles" -DMULTI=PTHREAD -DCOMP="-O3 -funroll-loops -fomit-frame-pointer -finline-small-functions -march=native -mtune=native" -DARCH="X64"  -DRAND="UDEV" -DWITH="BN;DV;FP;FPX;EP;EPX;PP;PC;MD" -DCHECK=off -DVERBS=off -DDEBUG=off -DBENCH=0 -DTESTS=1 -DARITH=gmp -DFP_PRIME=254 -DFP_QNRES=off -DFP_METHD="INTEG;INTEG;INTEG;MONTY;LOWER;SLIDE" -DFPX_METHD="INTEG;INTEG;LAZYR" -DPP_METHD="LAZYR;OATEP" -DBN_PRECI=256 -DFP_QNRES=on ../.;
make -j;
```