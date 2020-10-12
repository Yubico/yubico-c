#!/bin/sh -eux

make clean
make -C .. clean
make CFLAGS="-fprofile-instr-generate -fcoverage-mapping" -C ..
make CFLAGS="-fprofile-instr-generate -fcoverage-mapping"
if [ ! -e "corpus" ]; then
    curl --retry 4 -s -o corpus.tgz https://storage.googleapis.com/kroppkaka/corpus/yubico-c.corpus.tgz
    tar xzf corpus.tgz
fi
./fuzz_libyubikey -runs=1 -dump_coverage=1 corpus
llvm-profdata merge -sparse *.profraw -o default.profdata

llvm-cov report -show-functions -instr-profile=default.profdata fuzz_libyubikey ../*.c fuzz_libyubikey.c

# other report alternatives for convenience:
#llvm-cov report -use-color=false -instr-profile=default.profdata fuzz_libyubikey
#llvm-cov show -format=html -tab-size=8 -instr-profile=default.profdata -output-dir=report fuzz_libyubikey
#llvm-cov show fuzz_libyubikey -instr-profile=default.profdata --show-line-counts-or-regions -format=html > report.html
