#!/bin/zsh

index=1

for i in {1..10};
do
    filename="./bench_result/set_8_batch_16_${index}.txt"

    cargo test -r --package harisa-rs --features "parallel print-trace" --lib -- lookup::test::test_lookup_bench --exact --show-output >> "$filename"

    index=$((index+1))
done