#!/bin/zsh

index=1

for i in {1..5};
do
    filename="./bench_result/set_11_batch_1024_${index}.txt"

    cargo test -r --package harisa-rs --features "parallel print-trace" --lib -- lookup::test::test_lookup_bench --exact --show-output >> "$filename"

    index=$((index+1))
done