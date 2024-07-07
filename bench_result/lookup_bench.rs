extern crate criterion;
extern crate structopt;
extern crate harisa_rs;

use criterion::{criterion_group, criterion_main,Criterion};
use structopt::StructOpt;
use harisa_rs::lookup::test::test_lookup_arbit;
use ark_bn254::Bn254;

#[derive(StructOpt, Debug)]
#[structopt(name = "bench")]
struct Opt {
    #[structopt(short="n", long="set", default_value = "1024")]
    set_size: usize,

    #[structopt(short="m", long="batch", default_value = "16")]
    batch_size: usize
}

fn bench_lookup(c: &mut Criterion, set_size: usize, batch_size: usize) {
    c.bench_function(&format!("N: {} \t m: {}", set_size, batch_size), |b| b.iter(|| test_lookup_arbit::<Bn254>(set_size, batch_size)));
}

criterion_group!(benches, bench_lookup);
criterion_main!(benches);