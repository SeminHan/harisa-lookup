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
    #[structopt(short="n", long="set", default_value = "8")]
    set: u32,

    #[structopt(short="m", long="batch", default_value = "16")]
    batch: usize
}

fn bench_lookup(c: &mut Criterion, set: u32, batch: usize) {
    c.bench_function(&format!("N: {}, m:{}", set, batch), |b| {
        b.iter(|| test_lookup_arbit::<Bn254>(set, batch))
    });
}

fn bench_lookup_w_args(c: &mut Criterion) {
    let opt = Opt::from_args();
    bench_lookup(c, opt.set, opt.batch)
}

criterion_group!(benches, bench_lookup_w_args);
criterion_main!(benches);