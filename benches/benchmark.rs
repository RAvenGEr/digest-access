use criterion::{criterion_group, criterion_main, Criterion};
use digest_access::DigestAccess;

fn full_cycle(c: &mut Criterion) {
    let rfc7616_test = r#"Digest
    realm="api@example.org",
    qop="auth",
    algorithm=SHA-512-256,
    nonce="5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK",
    opaque="HRPCssKJSGjCrkzDg8OhwpzCiGPChXYjwrI2QmXDnsOS",
    charset=UTF-8,
    userhash=true"#;

    c.bench_function("parse", |b| {
        b.iter(|| rfc7616_test.parse::<DigestAccess>().unwrap())
    });

    c.bench_function("set username and password", |b| {
        let mut d = rfc7616_test.parse::<DigestAccess>().unwrap();
        b.iter(|| {
            d.set_username("Jäsøn Doe");
            d.set_password("Secret, or not?");
        })
    });

    c.bench_function("generate authorization", |b| {
        let mut d = rfc7616_test.parse::<DigestAccess>().unwrap();
        d.set_username("Jäsøn Doe");
        d.set_password("Secret, or not?");
        b.iter(|| {
            d.generate_authorization(
                "GET",
                "/doe.json",
                None,
                Some("NTg6RKcb9boFIAS3KrFK9BGeh+iDa/sm6jUMp2wds69v"),
            );
        })
    });
}

criterion_group!(benches, full_cycle);
criterion_main!(benches);
