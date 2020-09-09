#![feature(test)]

extern crate test;
use dkim::{canonicalization::*, dkim::Header};
use test::Bencher;

#[bench] // 1,249 ns/iter (+/- 24)
fn canonicalize_headers_relaxed_bench(b: &mut Bencher) {
    const MAIL: &str = "A: X\r\nB : Y\t\r\n\tZ  \r\n\r\n C \r\nD \t E\r\n\r\n\r\n";
    let (headers, body) =
        email_parser::parser::parse_message(MAIL.as_bytes()).unwrap();

    let headers: Vec<(&str, &str)> = headers
        .iter()
        .filter_map(|(n, v)| {
            if let (Ok(name), Ok(value)) = (
                std::str::from_utf8(n),
                std::str::from_utf8(v),
            ) {
                Some((name, value))
            } else {
                None
            }
        })
        .collect();

    b.iter(|| {
        canonicalize_headers_relaxed(&headers, &["a", "b"]);
        canonicalize_headers_relaxed(&headers, &["b", "a"]);
    });
}

#[bench] // 347 ns/iter (+/- 17)
fn canonicalize_headers_simple_bench(b: &mut Bencher) {
    const MAIL: &str = "A: X\r\nB : Y\t\r\n\tZ  \r\n\r\n C \r\nD \t E\r\n\r\n\r\n";
    let (headers, body) =
        email_parser::parser::parse_message(MAIL.as_bytes()).unwrap();

    let headers: Vec<(&str, &str)> = headers
        .iter()
        .filter_map(|(n, v)| {
            if let (Ok(name), Ok(value)) = (
                std::str::from_utf8(n),
                std::str::from_utf8(v),
            ) {
                Some((name, value))
            } else {
                None
            }
        })
        .collect();

    b.iter(|| {
        canonicalize_headers_simple(&headers, &["a", "b"]);
        canonicalize_headers_simple(&headers, &["b", "a"]);
    });
}

#[bench] // 2,779 ns/iter (+/- 227)
fn parse_dkim_header(b: &mut Bencher) {
    b.iter(|| {
        let header = Header::parse("Dkim-Signature", " v=1; a=rsa-sha256; d=example.net; s=brisbane; c=simple; q=dns/txt; i=@eng.example.net; t=1117574938; x=1118006938; h=from:to:subject:date; bh=MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=; b=dzdVyOfAKCdLXdJOc9G2q8LoXSlEniSbav+yuU4zGeeruD00lszZVoG4ZHRNiYzR").unwrap();
    });
}
