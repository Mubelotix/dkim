#![feature(test)]

extern crate test;
use std::convert::TryFrom;
use dkim::canonicalization::*;
use test::Bencher;

#[bench] // 2,521 ns/iter (+/- 54)
fn canonicalize_headers_relaxed_bench(b: &mut Bencher) {
    const MAIL: &str = "A: X\r\nB : Y\t\r\n\tZ  \r\n\r\n C \r\nD \t E\r\n\r\n\r\n";
    let (headers, body) = email_parser::parser::parse_message(MAIL.as_bytes()).unwrap();

    let headers: Vec<(&str, &str)> = headers.iter().filter_map(|(n, v)| {
        if let (Ok(name), Ok(value)) = (std::str::from_utf8(n), std::str::from_utf8(v)) {
            Some((name, value))
        } else {
            None
        }
    }).collect();

    b.iter(|| {
        canonicalize_headers_relaxed(&headers, &["a".to_string(), "b".to_string()]);
        canonicalize_headers_relaxed(&headers, &["b".to_string(), "a".to_string()]);
    });
}

#[bench] // 1,423 ns/iter (+/- 76)
fn canonicalize_headers_simple_bench(b: &mut Bencher) {
    const MAIL: &str = "A: X\r\nB : Y\t\r\n\tZ  \r\n";

    b.iter(|| {
        canonicalize_headers_simple(MAIL, &["a".to_string(), "b".to_string()]);
        canonicalize_headers_simple(MAIL, &["b".to_string(), "a".to_string()]);
    });
}
