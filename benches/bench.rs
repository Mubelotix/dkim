#![feature(test)]

extern crate test;
use dkim::canonicalization::*;
use std::convert::TryFrom;
use test::Bencher;

#[bench] // 1,411 ns/iter (+/- 414)
fn canonicalize_headers_relaxed_bench(b: &mut Bencher) {
    const MAIL: &str = "A: X\r\nB : Y\t\r\n\tZ  \r\n\r\n C \r\nD \t E\r\n\r\n\r\n";
    let (headers, body) = email_parser::parser::parse_message_with_separators(MAIL.as_bytes()).unwrap();

    let headers: Vec<(&str, &str, &str)> = headers
        .iter()
        .filter_map(|(n, s, v)| {
            if let (Ok(name), Ok(separator), Ok(value)) = (std::str::from_utf8(n), std::str::from_utf8(s), std::str::from_utf8(v)) {
                Some((name, separator, value))
            } else {
                None
            }
        })
        .collect();

    b.iter(|| {
        canonicalize_headers_relaxed(&headers, &["a".to_string(), "b".to_string()]);
        canonicalize_headers_relaxed(&headers, &["b".to_string(), "a".to_string()]);
    });
}

#[bench] // 347 ns/iter (+/- 17)
fn canonicalize_headers_simple_bench(b: &mut Bencher) {
    const MAIL: &str = "A: X\r\nB : Y\t\r\n\tZ  \r\n\r\n C \r\nD \t E\r\n\r\n\r\n";
    let (headers, body) = email_parser::parser::parse_message_with_separators(MAIL.as_bytes()).unwrap();

    let headers: Vec<(&str, &str, &str)> = headers
        .iter()
        .filter_map(|(n, s, v)| {
            if let (Ok(name), Ok(separator), Ok(value)) = (std::str::from_utf8(n), std::str::from_utf8(s), std::str::from_utf8(v)) {
                Some((name, separator, value))
            } else {
                None
            }
        })
        .collect();

    b.iter(|| {
        canonicalize_headers_simple(&headers, &["a".to_string(), "b".to_string()]);
        canonicalize_headers_simple(&headers, &["b".to_string(), "a".to_string()]);
    });
}
