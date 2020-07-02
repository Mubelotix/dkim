// Canonicalize headers using the simple canonicalization algorithm.
//
// The first argument *should* be the head part of the mail.
// The list of signed_headers **must** be a list of lowercase Strings.
pub fn canonicalize_headers_simple(headers: &[(&str, &str, &str)], signed_headers: &[String]) -> String {
    let mut canonicalized_headers = String::new();
    let mut already_used = Vec::new();

    for signed_header in signed_headers {
        for (idx, (name, separator, value)) in headers
            .iter()
            .enumerate()
            .filter(|(idx, _)| !already_used.contains(idx))
        {
            if unicase::eq_ascii(signed_header.as_str(), name) {
                canonicalized_headers.push_str(name);
                canonicalized_headers.push_str(separator);
                canonicalized_headers.push_str(value);
                canonicalized_headers.push_str("\r\n");
                
                already_used.push(idx);
                break;
            }
        }
    }
    canonicalized_headers
}

/// Canonicalize body using the simple canonicalization algorithm.  
///   
/// The first argument **must** be the body of the mail.
pub fn canonicalize_body_simple(mut body: &str) -> &str {
    if body.is_empty() {
        return "\r\n";
    }

    while body.ends_with("\r\n\r\n") {
        body = &body[..body.len() - 2];
    }

    body
}

/// Canonicalize a single header using the relaxed canonicalization algorithm.  
///   
/// Note: There is no corresponding function for the simple canonicalization algorithm because the simple canonicalization algorithm does not change a single header.
pub fn canonicalize_header_relaxed(mut value: String) -> String {
    value = value.replace('\t', " ");
    value = value.replace("\r\n", "");

    while value.ends_with(' ') {
        value.remove(value.len() - 1);
    }
    while value.starts_with(' ') {
        value.remove(0);
    }
    let mut previous = false;
    value.retain(|c| {
        if c == ' ' {
            if previous {
                false
            } else {
                previous = true;
                true
            }
        } else {
            previous = false;
            true
        }
    });

    value
}

// Canonicalize headers using the relaxed canonicalization algorithm.
//
// The first argument **must** be the head part of the mail.
// The list of signed_headers **must** be a list of lowercase Strings.
pub fn canonicalize_headers_relaxed(headers: &[(&str, &str, &str)], signed_headers: &[String]) -> String {
    let mut canonicalized_headers = String::new();
    let mut already_used = Vec::new();

    for signed_header in signed_headers {
        for (idx, (name, _separator, value)) in headers
            .iter()
            .enumerate()
            .filter(|(idx, _)| !already_used.contains(idx))
        {
            if unicase::eq_ascii(signed_header.as_str(), name) {
                canonicalized_headers.push_str(&format!(
                    "{}:{}\r\n",
                    name.to_lowercase(),
                    canonicalize_header_relaxed(value.to_string())
                ));
                already_used.push(idx);
                break;
            }
        }
    }
    canonicalized_headers
}

/// Canonicalize body using the relaxed canonicalization algorithm.  
///   
/// The first argument **must** be the body of the mail.
pub fn canonicalize_body_relaxed(mut body: String) -> String {
    // See https://tools.ietf.org/html/rfc6376#section-3.4.4 for implementation details

    // Reduce all sequences of WSP within a line to a single SP character.
    body = body.replace('\t', " ");
    let mut previous = false;
    body.retain(|c| {
        if c == ' ' {
            if previous {
                false
            } else {
                previous = true;
                true
            }
        } else {
            previous = false;
            true
        }
    });

    // Ignore all whitespace at the end of lines. Implementations MUST NOT remove the CRLF at the end of the line.
    while let Some(idx) = body.find(" \r\n") {
        body.remove(idx);
    }

    // Ignore all empty lines at the end of the message body. "Empty line" is defined in Section 3.4.3.
    while body.ends_with("\r\n\r\n") {
        body.remove(body.len() - 1);
        body.remove(body.len() - 1);
    }

    // If the body is non-empty but does not end with a CRLF, a CRLF is added. (For email, this is only possible when using extensions to SMTP or non-SMTP transport mechanisms.)
    if !body.is_empty() && !body.ends_with("\r\n") {
        body.push_str("\r\n");
    }

    body
}

/*pub fn canonicalize_relaxed(mail: &str, signed_headers: &[String]) -> (String, String) {
    let header_end_idx = mail.find("\r\n\r\n").map(|i| i+4).unwrap_or_else(|| mail.len());
    let headers_part = mail[..header_end_idx].to_string();
    let body_part = mail[header_end_idx..].to_string();

    (headers_part, body_part)
}*/

#[cfg(test)]
mod test {
    use super::*;
    use pretty_assertions::assert_eq;
    use std::convert::TryFrom;
    use string_tools::get_all_after;
    use crate::email::Email;

    const MAIL: &str = "A: X\r\nB : Y\t\r\n\tZ  \r\n\r\n C \r\nD \t E\r\n\r\n\r\n";

    #[test]
    fn canonicalize_body_relaxed_test() {
        assert_eq!(
            canonicalize_body_relaxed(get_all_after(MAIL, "\r\n\r\n").to_string()),
            " C\r\nD E\r\n"
        );
    }

    #[test]
    fn canonicalize_headers_relaxed_test() {
        let mail = Email::try_from(MAIL).unwrap();
        assert_eq!(
            canonicalize_headers_relaxed(&mail.parsed.0, &["a".to_string(), "b".to_string()]),
            "a:X\r\nb:Y Z\r\n"
        );
        assert_eq!(
            canonicalize_headers_relaxed(&mail.parsed.0, &["b".to_string(), "a".to_string()]),
            "b:Y Z\r\na:X\r\n"
        );
    }

    #[test]
    fn canonicalize_body_simple_test() {
        assert_eq!(
            canonicalize_body_simple(get_all_after(MAIL, "\r\n\r\n")),
            " C \r\nD \t E\r\n"
        );
    }

    #[test]
    fn canonicalize_headers_simple_test() {
        let mail = Email::try_from(MAIL).unwrap();
        assert_eq!(
            canonicalize_headers_simple(&mail.parsed.0, &["a".to_string(), "b".to_string()]),
            "A: X\r\nB : Y\t\r\n\tZ  \r\n"
        );
        assert_eq!(
            canonicalize_headers_simple(&mail.parsed.0, &["b".to_string(), "a".to_string()]),
            "B : Y\t\r\n\tZ  \r\nA: X\r\n"
        );
    }
}
