pub fn canonicalize_headers_simple(mail: &str) -> &str {
    &mail[..mail.find("\r\n\r\n").unwrap_or_else(|| mail.len() - 2) + 2];
    todo!();
}

pub fn canonicalize_body_simple(mail: &str) -> &str {
    let mut body: &str = if let Some(idx) = mail.find("\r\n\r\n") {
        &mail[idx + 4..]
    } else {
        &mail[..]
    };

    if body.is_empty() {
        return "\r\n";
    }

    while body.ends_with("\r\n\r\n") {
        body = &body[..body.len() - 2];
    }

    body
}

pub fn canonicalize_header_relaxed(header: &email::Header) -> String {
    let name = header.name.to_lowercase();
    let mut value = header.get_value::<String>().unwrap();
    while value.ends_with(' ') || value.ends_with('\t') {
        value.remove(value.len() - 1);
    }
    value = value.replace('\t', " ");
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

    // PROVISORY FIX
    if name == "references" {
        value = value.replace("><", "> <");
    }

    format!("{}:{}\r\n", name, value)
}

pub fn canonicalize_headers_relaxed(mail: &str, h: &Vec<String>) -> String {
    let mut mail = email::rfc5322::Rfc5322Parser::new(&mail);
    let mut headers = String::new();
    while let Some(header) = mail.consume_header() {
        let name = header.name.to_lowercase();
        if h.contains(&name) {
            headers.push_str(&canonicalize_header_relaxed(&header))
        }
    };
    headers
}

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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn canonicalize_body_relaxed_test() {
        assert_eq!(canonicalize_body_relaxed("A: X\r\nB : Y\t\r\n\tZ  \r\n\r\n C \r\nD \t E\r\n\r\n\r\n".to_string()), " C\r\nD E\r\n");
    }

    #[test]
    fn canonicalize_headers_relaxed_test() {
        assert_eq!(canonicalize_headers_relaxed("A: X\r\nB : Y\t\r\n\tZ  \r\n\r\n C \r\nD \t E\r\n\r\n\r\n", &vec!["a".to_string(),"b".to_string()]), "a:X\r\nb:Y Z\r\n");
        //assert_eq!(canonicalize_headers_relaxed("A: X\r\nB : Y\t\r\n\tZ  \r\n\r\n C \r\nD \t E\r\n\r\n\r\n", vec!["b", "a"]), "b:Y Z\r\na:X\r\n"); // check correctness of the logic
    }

    #[test]
    fn canonicalize_headers_simple_test() {
       // assert_eq!(canonicalize_headers_simple("A: X\r\nB : Y\t\r\n\tZ  \r\n\r\n C \r\nD \t E\r\n\r\n\r\n"), "A: X \r\nB : Y \t \r\n \tZ   \r\n");
    }
}