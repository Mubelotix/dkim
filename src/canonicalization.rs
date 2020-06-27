use email::UnfoldingStrategy;

pub fn canonicalize_headers_simple(head: &str, signed_headers: &[String]) -> String {
    enum Expects {
        CarriageReturn,
        WhiteSpace
    }

    let mut separations = vec![0];
    let mut state = Expects::CarriageReturn;
    let mut characters = head.chars();
    let mut idx = 0;

    while let Some(character) = characters.next() {
        match state {
            Expects::CarriageReturn => if character == '\r' && {
                idx += 1;
                characters.next() == Some('\n')
            } {
                state = Expects::WhiteSpace;
            },
            Expects::WhiteSpace => {
                state = Expects::CarriageReturn;
                if character != ' ' && character != '\t' {
                    separations.push(idx);
                }
            },
        }
        idx += 1;
    }
    separations.push(head.len());

    let mut parsed_headers = Vec::new();
    for idx in 1..separations.len() {
        parsed_headers.push(&head[separations[idx - 1]..separations[idx]]);
    }

    let mut canonicalized_headers = String::new();
    for signed_header in signed_headers {
        let mut idx_to_remove = None;
        for (idx, value) in parsed_headers.iter().enumerate() {
            if value.to_lowercase().starts_with(signed_header) && value.len() > signed_header.len() && {
                let next = value.get(signed_header.len()..signed_header.len()+1);
                next == Some(":") || next == Some(" ") || next == Some("\t")
            } {
                idx_to_remove = Some(idx);
                break
            }
        };

        if let Some(idx) = idx_to_remove {
            let value = parsed_headers.remove(idx);
            canonicalized_headers.push_str(value);
        }
    }
    canonicalized_headers
}

pub fn canonicalize_body_simple(mut body: &str) -> &str {
    if body.is_empty() {
        return "\r\n";
    }

    while body.ends_with("\r\n\r\n") {
        body = &body[..body.len() - 2];
    }

    body
}

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

pub fn canonicalize_headers_relaxed(headers_part: &str, signed_headers: &[String]) -> String {
    let mut mail = email::rfc5322::Rfc5322Parser::new_with_unfolding_strategy(&headers_part, UnfoldingStrategy::RfcCompliant);
    let mut headers = Vec::new();
    while let Some(header) = mail.consume_header() {
        let name = header.name.to_lowercase();
        let value = header.get_value::<String>().unwrap();
        if signed_headers.contains(&name) {
            headers.push((name, canonicalize_header_relaxed(value)));
        }
    };

    let mut canonicalized_headers = String::new();
    for signed_header in signed_headers {
        let mut idx_to_remove = None;
        for (idx, (name, _value)) in headers.iter().enumerate() {
            if name == signed_header {
                idx_to_remove = Some(idx);
                break
            }
        };

        if let Some(idx) = idx_to_remove {
            let (name, value) = headers.remove(idx);
            canonicalized_headers.push_str(&format!("{}:{}\r\n", name, value));
        }
    }
    canonicalized_headers
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

pub fn canonicalize_relaxed(mail: &str, signed_headers: &[String]) -> (String, String) {
    let header_end_idx = mail.find("\r\n\r\n").map(|i| i+4).unwrap_or_else(|| mail.len());
    let headers_part = mail[..header_end_idx].to_string();
    let body_part = mail[header_end_idx..].to_string();

    (headers_part, body_part)
}

#[cfg(test)]
mod test {
    use pretty_assertions::assert_eq;
    use super::*;
    use string_tools::get_all_after;

    const MAIL: &str = "A: X\r\nB : Y\t\r\n\tZ  \r\n\r\n C \r\nD \t E\r\n\r\n\r\n";

    #[test]
    fn canonicalize_body_relaxed_test() {
        assert_eq!(canonicalize_body_relaxed(get_all_after(MAIL, "\r\n\r\n").to_string()), " C\r\nD E\r\n");
    }

    #[test]
    fn canonicalize_headers_relaxed_test() {
        assert_eq!(canonicalize_headers_relaxed(MAIL, &["a".to_string(),"b".to_string()]), "a:X\r\nb:Y Z\r\n");
        assert_eq!(canonicalize_headers_relaxed(MAIL, &["b".to_string(),"a".to_string()]), "b:Y Z\r\na:X\r\n");
    }

    #[test]
    fn canonicalize_body_simple_test() {
       assert_eq!(canonicalize_body_simple(get_all_after(MAIL, "\r\n\r\n")), " C \r\nD \t E\r\n");
    }

    #[test]
    fn canonicalize_headers_simple_test() {
       assert_eq!(canonicalize_headers_simple(MAIL, &["a".to_string(),"b".to_string()]), "A: X\r\nB : Y\t\r\n\tZ  \r\n");
       assert_eq!(canonicalize_headers_simple(MAIL, &["b".to_string(),"a".to_string()]), "B : Y\t\r\n\tZ  \r\nA: X\r\n");
    }
}