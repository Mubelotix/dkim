use super::header::{ParsingError, is_valchar, is_wsp};

pub fn dkim_quoted_printable(input: &str) -> nom::IResult<&str, String, ParsingError> {
    let mut chars = input.chars().enumerate();
    let mut result = String::new();
    let mut last_valid_idx = 0;
    loop {
        let (idx, character) = match chars.next() {
            Some(character) => character,
            None => break
        };

        match character {
            character if is_valchar(character) && character != '=' => {
                last_valid_idx = idx + 1;
                result.push(character);
            }
            character if character == '='=> {
                if let (Some((_, c1)), Some((idx, c2))) = (chars.next(), chars.next()) {
                    let mut number = String::new();
                    number.push(c1);
                    number.push(c2);
                    let character: char = u8::from_str_radix(&number, 16).map_err(|_e| ParsingError::InvalidDkimQuotedPrintable.into())? as char;
                    result.push(character);
                    last_valid_idx = idx + 1;
                } else {
                    return Err(ParsingError::InvalidDkimQuotedPrintable.into());
                }
            }
            character if character == '\r' => {
                match chars.next() {
                    Some((_, '\n')) => (),
                    _ => return Err(ParsingError::ExpectedLineFeed.into())
                }
                match chars.next() {
                    Some((_, character)) if is_wsp(character) => (),
                    _ => return Err(ParsingError::ExpectedWhitespace.into())
                }
            },
            character if is_wsp(character) => (),
            _ => {
                break;
            },
        }
    }

    Ok((&input[last_valid_idx..], result))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_dkim_quoted_printable() {
        assert_eq!(&dkim_quoted_printable("this\r\n is a test").unwrap().1, "thisisatest");
        assert_eq!(&dkim_quoted_printable("This=20is=20a=20test").unwrap().1, "This is a test");
        assert_eq!(&dkim_quoted_printable("This=20is=00a=09test").unwrap().1, "This is\u{0}a\ttest");
    }
}