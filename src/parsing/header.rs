use nom::{
    bytes::complete::{tag, take_while1},
    Err::Error as NomError,
    IResult,
};
use crate::dkim::{SigningAlgorithm, CanonicalizationType};
use super::dkim_quoted_printable::dkim_quoted_printable;

#[derive(Debug)]
pub enum ParsingError {
    InvalidTagName,
    ExpectedLineFeed,
    ExpectedWhitespace,
    ExpectedEqualSign,
    MissingSemicolon,
    EmptyHeaderName,
    ExpectedColon,
    InvalidDkimQuotedPrintable,
    InvalidTagValue(&'static str)
}

#[derive(Debug, PartialEq)]
pub enum Tag<'a> {
    Version(u8),
    SigningAlgorithm(SigningAlgorithm),
    Signature(Vec<u8>),
    Hash(Vec<u8>),
    Canonicalization(CanonicalizationType, CanonicalizationType),
    SDID(&'a str),
    SignedHeaders(Vec<&'a str>),
    AUID(String),
    BodyLenght(usize),
    QueryMethods(&'a str),
    Selector(&'a str),
    SignatureTimestamp(u64),
    SignatureExpiration(u64),
    CopiedHeaders(Vec<String>),

    Unknown(&'a str, &'a str),
}

impl Into<nom::Err<ParsingError>> for ParsingError {
    fn into(self) -> nom::Err<ParsingError> {
        NomError(self)
    }
}

pub(super) fn is_valchar(character: char) -> bool {
    character as u8 >= 0x21 && character as u8 <= 0x7e && character as u8 != b';'
}

pub(super) fn is_wsp(character: char) -> bool {
    character as u8 == b' ' || character as u8 == b'\t'
}

fn is_alpha(character: char) -> bool {
    (character as u8 >= 0x41 && character as u8 <= 0x5a)
        || (character as u8 >= 0x61 && character as u8 <= 0x7a)
}

fn is_digit(character: char) -> bool {
    character as u8 >= 0x30 && character as u8 <= 0x39
}

fn is_alphapunc(character: char) -> bool {
    is_alpha(character) || is_digit(character) || character == '_'
}

fn is_ftext(character: char) -> bool {
    character as u8 >= 33 && character as u8 <= 126 && character as u8 != 58 && character as u8 != 59
}

fn wsp(input: &str) -> IResult<&str, &str, ParsingError> {
    #[derive(Clone, Copy)]
    enum Status {
        LineFeed,
        Anything,
        Whitespace,
    }

    let mut status: Status = Status::Anything;
    let mut end_idx: Option<usize> = None;
    for (idx, character) in input.chars().enumerate() {
        match status {
            Status::Anything => if character == '\r' {
                status = Status::LineFeed;
            } else if !is_wsp(character) {
                end_idx = Some(idx);
                break;
            },
            Status::LineFeed => if character == '\n' {
                status = Status::Whitespace;
            } else {
                return Err(ParsingError::ExpectedLineFeed.into());
            }
            Status::Whitespace => if is_wsp(character) {
                status = Status::Anything;
            } else {
                return Err(ParsingError::ExpectedWhitespace.into());
            }
        }
    }

    let end_idx = end_idx.unwrap_or(input.len());
    Ok((&input[end_idx..], &input[..end_idx]))
}

fn header_name(input: &str) -> IResult<&str, &str, ParsingError> {
    take_while1::<_,_,()>(is_ftext)(input).map_err(|_e| ParsingError::EmptyHeaderName.into())
}

fn signed_header_value(input: &str) -> IResult<&str, Vec<&str>, ParsingError> {
    let mut headers = Vec::new();
    let (mut input, first_header) = header_name(input)?;
    headers.push(first_header);
    input = wsp(input)?.0;

    loop {
        if input.starts_with(";") || input.is_empty() {
            break;
        }
        
        input = tag::<_,_,()>(":")(input).map_err(|_e| ParsingError::ExpectedColon.into())?.0;
        input = wsp(input)?.0;
        let (remaining_input, header) = header_name(input)?;
        input = remaining_input;
        headers.push(header);
        input = wsp(input)?.0;
    }

    Ok((input, headers))
}

fn tag_value(input: &str) -> IResult<&str, &str, ParsingError> {
    #[derive(Clone, Copy)]
    enum Status {
        ValChar,
        ValCharOrFWS,
        LineFeed,
        Whitespace,
    }

    let mut status = Status::ValChar;
    let mut last_valid_idx = 0;
    for (idx, character) in input.chars().enumerate() {
        match status {
            Status::LineFeed => {
                status = Status::Whitespace;
                if character != '\n' {
                    return Err(NomError(ParsingError::ExpectedLineFeed));
                }
            }
            Status::ValCharOrFWS => match character {
                character if is_valchar(character) => {
                    last_valid_idx = idx + 1;
                }
                character if character == '\r' => {
                    status = Status::LineFeed;
                }
                character if !is_wsp(character) => break,
                _ => (),
            },
            Status::Whitespace => {
                status = Status::ValCharOrFWS;
                if !is_wsp(character) {
                    return Err(NomError(ParsingError::ExpectedWhitespace));
                }
            }
            Status::ValChar => {
                if is_valchar(character) {
                    last_valid_idx = idx + 1;
                    status = Status::ValCharOrFWS;
                } else {
                    break;
                }
            }
        }
    }

    Ok((&input[last_valid_idx..], &input[..last_valid_idx]))
}

fn tag_name(input: &str) -> IResult<&str, &str, ParsingError> {
    match take_while1::<_, _, ()>(is_alphapunc)(input) {
        Ok(r) if is_alpha(r.1.chars().next().unwrap()) => Ok(r),
        _ => Err(NomError(ParsingError::InvalidTagName)),
    }
}

fn tag_spec(input: &str) -> IResult<&str, Tag, ParsingError> {
    // Remove whitespaces
    let (input, _wsp) = wsp(input)?;

    // Take name
    let (input, name) = tag_name(input)?;

    // Remove whitespaces
    let (mut input, _wsp) = wsp(input)?;

    // Assert there is an equal sign
    match tag::<_, _, ()>("=")(input) {
        Ok(r) => input = r.0,
        _ => return Err(ParsingError::ExpectedEqualSign.into()),
    };

    // Remove whitespaces
    let (input, _wsp) = wsp(input)?;

    // Take value
    let (input, tag) = match name {
        "v" => {
            let (input, value) = tag_value(input)?;
            (input, Tag::Version(value.parse::<u8>().map_err(|_e| ParsingError::InvalidTagValue("v").into())?))
        }
        "a" => {
            let (input, value) = tag_value(input)?;
            let algorithm = match value {
                "rsa-sha1" => SigningAlgorithm::RsaSha1,
                "rsa-sha256" => SigningAlgorithm::RsaSha256,
                _ => return Err(ParsingError::InvalidTagValue("a").into())
            };
            (input, Tag::SigningAlgorithm(algorithm))
        }
        "b" => {
            // todo some optimizations
            let (input, value) = tag_value(input)?;
            let mut value = value.to_string();
            value.retain(|c| (c as u8 >= 65 && c as u8 <= 90) || (c as u8 >= 97 && c as u8 <= 122) || (c as u8 >= 47 && c as u8 <= 57) || c as u8 == 61 || c as u8 == 43);
            let value = base64::decode(value).map_err(|_e| ParsingError::InvalidTagValue("b").into())?;
            (input, Tag::Signature(value))
        }
        "bh" => {
            // todo some optimizations
            let (input, value) = tag_value(input)?;
            let mut value = value.to_string();
            value.retain(|c| (c as u8 >= 65 && c as u8 <= 90) || (c as u8 >= 97 && c as u8 <= 122) || (c as u8 >= 47 && c as u8 <= 57) || c as u8 == 61 || c as u8 == 43);
            let value = base64::decode(value).map_err(|_e| ParsingError::InvalidTagValue("bh").into())?;
            (input, Tag::Hash(value))
        }
        "c" => {
            let (input, value) = tag_value(input)?;
            let (c1, c2) = match value {
                "relaxed/relaxed" => (CanonicalizationType::Relaxed, CanonicalizationType::Relaxed),
                "relaxed/simple" | "relaxed" => (CanonicalizationType::Relaxed, CanonicalizationType::Simple),
                "simple/relaxed" => (CanonicalizationType::Simple, CanonicalizationType::Relaxed),
                "simple/simple" | "simple" => (CanonicalizationType::Simple, CanonicalizationType::Simple),
                _ => return Err(ParsingError::InvalidTagValue("c").into())
            };
            (input, Tag::Canonicalization(c1, c2))
        }
        "d" => {
            let (input, value) = tag_value(input)?;
            (input, Tag::SDID(value))
        }
        "h" => {
            let (input, headers) = signed_header_value(input)?;
            (input, Tag::SignedHeaders(headers))
        }
        "i" => {
            let (input, value) = dkim_quoted_printable(input)?;
            (input, Tag::AUID(value))
        }
        "l" => {
            use std::str::FromStr;
            let (input, lenght) = take_while1::<_,_,()>(is_digit)(input).map_err(|_e| ParsingError::InvalidTagValue("l").into())?;
            let lenght = usize::from_str(lenght).map_err(|_e| ParsingError::InvalidTagValue("l").into())?;
            (input, Tag::BodyLenght(lenght))
        }
        "q" => {
            let (input, value) = tag_value(input)?;
            (input, Tag::QueryMethods(value))
        },
        "s" => {
            let (input, value) = tag_value(input)?;
            (input, Tag::Selector(value))
        },
        "t" => {
            use std::str::FromStr;
            let (input, lenght) = take_while1::<_,_,()>(is_digit)(input).map_err(|_e| ParsingError::InvalidTagValue("t").into())?;
            let lenght = u64::from_str(lenght).map_err(|_e| ParsingError::InvalidTagValue("t").into())?;
            (input, Tag::SignatureTimestamp(lenght))
        }
        "x" => {
            use std::str::FromStr;
            let (input, lenght) = take_while1::<_,_,()>(is_digit)(input).map_err(|_e| ParsingError::InvalidTagValue("x").into())?;
            let lenght = u64::from_str(lenght).map_err(|_e| ParsingError::InvalidTagValue("x").into())?;
            (input, Tag::SignatureExpiration(lenght))
        }
        "z" => {
            // TODO optimization
            let (input, value) = dkim_quoted_printable(input)?;
            (input, Tag::CopiedHeaders(value.split_terminator('|').map(|h| h.to_string()).collect()))
        }
        _ => {
            let (input, value) = tag_value(input)?;
            (input, Tag::Unknown(name, value))
        },
    };

    // Remove whitespaces
    let (input, _wsp) = wsp(input)?;

    Ok((input, tag))
}

#[allow(dead_code)] // todo remove this line
pub fn tag_list(input: &str) -> Result<Vec<Tag>, ParsingError> {
    let handle_error = |e| if let NomError(e) = e {e} else {ParsingError::InvalidTagName};

    let mut tags = Vec::new();
    let (mut input, first_tag) = tag_spec(input).map_err(handle_error)?;
    tags.push(first_tag);

    loop {
        if input.is_empty() {
            break;
        }

        input = tag::<_, _, ()>(";")(input)
            .map_err(|_e| ParsingError::MissingSemicolon.into())?
            .0;

        if input.is_empty() {
            break;
        }

        let new_tag = tag_spec(input).map_err(handle_error)?;
        input = new_tag.0;
        tags.push(new_tag.1);
    }

    Ok(tags)
}

#[cfg(test)]
mod parsing_tests {
    use super::*;

    #[test]
    fn test_wsp() {
        assert_eq!(wsp("   ").unwrap().1, "   ");
        assert_eq!(wsp(" word ").unwrap().1, " ");
        assert_eq!(wsp("  \t ").unwrap().1, "  \t ");
        assert_eq!(wsp("  \r\n ").unwrap().1, "  \r\n ");
        assert_eq!(wsp("  \r\n test").unwrap().1, "  \r\n ");

        assert!(wsp("  \r test").is_err()); // expected line feed
        assert!(wsp("  \r\ntest").is_err()); // expected whitespace
    }

    #[test]
    fn test_tag_value() {
        assert_eq!(
            tag_value("This is a valid tag value").unwrap().1,
            "This is a valid tag value"
        );
        assert_eq!(
            tag_value("This is a valid tag value    ").unwrap().1,
            "This is a valid tag value"
        );
        assert_eq!(
            tag_value("This is a valid tag\r\n value").unwrap().1,
            "This is a valid tag\r\n value"
        );
        assert_eq!(
            tag_value("This is a valid tag value; tagname=Another")
                .unwrap()
                .1,
            "This is a valid tag value"
        );
        assert_eq!(tag_value("").unwrap().1, "");
        assert_eq!(tag_value(";").unwrap().1, "");

        assert!(tag_value("This is an \rinvalid tag value").is_err()); // expected linefeed
        assert!(tag_value("This is an \r\ninvalid tag value").is_err()); // expected whitespace after folding
    }

    #[test]
    fn test_tag_name() {
        assert_eq!(tag_name("tag_name2").unwrap().1, "tag_name2");
        assert_eq!(tag_name("tag_na me2").unwrap().1, "tag_na");
        assert_eq!(tag_name("tag_name2=").unwrap().1, "tag_name2");

        assert!(tag_name("2tag_name").is_err());
        assert!(tag_name("_tag_name").is_err());
    }

    #[test]
    fn test_tag_spec() {
        assert_eq!(tag_spec("v=1;").unwrap().1, Tag::Version(1));
        assert_eq!(
            tag_spec("tag_name=value;").unwrap().1,
            Tag::Unknown("tag_name", "value")
        );
        assert_eq!(
            tag_spec("  tag_name =  value   ;").unwrap().1,
            Tag::Unknown("tag_name", "value")
        );
        assert_eq!(
            tag_spec("  tag_name = \r\n value   ;").unwrap().1,
            Tag::Unknown("tag_name", "value")
        );
        assert_eq!(
            tag_spec("  tag_name = value   \r\n ;").unwrap().1,
            Tag::Unknown("tag_name", "value")
        );
        // todo add more tests
    }

    #[test]
    fn test_tag_list() {
        assert_eq!(
            tag_list("pseudo=mubelotix; website=https://mubelotix.dev; state=France;")
                .unwrap(),
            vec![
                Tag::Unknown("pseudo", "mubelotix"),
                Tag::Unknown("website", "https://mubelotix.dev"),
                Tag::Unknown("state", "France")
            ]
        );
        assert_eq!(tag_list("v=1; a=rsa-sha256; d=example.net; s=brisbane; c=simple; q=dns/txt; i=@eng.example.net; t=1117574938; x=1118006938; h=from:to:subject:date; z=From:foo@eng.example.net|To:joe@example.com|  Subject:demo=20run|Date:July=205,=202005=203:44:08=20PM=20-0700; bh=MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=; b=dzdVyOfAKCdLXdJOc9G2q8LoXSlEniSbav+yuU4zGeeruD00lszZVoG4ZHRNiYzR").unwrap(), 
            vec![
                Tag::Version(1),
                Tag::SigningAlgorithm(SigningAlgorithm::RsaSha256),
                Tag::SDID("example.net"),
                Tag::Selector("brisbane"),
                Tag::Canonicalization(CanonicalizationType::Simple, CanonicalizationType::Simple),
                Tag::QueryMethods("dns/txt"),
                Tag::AUID("@eng.example.net".to_string()),
                Tag::SignatureTimestamp(1117574938),
                Tag::SignatureExpiration(1118006938),
                Tag::SignedHeaders(vec!["from","to","subject","date"]),
                Tag::CopiedHeaders(vec!["From:foo@eng.example.net".to_string(),"To:joe@example.com".to_string(),"Subject:demo run".to_string(),"Date:July 5, 2005 3:44:08 PM -0700".to_string()]),
                Tag::Hash(base64::decode("MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=").unwrap()),
                Tag::Signature(base64::decode("dzdVyOfAKCdLXdJOc9G2q8LoXSlEniSbav+yuU4zGeeruD00lszZVoG4ZHRNiYzR").unwrap())
            ]
        );
    }

    #[test]
    fn test_signed_headers_value() {
        assert_eq!(signed_header_value("this:is:a:test").unwrap().1, vec!["this", "is", "a", "test"]);
        assert_eq!(signed_header_value("from:to:subject:date").unwrap().1, vec!["from", "to", "subject", "date"]);
        assert_eq!(signed_header_value("from:to:subject:date;").unwrap().1, vec!["from", "to", "subject", "date"]);
    }
}
