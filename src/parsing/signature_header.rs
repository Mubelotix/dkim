use crate::dkim::{CanonicalizationType, SigningAlgorithm};
use crate::parsing::{quoted_printable::from_dqp, tag_value_list::*, ParsingError};
use nom::{
    bytes::complete::{tag, take_while1},
    Err::Error as NomError,
    IResult,
};

/// A valid tag in a `Dkim-Signature` mail header.
#[derive(Debug, PartialEq)]
pub enum Tag<'a> {
    Version(u8),
    SigningAlgorithm(SigningAlgorithm),
    Signature(Vec<u8>),
    BodyHash(Vec<u8>),
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

/// Read an email header name (in a `h` tag).
fn header_name(input: &str) -> IResult<&str, &str, ParsingError> {
    fn is_valid(character: char) -> bool {
        is_ftext(character) && is_valchar(character)
    }

    take_while1::<_, _, ()>(is_valid)(input).map_err(|_e| ParsingError::InvalidTagValue("h").into())
}

/// Read the value of a `h` tag.
fn signed_header_value(input: &str) -> IResult<&str, Vec<&str>, ParsingError> {
    let mut headers = Vec::new();
    let (mut input, first_header) = header_name(input)?;
    headers.push(first_header);
    input = wsp(input)?.0;

    loop {
        if input.starts_with(";") || input.is_empty() {
            break;
        }

        input = tag::<_, _, ()>(":")(input)
            .map_err(|_e| ParsingError::InvalidTagValue("h").into())?
            .0;
        input = wsp(input)?.0;
        let (remaining_input, header) = header_name(input)?;
        input = remaining_input;
        headers.push(header);
        input = wsp(input)?.0;
    }

    Ok((input, headers))
}

/// Read and parse a tag valid in a `Dkim-Signature` mail header.
pub fn signature_header_tag<'a>(
    name: &'a str,
    input: &'a str,
) -> IResult<&'a str, Tag<'a>, ParsingError> {
    Ok(match name {
        "v" => {
            let (input, value) = tag_value(input)?;
            (
                input,
                Tag::Version(
                    value
                        .parse::<u8>()
                        .map_err(|_e| ParsingError::InvalidTagValue("v").into())?,
                ),
            )
        }
        "a" => {
            let (input, value) = tag_value(input)?;
            let algorithm = match value {
                "rsa-sha1" => SigningAlgorithm::RsaSha1,
                "rsa-sha256" => SigningAlgorithm::RsaSha256,
                _ => return Err(ParsingError::InvalidTagValue("a").into()),
            };
            (input, Tag::SigningAlgorithm(algorithm))
        }
        "b" => {
            // todo some optimizations
            let (input, value) = tag_value(input)?;
            let mut value = value.to_string();
            value.retain(|c| {
                (c as u8 >= 65 && c as u8 <= 90)
                    || (c as u8 >= 97 && c as u8 <= 122)
                    || (c as u8 >= 47 && c as u8 <= 57)
                    || c as u8 == 61
                    || c as u8 == 43
            });
            let value =
                base64::decode(value).map_err(|_e| ParsingError::InvalidTagValue("b").into())?;
            (input, Tag::Signature(value))
        }
        "bh" => {
            // todo some optimizations
            let (input, value) = tag_value(input)?;
            let mut value = value.to_string();
            value.retain(|c| {
                (c as u8 >= 65 && c as u8 <= 90)
                    || (c as u8 >= 97 && c as u8 <= 122)
                    || (c as u8 >= 47 && c as u8 <= 57)
                    || c as u8 == 61
                    || c as u8 == 43
            });
            let value =
                base64::decode(value).map_err(|_e| ParsingError::InvalidTagValue("bh").into())?;
            (input, Tag::BodyHash(value))
        }
        "c" => {
            let (input, value) = tag_value(input)?;
            let (c1, c2) = match value {
                "relaxed/relaxed" => (CanonicalizationType::Relaxed, CanonicalizationType::Relaxed),
                "relaxed/simple" | "relaxed" => {
                    (CanonicalizationType::Relaxed, CanonicalizationType::Simple)
                }
                "simple/relaxed" => (CanonicalizationType::Simple, CanonicalizationType::Relaxed),
                "simple/simple" | "simple" => {
                    (CanonicalizationType::Simple, CanonicalizationType::Simple)
                }
                _ => return Err(ParsingError::InvalidTagValue("c").into()),
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
            let (input, value) = from_dqp(input)?;
            (input, Tag::AUID(value))
        }
        "l" => {
            use std::str::FromStr;
            let (input, lenght) = take_while1::<_, _, ()>(is_digit)(input)
                .map_err(|_e| ParsingError::InvalidTagValue("l").into())?;
            let lenght =
                usize::from_str(lenght).map_err(|_e| ParsingError::InvalidTagValue("l").into())?;
            (input, Tag::BodyLenght(lenght))
        }
        "q" => {
            let (input, value) = tag_value(input)?;
            (input, Tag::QueryMethods(value))
        }
        "s" => {
            let (input, value) = tag_value(input)?;
            (input, Tag::Selector(value))
        }
        "t" => {
            use std::str::FromStr;
            let (input, lenght) = take_while1::<_, _, ()>(is_digit)(input)
                .map_err(|_e| ParsingError::InvalidTagValue("t").into())?;
            let lenght =
                u64::from_str(lenght).map_err(|_e| ParsingError::InvalidTagValue("t").into())?;
            (input, Tag::SignatureTimestamp(lenght))
        }
        "x" => {
            use std::str::FromStr;
            let (input, lenght) = take_while1::<_, _, ()>(is_digit)(input)
                .map_err(|_e| ParsingError::InvalidTagValue("x").into())?;
            let lenght =
                u64::from_str(lenght).map_err(|_e| ParsingError::InvalidTagValue("x").into())?;
            (input, Tag::SignatureExpiration(lenght))
        }
        "z" => {
            // TODO optimization
            let (input, value) = from_dqp(input)?;
            (
                input,
                Tag::CopiedHeaders(value.split_terminator('|').map(|h| h.to_string()).collect()),
            )
        }
        _ => {
            let (input, value) = tag_value(input)?;
            (input, Tag::Unknown(name, value))
        }
    })
}

/// Reimplementation of the [tag_list](../tag_value_list/fn.tag_list.html) function with a few differences.  
/// Return a `Vec` of `Tag`s.  
/// Also return the orignal value splitted in 2 parts excluding the signature value (where it was splitted).  
pub fn tag_list_with_reassembled(
    input: &str,
) -> Result<(Vec<Tag>, Option<(&str, &str)>), ParsingError> {
    let handle_error = |e| {
        if let NomError(e) = e {
            e
        } else {
            ParsingError::InvalidTagName
        }
    };

    let original = input;
    let mut reassembled = None;

    let mut tags = Vec::new();
    let (mut input, first_tag) = tag_spec(input, &signature_header_tag).map_err(handle_error)?;
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

        let new_tag = tag_spec(input, &signature_header_tag).map_err(handle_error)?;
        if matches!(new_tag.1, Tag::Signature(_)) {
            let approx_part1_end = original.len() - input.len();

            // this contains a few chars stolen to part1 (often " b=")
            let approx_removed_part = &original[approx_part1_end..];

            // count the stolen chars
            let stolen_chars = approx_removed_part.find("b=").unwrap() + 2;

            // gather part1
            let part1 = &original[..approx_part1_end + stolen_chars];

            reassembled = Some((part1, new_tag.0));
        }
        input = new_tag.0;
        tags.push(new_tag.1);
    }

    Ok((tags, reassembled))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_signed_headers_value() {
        assert_eq!(
            signed_header_value("this:is:a:test").unwrap().1,
            vec!["this", "is", "a", "test"]
        );
        assert_eq!(
            signed_header_value("from:to:subject:date").unwrap().1,
            vec!["from", "to", "subject", "date"]
        );
        assert_eq!(
            signed_header_value("from:to:subject:date;").unwrap().1,
            vec!["from", "to", "subject", "date"]
        );
    }

    #[test]
    fn test_tag_spec() {
        assert_eq!(
            tag_spec("v=1;", &signature_header_tag).unwrap().1,
            Tag::Version(1)
        );
        assert_eq!(
            tag_spec("tag_name=value;", &signature_header_tag)
                .unwrap()
                .1,
            Tag::Unknown("tag_name", "value")
        );
        assert_eq!(
            tag_spec("  tag_name =  value   ;", &signature_header_tag)
                .unwrap()
                .1,
            Tag::Unknown("tag_name", "value")
        );
        assert_eq!(
            tag_spec("  tag_name = \r\n value   ;", &signature_header_tag)
                .unwrap()
                .1,
            Tag::Unknown("tag_name", "value")
        );
        assert_eq!(
            tag_spec("  tag_name = value   \r\n ;", &signature_header_tag)
                .unwrap()
                .1,
            Tag::Unknown("tag_name", "value")
        );
        // todo add more tests
    }

    #[test]
    fn test_tag_list() {
        assert_eq!(
            tag_list(
                "pseudo=mubelotix; website=https://mubelotix.dev; state=France;",
                &signature_header_tag
            )
            .unwrap(),
            vec![
                Tag::Unknown("pseudo", "mubelotix"),
                Tag::Unknown("website", "https://mubelotix.dev"),
                Tag::Unknown("state", "France")
            ]
        );
        assert_eq!(tag_list("v=1; a=rsa-sha256; d=example.net; s=brisbane; c=simple; q=dns/txt; i=@eng.example.net; t=1117574938; x=1118006938; h=from:to:subject:date; z=From:foo@eng.example.net|To:joe@example.com|  Subject:demo=20run|Date:July=205,=202005=203:44:08=20PM=20-0700; bh=MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=; b=dzdVyOfAKCdLXdJOc9G2q8LoXSlEniSbav+yuU4zGeeruD00lszZVoG4ZHRNiYzR", &signature_header_tag).unwrap(), 
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
                Tag::BodyHash(base64::decode("MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=").unwrap()),
                Tag::Signature(base64::decode("dzdVyOfAKCdLXdJOc9G2q8LoXSlEniSbav+yuU4zGeeruD00lszZVoG4ZHRNiYzR").unwrap())
            ]
        );
    }

    #[test]
    fn test_reassembled() {
        assert_eq!(tag_list_with_reassembled("v=1; a=rsa-sha256; d=example.net; s=brisbane; c=simple; q=dns/txt; i=@eng.example.net; t=1117574938; x=1118006938; h=from:to:subject:date; z=From:foo@eng.example.net|To:joe@example.com|  Subject:demo=20run|Date:July=205,=202005=203:44:08=20PM=20-0700; bh=MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=; b=dzdVyOfAKCdLXdJOc9G2q8LoXSlEniSbav+yuU4zGeeruD00lszZVoG4ZHRNiYzR").unwrap().1.unwrap(), 
            ("v=1; a=rsa-sha256; d=example.net; s=brisbane; c=simple; q=dns/txt; i=@eng.example.net; t=1117574938; x=1118006938; h=from:to:subject:date; z=From:foo@eng.example.net|To:joe@example.com|  Subject:demo=20run|Date:July=205,=202005=203:44:08=20PM=20-0700; bh=MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=; b=", "")
        );

        assert_eq!(tag_list_with_reassembled("v=1; a=rsa-sha256; d=example.net; s=brisbane; c=simple; q=dns/txt; i=@eng.example.net; t=1117574938; x=1118006938; b=dzdVyOfAKCdLXdJOc9G2q8LoXSlEniSbav+yuU4zGeeruD00lszZVoG4ZHRNiYzR; h=from:to:subject:date; z=From:foo@eng.example.net|To:joe@example.com|  Subject:demo=20run|Date:July=205,=202005=203:44:08=20PM=20-0700; bh=MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=;").unwrap().1.unwrap(), 
            ("v=1; a=rsa-sha256; d=example.net; s=brisbane; c=simple; q=dns/txt; i=@eng.example.net; t=1117574938; x=1118006938; b=", "; h=from:to:subject:date; z=From:foo@eng.example.net|To:joe@example.com|  Subject:demo=20run|Date:July=205,=202005=203:44:08=20PM=20-0700; bh=MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=;")
        );
    }
}
