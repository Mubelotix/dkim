use nom::sequence::Tuple;
use nom::{
    bytes::complete::{tag, take_while, take_while1},
    combinator::map_res,
    error::ErrorKind,
    sequence::tuple,
    multi::many0,
    IResult,
    Err::Error as NomError,
};
use std::cell::Cell;

#[derive(Debug)]
pub enum DkimSignatureParsingError {
    InvalidTagValue,
    InvalidTagName,
    InvalidTag,
    MissingSemicolon,
}

impl Into<nom::Err<DkimSignatureParsingError>> for DkimSignatureParsingError {
    fn into(self) -> nom::Err<DkimSignatureParsingError> {
        NomError(self)
    }
}

fn is_valchar(character: char) -> bool {
    character as u8 >= 0x21 && character as u8 <= 0x7e && character as u8 != b';'
}

fn is_wsp(character: char) -> bool {
    character as u8 == b' ' || character as u8 == b'\t'
}

fn is_alpha(character: char) -> bool {
    (character as u8 >= 0x41 && character as u8 <= 0x5a) || (character as u8 >= 0x61 && character as u8 <= 0x7a)
}

fn is_digit(character: char) -> bool {
    character as u8 >= 0x30 && character as u8 <= 0x39
}

fn is_alphapunc(character: char) -> bool {
    is_alpha(character) || is_digit(character) || character == '_'
}

fn wsp(input: &str) -> IResult<&str, &str> {
    #[derive(Clone, Copy)]
    enum Status {
        LineFeed,
        Anything,
        Whitespace,
    }

    let status: Cell<Status> = Cell::new(Status::Anything);
    let mut end_idx: Option<usize> = None;
    for (idx, character) in input.chars().enumerate() {
        match status.get() {
            Status::Anything if is_wsp(character) => (),
            Status::Anything if character == '\r' => {
                status.set(Status::LineFeed);
            }
            Status::LineFeed if character == '\n' => {
                status.set(Status::Whitespace);
            }
            Status::Whitespace if is_wsp(character) => {
                status.set(Status::Anything);
            },
            _ => {
                end_idx = Some(idx);
                break;
            }
        }
    }

    let end_idx = end_idx.unwrap_or(input.len());
    Ok((&input[end_idx..], &input[..end_idx]))
}

fn tag_value(input: &str) -> IResult<&str, &str, DkimSignatureParsingError> {
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
                    return Err(NomError(DkimSignatureParsingError::InvalidTagValue));
                }
            }
            Status::ValCharOrFWS => {
                match character {
                    character if is_valchar(character) => {
                        last_valid_idx = idx + 1;
                    }
                    character if character == '\r' =>  {
                        status = Status::LineFeed;
                    }
                    character if !is_wsp(character) => break,
                    _ => ()
                }
            }
            Status::Whitespace => {
                status = Status::ValCharOrFWS;
                if !is_wsp(character) {
                    return Err(NomError(DkimSignatureParsingError::InvalidTagValue));
                }
            }
            Status::ValChar => if is_valchar(character) {
                last_valid_idx = idx + 1;
                status = Status::ValCharOrFWS;
            } else {
                return Err(NomError(DkimSignatureParsingError::InvalidTagValue));
            }
        }
    };

    Ok((&input[last_valid_idx..], &input[..last_valid_idx]))
}

fn tag_name(input: &str) -> IResult<&str, &str, DkimSignatureParsingError> {
    match take_while1::<_, _, ()>(is_alphapunc)(input) {
        Ok(r) if is_alpha(r.1.chars().next().unwrap()) => Ok(r),
        _ => Err(NomError(DkimSignatureParsingError::InvalidTagName)),
    }
}

fn tag_spec(input: &str) -> IResult<&str, (&str, &str), DkimSignatureParsingError> {
    // Remove whitespaces
    let (input, _wsp) = wsp(input).map_err(|_e| DkimSignatureParsingError::InvalidTag.into())?;

    // Take name
    let (input, name) = tag_name(input)?;

    // Remove whitespaces
    let (mut input, _wsp) = wsp(input).map_err(|_e| DkimSignatureParsingError::InvalidTag.into())?;

    // Assert there is an equal sign
    match tag::<_,_,()>("=")(input) {
        Ok(r) => input = r.0,
        _ => return Err(NomError(DkimSignatureParsingError::InvalidTag)),
    };

    // Remove whitespaces
    let (input, _wsp) = wsp(input).map_err(|_e| DkimSignatureParsingError::InvalidTag.into())?;

    // Take value
    let (input, value) = tag_value(input)?;

    // Remove whitespaces
    let (input, _wsp) = wsp(input).map_err(|_e| DkimSignatureParsingError::InvalidTag.into())?;

    Ok((input, (name, value)))
}

pub fn tag_list(input: &str) -> IResult<(), Vec<(&str, &str)>, DkimSignatureParsingError> {
    let mut tags = Vec::new();
    let (mut input, first_tag) = tag_spec(input)?;
    tags.push(first_tag);
    
    loop {
        if input.is_empty() {
            break;
        }

        input = tag::<_,_,()>(";")(input).map_err(|_e| DkimSignatureParsingError::MissingSemicolon.into())?.0;

        if input.is_empty() {
            break;
        }

        let new_tag = tag_spec(input)?;
        input = new_tag.0;
        tags.push(new_tag.1);
    }

    Ok(((), tags))
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

        assert!(tag_value(" This is an invalid tag value").is_err()); // space at the start
        assert!(tag_value("This is an \rinvalid tag value").is_err()); // expected linefeed
        assert!(tag_value("This is an \r\ninvalid tag value").is_err()); // missing whitespace after folding
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
        assert_eq!(tag_spec("v=1;").unwrap().1, ("v", "1"));
        assert_eq!(tag_spec("tag_name=value;").unwrap().1, ("tag_name", "value"));
        assert_eq!(tag_spec("  tag_name =  value   ;").unwrap().1, ("tag_name", "value"));
        assert_eq!(tag_spec("  tag_name = \r\n value   ;").unwrap().1, ("tag_name", "value"));
        assert_eq!(tag_spec("  tag_name = value   \r\n ;").unwrap().1, ("tag_name", "value"));
    }
    
    #[test]
    fn test_tag_list() {
        assert_eq!(tag_list("pseudo=mubelotix; website=https://mubelotix.dev; state=France;").unwrap().1, vec![("pseudo", "mubelotix"), ("website", "https://mubelotix.dev"), ("state", "France")]);
        assert_eq!(tag_list("v=1; a=rsa-sha256; d=example.net; s=brisbane; c=simple; q=dns/txt; i=@eng.example.net; t=1117574938; x=1118006938; h=from:to:subject:date; z=From:foo@eng.example.net|To:joe@example.com|  Subject:demo=20run|Date:July=205,=202005=203:44:08=20PM=20-0700; bh=MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=; b=dzdVyOfAKCdLXdJOc9G2q8LoXSlEniSbav+yuU4zGeeruD00lszZVoG4ZHRNiYzR").unwrap().1, 
            vec![
                ("v", "1"),
                ("a", "rsa-sha256"),
                ("d", "example.net"),
                ("s", "brisbane"),
                ("c", "simple"),
                ("q", "dns/txt"),
                ("i", "@eng.example.net"),
                ("t", "1117574938"),
                ("x", "1118006938"),
                ("h", "from:to:subject:date"),
                ("z", "From:foo@eng.example.net|To:joe@example.com|  Subject:demo=20run|Date:July=205,=202005=203:44:08=20PM=20-0700"),
                ("bh", "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI="),
                ("b", "dzdVyOfAKCdLXdJOc9G2q8LoXSlEniSbav+yuU4zGeeruD00lszZVoG4ZHRNiYzR"),
            ]
        );
    }
}
