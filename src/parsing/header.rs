use nom::sequence::Tuple;
use nom::{
    bytes::complete::{tag, take_while, take_while1},
    combinator::map_res,
    error::ErrorKind,
    sequence::tuple,
    IResult,
    Err::Error as NomError,
};
use std::cell::Cell;

#[derive(Debug)]
pub enum DkimSignatureParsingError {
    InvalidTagValue,
    InvalidTagName,
    InvalidTag,
}

impl Into<nom::Err<DkimSignatureParsingError>> for DkimSignatureParsingError {
    fn into(self) -> nom::Err<DkimSignatureParsingError> {
        NomError(self)
    }
}

fn is_valchar(character: u8) -> bool {
    character >= 0x21 && character <= 0x7e && character != b';'
}

fn is_wsp(character: u8) -> bool {
    character == b' ' || character == b'\t'
}

fn is_alpha(character: u8) -> bool {
    (character >= 0x41 && character <= 0x5a) || (character >= 0x61 && character <= 0x7a)
}

fn is_digit(character: u8) -> bool {
    character >= 0x30 && character <= 0x39
}

fn is_alphapunc(character: u8) -> bool {
    is_alpha(character) || is_digit(character) || character == b'_'
}

fn wsp(input: &[u8]) -> IResult<&[u8], &[u8]> {
    #[derive(Clone, Copy)]
    enum Status {
        LineFeed,
        Anything,
        Whitespace,
    }

    let status: Cell<Status> = Cell::new(Status::Anything);
    take_while(move |character| {
        match status.get() {
            Status::Anything if is_wsp(character) => {
                true
            }
            Status::Anything if character == b'\r' => {
                status.set(Status::LineFeed);
                true
            }
            Status::LineFeed if character == b'\n' => {
                status.set(Status::Whitespace);
                true
            }
            Status::Whitespace if is_wsp(character) => {
                status.set(Status::Anything);
                true
            },
            _ => false
        }
    })(input)
}

fn tag_value(input: &[u8]) -> IResult<&[u8], &[u8], DkimSignatureParsingError> {
    #[derive(Clone, Copy)]
    enum Status {
        ValChar,
        ValCharOrFWS,
        LineFeed,
        Whitespace,
    }

    let mut status = Status::ValChar;
    let mut last_valid_idx = 0;
    for (idx, character) in input.iter().enumerate() {
        match status {
            Status::LineFeed => {
                status = Status::Whitespace;
                if character != &b'\n' {
                    return Err(NomError(DkimSignatureParsingError::InvalidTagValue));
                }
            }
            Status::ValCharOrFWS => {
                match character {
                    character if is_valchar(*character) => {
                        last_valid_idx = idx + 1;
                    }
                    character if character == &b'\r' =>  {
                        status = Status::LineFeed;
                    }
                    character if !is_wsp(*character) => break,
                    _ => ()
                }
            }
            Status::Whitespace => {
                status = Status::ValCharOrFWS;
                if !is_wsp(*character) {
                    return Err(NomError(DkimSignatureParsingError::InvalidTagValue));
                }
            }
            Status::ValChar => if is_valchar(*character) {
                last_valid_idx = idx;
                status = Status::ValCharOrFWS;
            } else {
                return Err(NomError(DkimSignatureParsingError::InvalidTagValue));
            }
        }
    };

    Ok((&input[last_valid_idx..], &input[..last_valid_idx]))
}

fn tag_name(input: &[u8]) -> IResult<&[u8], &[u8], DkimSignatureParsingError> {
    match take_while1::<_, _, ()>(is_alphapunc)(input) {
        Ok(r) if is_alpha(*r.1.first().unwrap()) => Ok(r),
        _ => Err(NomError(DkimSignatureParsingError::InvalidTagName)),
    }
}

fn tag_spec(input: &[u8]) -> IResult<&[u8], (&[u8], &[u8]), DkimSignatureParsingError> {
    // Remove whitespaces
    let (input, _wsp) = wsp(input).map_err(|_e| DkimSignatureParsingError::InvalidTag.into())?;

    // Take name
    let (input, name) = tag_name(input)?;

    // Remove whitespaces
    let (mut input, _wsp) = wsp(input).map_err(|_e| DkimSignatureParsingError::InvalidTag.into())?;

    // Assert there is an equal sign
    match tag::<_,_,()>(b"=")(input) {
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_tag_value() {
        assert_eq!(
            tag_value(b"This is a valid tag value").unwrap().1,
            &b"This is a valid tag value"[..]
        );
        assert_eq!(
            tag_value(b"This is a valid tag value    ").unwrap().1,
            &b"This is a valid tag value"[..]
        );
        assert_eq!(
            tag_value(b"This is a valid tag\r\n value").unwrap().1,
            &b"This is a valid tag\r\n value"[..]
        );
        assert_eq!(
            tag_value(b"This is a valid tag value; tagname=Another")
                .unwrap()
                .1,
            &b"This is a valid tag value"[..]
        );
        assert_eq!(tag_value(b"").unwrap().1, &b""[..]);

        assert!(tag_value(b" This is an invalid tag value").is_err()); // space at the start
        assert!(tag_value(b"This is an \rinvalid tag value").is_err()); // expected linefeed
        assert!(tag_value(b"This is an \r\ninvalid tag value").is_err()); // missing whitespace after folding
    }

    #[test]
    fn test_tag_name() {
        assert_eq!(tag_name(b"tag_name2").unwrap().1, &b"tag_name2"[..]);
        assert_eq!(tag_name(b"tag_na me2").unwrap().1, &b"tag_na"[..]);
        assert_eq!(tag_name(b"tag_name2=").unwrap().1, &b"tag_name2"[..]);

        assert!(tag_name(b"2tag_name").is_err());
        assert!(tag_name(b"_tag_name").is_err());
    }

    #[test]
    fn test_tag_spec() {
        assert_eq!(tag_spec(b"tag_name=value;").unwrap().1, (&b"tag_name"[..], &b"value"[..]));
        assert_eq!(tag_spec(b"  tag_name =  value   ;").unwrap().1, (&b"tag_name"[..], &b"value"[..]));
        assert_eq!(tag_spec(b"  tag_name = \r\n value   ;").unwrap().1, (&b"tag_name"[..], &b"value"[..]));
        assert_eq!(tag_spec(b"  tag_name = value   \r\n ;").unwrap().1, (&b"tag_name"[..], &b"value"[..]));
    }

    #[test]
    fn test_wsp() {
        assert_eq!(wsp(b"   ").unwrap().1, &b"   "[..]);
        assert_eq!(wsp(b" word ").unwrap().1, &b" "[..]);
        assert_eq!(wsp(b"  \t ").unwrap().1, &b"  \t "[..]);
        assert_eq!(wsp(b"  \r\n ").unwrap().1, &b"  \r\n "[..]);
        assert_eq!(wsp(b"  \r\n test").unwrap().1, &b"  \r\n "[..]);
    }
}
