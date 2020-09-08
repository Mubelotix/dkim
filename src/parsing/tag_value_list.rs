use crate::parsing::ParsingError;
use nom::{
    bytes::complete::{tag, take_while1},
    Err::Error as NomError,
    IResult,
};

/// Determine if a character can be used in a value.
pub(crate) fn is_valchar(character: char) -> bool {
    character as u8 >= 0x21 && character as u8 <= 0x7e && character as u8 != b';'
}

/// Determine if a character is a whitespace.
pub(crate) fn is_wsp(character: char) -> bool {
    character as u8 == b' ' || character as u8 == b'\t'
}

/// Determine if a character is a letter.
pub(crate) fn is_alpha(character: char) -> bool {
    (character as u8 >= 0x41 && character as u8 <= 0x5a)
        || (character as u8 >= 0x61 && character as u8 <= 0x7a)
}

/// Determine if a character is a digit.
pub(crate) fn is_digit(character: char) -> bool {
    character as u8 >= 0x30 && character as u8 <= 0x39
}

/// Determine if a character can be used in a tag name.
pub(crate) fn is_alphapunc(character: char) -> bool {
    is_alpha(character) || is_digit(character) || character == '_'
}

/// Determine if a character can be used in an email header.
pub(crate) fn is_ftext(character: char) -> bool {
    character as u8 >= 33 && character as u8 <= 126 && character as u8 != 58
}

/// Read a whitespace (can be a folding whitespace).
pub(crate) fn wsp(input: &str) -> IResult<&str, &str, ParsingError> {
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
            Status::Anything => {
                if character == '\r' {
                    status = Status::LineFeed;
                } else if !is_wsp(character) {
                    end_idx = Some(idx);
                    break;
                }
            }
            Status::LineFeed => {
                if character == '\n' {
                    status = Status::Whitespace;
                } else {
                    return Err(ParsingError::ExpectedLineFeed.into());
                }
            }
            Status::Whitespace => {
                if is_wsp(character) {
                    status = Status::Anything;
                } else {
                    return Err(ParsingError::ExpectedWhitespace.into());
                }
            }
        }
    }

    let end_idx = end_idx.unwrap_or(input.len());
    Ok((&input[end_idx..], &input[..end_idx]))
}

/// Read a tag name.
pub(crate) fn tag_name(input: &str) -> IResult<&str, &str, ParsingError> {
    match take_while1::<_, _, ()>(is_alphapunc)(input) {
        Ok(r) if is_alpha(r.1.chars().next().unwrap()) => Ok(r),
        _ => Err(NomError(ParsingError::InvalidTagName)),
    }
}

/// Read a tag value.
pub(crate) fn tag_value(input: &str) -> IResult<&str, &str, ParsingError> {
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

/// Read a tag and parse it using a custom parsing function.  
/// The name of the tag and the remaining part of the data will be provided as parameters to the function.  
pub(crate) fn tag_spec<'a, T>(
    input: &'a str,
    value_parser: &dyn Fn(&'a str, &'a str) -> IResult<&'a str, T, ParsingError>,
) -> IResult<&'a str, T, ParsingError> {
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
    let (input, tag) = value_parser(name, input)?;

    // Remove whitespaces
    let (input, _wsp) = wsp(input)?;

    Ok((input, tag))
}

/// Read a list of tags.  
/// Values of tags will be parsed by the specified function.  
pub fn tag_list<'a, T>(
    input: &'a str,
    value_parser: &dyn Fn(&'a str, &'a str) -> IResult<&'a str, T, ParsingError>,
) -> Result<Vec<T>, ParsingError> {
    let handle_error = |e| {
        if let NomError(e) = e {
            e
        } else {
            ParsingError::InvalidTagName
        }
    };

    let mut tags = Vec::new();
    let (mut input, first_tag) = tag_spec(input, value_parser).map_err(handle_error)?;
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

        let new_tag = tag_spec(input, value_parser).map_err(handle_error)?;
        input = new_tag.0;
        tags.push(new_tag.1);
    }

    Ok(tags)
}

#[cfg(test)]
mod test {
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
    fn test_tag_name() {
        assert_eq!(tag_name("tag_name2").unwrap().1, "tag_name2");
        assert_eq!(tag_name("tag_na me2").unwrap().1, "tag_na");
        assert_eq!(tag_name("tag_name2=").unwrap().1, "tag_name2");

        assert!(tag_name("2tag_name").is_err());
        assert!(tag_name("_tag_name").is_err());
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
}
