/// Functions for parsing a DKIM dns record
pub mod dns_record;
/// Encode or decode strings with dkim-quoted-printable.
pub mod quoted_printable;
/// Functions for parsing a DKIM-Signature header
pub mod signature_header;
/// Common functions to parse a dkim tag value list
pub mod tag_value_list;

/// Parse a mail using the `email_parser` crate.
pub fn parse_mail<'a>(raw_mail: &'a str) -> Result<(Vec<(&'a str, &'a str)>, &'a str), ()> {
    let parsed_mail = email_parser::parser::parse_message(raw_mail.as_bytes())?;

    let headers: Vec<(&str, &str)> = parsed_mail
        .0
        .iter()
        .filter_map(|(n, v)| {
            if let (Ok(name), Ok(value)) = (std::str::from_utf8(n), std::str::from_utf8(v)) {
                Some((name, value))
            } else {
                None
            }
        })
        .collect();

    Ok((
        headers,
        parsed_mail
            .1
            .map(|b| std::str::from_utf8(b).ok())
            .flatten()
            .unwrap_or(""),
    ))
}

/// An error related to parsing
#[derive(Debug)]
pub enum ParsingError<'a> {
    /// A tag name contains invalid characters.
    InvalidTagName,
    /// A line feed character is missing (probably after '\r').
    ExpectedLineFeed,
    /// A whitespace character is missing (probably after "\r\n").
    ExpectedWhitespace,
    /// An equal sign is missing (probably after a tag name, which could have ended prematurely due to invalid characters).
    ExpectedEqualSign,
    /// A semicolon is missing (probably after a tag value, which could have ended prematurely due to invalid characters).
    MissingSemicolon,
    /// A tag value is invalid for a reason specified in this field.
    InvalidTagValue(&'static str),
    /// Missing required tag
    MissingTag(&'static str),
    /// A tag has been found multiple times
    DuplicatedField(&'static str),
    /// Unsupported DKIM version
    UnsupportedVersion(&'a str),
    /// Unable to accomodate a parameter
    UnableToAccomodateParameter(&'static str, &'static str),
    /// Other
    Other(&'static str),
}

impl<'a> Into<nom::Err<ParsingError<'a>>> for ParsingError<'a> {
    fn into(self) -> nom::Err<ParsingError<'a>> {
        nom::Err::Error(self)
    }
}

impl<'a> std::fmt::Display for ParsingError<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParsingError::InvalidTagName => write!(f, "A tag name contains invalid characters."),
            ParsingError::ExpectedLineFeed => write!(f, "A line feed character is missing (probably after '\r')."),
            ParsingError::ExpectedWhitespace => write!(f, "A whitespace character is missing (probably after \"\r\n\")."),
            ParsingError::ExpectedEqualSign => write!(f, "An equal sign is missing (probably after a tag name, which could have ended prematurely due to invalid characters)."),
            ParsingError::MissingSemicolon => write!(f, "A semicolon is missing (probably after a tag value, which could have ended prematurely due to invalid characters)."),
            ParsingError::InvalidTagValue(reason) => write!(f, "A tag value is invalid because {}.", reason),
            ParsingError::MissingTag(tag) => write!(f, "The tag {:?} is missing from the list.", tag),
            ParsingError::DuplicatedField(tag) => write!(f, "The tag {:?} is appearing multiple times in the list.", tag),
            ParsingError::UnsupportedVersion(tag) => write!(f, "The version {} is not supported by this program. RFC 6376 is the only supported version.", tag),
            ParsingError::UnableToAccomodateParameter(tag, explanation) => write!(f, "Unable to accomodate tag {:?}. {}.", tag, explanation),
            ParsingError::Other(message) => write!(f, "{}", message),
        }
    }
}

impl<'a> std::error::Error for ParsingError<'a> {}
