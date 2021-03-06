/// Functions for parsing a DKIM dns record
pub mod dns_record;
/// Encode or decode strings with dkim-quoted-printable.
pub mod quoted_printable;
/// Functions for parsing a DKIM-Signature header
pub mod signature_header;
/// Common functions to parse a dkim tag value list
pub mod tag_value_list;

/// An error related to parsing
#[derive(Debug)]
pub enum ParsingError {
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
}

impl Into<nom::Err<ParsingError>> for ParsingError {
    fn into(self) -> nom::Err<ParsingError> {
        nom::Err::Error(self)
    }
}

impl std::fmt::Display for ParsingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParsingError::InvalidTagName => write!(f, "A tag name contains invalid characters."),
            ParsingError::ExpectedLineFeed => write!(f, "A line feed character is missing (probably after '\r')."),
            ParsingError::ExpectedWhitespace => write!(f, "A whitespace character is missing (probably after \"\r\n\")."),
            ParsingError::ExpectedEqualSign => write!(f, "An equal sign is missing (probably after a tag name, which could have ended prematurely due to invalid characters)."),
            ParsingError::MissingSemicolon => write!(f, "A semicolon is missing (probably after a tag value, which could have ended prematurely due to invalid characters)."),
            ParsingError::InvalidTagValue(reason) => write!(f, "A tag value is invalid because {}.", reason),
        }
    }
}

impl std::error::Error for ParsingError {}
