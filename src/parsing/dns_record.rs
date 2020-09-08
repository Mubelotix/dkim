use crate::parsing::{quoted_printable::from_dqp, tag_value_list::*, ParsingError};
use nom::{
    bytes::complete::{tag, take_while1},
    IResult,
};

/// A valid tag in a DKIM dns TXT record.
#[derive(Debug, PartialEq)]
pub enum Tag<'a> {
    Version(&'a str),
    AcceptableHashAlgorithms(Vec<&'a str>),
    KeyType(&'a str),
    Notes(String),
    PublicKey(Vec<u8>),
    ServiceTypes(Vec<&'a str>),
    Flags(Vec<&'a str>),
    Unknown(&'a str, &'a str),
}

/// Read values separated by colons
fn colon_separated_values(input: &str) -> IResult<&str, Vec<&str>, ParsingError> {
    fn hash_algorithm(input: &str) -> IResult<&str, &str, ParsingError> {
        fn is_valid(character: char) -> bool {
            is_valchar(character) && character != ':'
        }

        take_while1::<_, _, ()>(is_valid)(input)
            .map_err(|_e| ParsingError::InvalidTagValue("h").into())
    }

    let mut values = Vec::new();
    let (mut input, first_value) = hash_algorithm(input)?;
    values.push(first_value);
    input = wsp(input)?.0;

    loop {
        if input.starts_with(";") || input.is_empty() {
            break;
        }

        input = tag::<_, _, ()>(":")(input)
            .map_err(|_e| ParsingError::InvalidTagValue("h").into())?
            .0;
        input = wsp(input)?.0;
        let (remaining_input, value) = hash_algorithm(input)?;
        input = remaining_input;
        values.push(value);
        input = wsp(input)?.0;
    }

    Ok((input, values))
}

/// Read and parse a tag valid in a DKIM dns TXT record.
pub fn dns_record_tag<'a>(
    name: &'a str,
    input: &'a str,
) -> IResult<&'a str, Tag<'a>, ParsingError> {
    Ok(match name {
        "v" => {
            let (input, value) = tag_value(input)?;
            (input, Tag::Version(value))
        }
        "h" => {
            let (input, hash_algorithms) = colon_separated_values(input)?;
            (input, Tag::AcceptableHashAlgorithms(hash_algorithms))
        }
        "k" => {
            let (input, value) = tag_value(input)?;
            (input, Tag::KeyType(value))
        }
        "n" => {
            let (input, value) = from_dqp(input)?;
            (input, Tag::Notes(value))
        }
        "p" => {
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
                base64::decode(value).map_err(|_e| ParsingError::InvalidTagValue("p").into())?;
            (input, Tag::PublicKey(value))
        }
        "s" => {
            let (input, services) = colon_separated_values(input)?;
            (input, Tag::ServiceTypes(services))
        }
        "t" => {
            let (input, flags) = colon_separated_values(input)?;
            (input, Tag::Flags(flags))
        }
        _ => {
            let (input, value) = tag_value(input)?;
            (input, Tag::Unknown(name, value))
        }
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::parsing::tag_value_list::tag_list;

    #[test]
    fn test_txt_record_parsing() {
        assert_eq!(tag_list("v=DKIM1; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkMoGeLnQg1fWn7/zYtIxN2SnFCjxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v/RtdC2UzJ1lWT947qR+Rcac2gbto/NMqJ0fzfVjH4OuKhitdY9tf6mcwGjaNBcWToIMmPSPDdQPNUYckcQ2QIDAQAB", &dns_record_tag).unwrap(), vec![
            Tag::Version("DKIM1"),
            Tag::PublicKey(vec![48, 129, 159, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 129, 141, 0, 48, 129, 137, 2, 129, 129, 0, 240, 33, 19, 255, 80, 45, 210, 6, 193, 38, 26, 166, 125, 100, 149, 183, 252, 57, 12, 160, 103, 139, 157, 8, 53, 125, 105, 251, 255, 54, 45, 35, 19, 118, 74, 113, 66, 143, 19, 130, 40, 111, 111, 221, 190, 35, 97, 247, 19, 54, 30, 98, 141, 43, 42, 235, 125, 110, 4, 139, 75, 107, 186, 29, 250, 255, 209, 181, 208, 182, 83, 50, 117, 149, 100, 253, 227, 186, 145, 249, 23, 26, 115, 104, 27, 182, 143, 205, 50, 162, 116, 127, 55, 213, 140, 126, 14, 184, 168, 98, 181, 214, 61, 181, 254, 166, 115, 1, 163, 104, 208, 92, 89, 58, 8, 50, 99, 210, 60, 55, 80, 60, 213, 24, 114, 71, 16, 217, 2, 3, 1, 0, 1])
        ]);

        assert_eq!(
            tag_list(
                "v=DKIM1; h=sha1:sha256; n=this=20is=20a=20test; s=email; t=y:s:z; other=mubelotix",
                &dns_record_tag
            )
            .unwrap(),
            vec![
                Tag::Version("DKIM1"),
                Tag::AcceptableHashAlgorithms(vec!["sha1", "sha256"]),
                Tag::Notes(String::from("this is a test")),
                Tag::ServiceTypes(vec!["email"]),
                Tag::Flags(vec!["y", "s", "z"]),
                Tag::Unknown("other", "mubelotix"),
            ]
        );
    }

    #[test]
    fn test_colon_separated_value() {
        assert_eq!(
            colon_separated_values("first:second:third").unwrap().1,
            vec!["first", "second", "third"]
        );

        assert_eq!(
            colon_separated_values("first:  second:third").unwrap().1,
            vec!["first", "second", "third"]
        );

        assert_eq!(
            colon_separated_values("first: \r\n  second:third")
                .unwrap()
                .1,
            vec!["first", "second", "third"]
        );

        assert_eq!(colon_separated_values("first").unwrap().1, vec!["first"]);

        assert_eq!(
            colon_separated_values("first:second:third\r\n :fourth")
                .unwrap()
                .1,
            vec!["first", "second", "third", "fourth"]
        );
    }
}
