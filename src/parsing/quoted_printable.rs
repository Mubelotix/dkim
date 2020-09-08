use crate::parsing::tag_value_list::{is_valchar, is_wsp};
use crate::parsing::ParsingError;

/// Read a string encoded with dkim-quoted-printable.
pub fn from_dqp(input: &str) -> nom::IResult<&str, String, ParsingError> {
    let mut chars = input.chars().enumerate();
    let mut result = String::new();
    let mut last_valid_idx = 0;
    loop {
        let (idx, character) = match chars.next() {
            Some(character) => character,
            None => break,
        };

        match character {
            character if is_valchar(character) && character != '=' => {
                last_valid_idx = idx + 1;
                result.push(character);
            }
            character if character == '=' => {
                if let (Some((_, c1)), Some((idx, c2))) = (chars.next(), chars.next()) {
                    let mut number = String::new();
                    number.push(c1);
                    number.push(c2);
                    let character: char = u8::from_str_radix(&number, 16).map_err(|_e| {
                        ParsingError::InvalidTagValue("dkim-quoted-printable failed").into()
                    })? as char;
                    result.push(character);
                    last_valid_idx = idx + 1;
                } else {
                    return Err(
                        ParsingError::InvalidTagValue("dkim-quoted-printable failed").into(),
                    );
                }
            }
            character if character == '\r' => {
                match chars.next() {
                    Some((_, '\n')) => (),
                    _ => return Err(ParsingError::ExpectedLineFeed.into()),
                }
                match chars.next() {
                    Some((_, character)) if is_wsp(character) => (),
                    _ => return Err(ParsingError::ExpectedWhitespace.into()),
                }
            }
            character if is_wsp(character) => (),
            _ => {
                break;
            }
        }
    }

    Ok((&input[last_valid_idx..], result))
}

/// Encode a string with dkim-quoted-printable.
pub fn into_dqp(input: &str) -> String {
    // todo guarantee safe chars
    let mut result = String::new();
    for character in input.chars() {
        let value = character as u8;
        if value < 0x20 || value >= 0x7f || value == 0x20 || value == 0x3b || value == 0x3d {
            result.push('=');
            fn hex_from_digit(num: u8) -> char {
                if num < 10 {
                    (b'0' + num) as char
                } else {
                    (b'A' + num - 10) as char
                }
            }
            result.push(hex_from_digit(value / 16));
            result.push(hex_from_digit(value % 16));
        } else {
            result.push(character);
        }
    }
    result
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_dkim_quoted_printable_parsing() {
        assert_eq!(&from_dqp("this\r\n is a test").unwrap().1, "thisisatest");
        assert_eq!(
            &from_dqp("This=20is=20a=20test").unwrap().1,
            "This is a test"
        );
        assert_eq!(
            &from_dqp("This=20is=00a=09test").unwrap().1,
            "This is\u{0}a\ttest"
        );
    }

    #[test]
    fn test_dkim_quoted_printable_generation() {
        assert_eq!(
            &into_dqp("Welcome to the aperture science computer aided enrichment center"),
            "Welcome=20to=20the=20aperture=20science=20computer=20aided=20enrichment=20center"
        );
        assert_eq!(
            &into_dqp("La France est également composée de nombreux territoires situés en dehors du continent européen, couramment appelés France d'outre-mer, qui lui permettent d'être présente dans tous les océans du monde sauf l'océan Arctique."),
            "La=20France=20est=20=E9galement=20compos=E9e=20de=20nombreux=20territoires=20situ=E9s=20en=20dehors=20du=20continent=20europ=E9en,=20couramment=20appel=E9s=20France=20d\'outre-mer,=20qui=20lui=20permettent=20d\'=EAtre=20pr=E9sente=20dans=20tous=20les=20oc=E9ans=20du=20monde=20sauf=20l\'oc=E9an=20Arctique."
        );
    }

    #[test]
    fn test_dkim_quoted_printable_generation_and_parsing() {
        assert_eq!(from_dqp(&into_dqp("Ces territoires ont des statuts variés dans l'administration territoriale de la France et sont situés : ")).unwrap().1, "Ces territoires ont des statuts variés dans l'administration territoriale de la France et sont situés : ");

        assert_eq!(from_dqp(&into_dqp("Au nord s'étend la vaste forêt de Cussangy d'enviton 800 hectares, qui se poursuit jusqu'à Chaource. C'est une forêt de feuillus essentiellement : chênes, charmes, acacias, bouleaux, merisiers. Les bois sont soit communaux (270 hectares environ) ou privés.")).unwrap().1, "Au nord s'étend la vaste forêt de Cussangy d'enviton 800 hectares, qui se poursuit jusqu'à Chaource. C'est une forêt de feuillus essentiellement : chênes, charmes, acacias, bouleaux, merisiers. Les bois sont soit communaux (270 hectares environ) ou privés.");
    }
}
