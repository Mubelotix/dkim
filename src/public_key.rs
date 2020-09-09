use crate::parsing::{
    ParsingError,
    tag_value_list::tag_list,
    dns_record::dns_record_tag,
};



/// A struct reprensenting a public key used in DKIM dns record.
#[derive(Debug)]
pub struct PublicKey<'a> {
    pub(crate) acceptable_hash_algorithms: Option<Vec<&'a str>>,
    pub(crate) key_type: &'a str,
    pub(crate) key_data: Vec<u8>,
    pub(crate) service_types: Vec<&'a str>,
    pub(crate) flags: Vec<&'a str>,
    pub(crate) notes: Option<String>,
}

impl<'a> std::convert::TryFrom<&'a str> for PublicKey<'a> {
    type Error = ParsingError<'a>;

    #[allow(clippy::many_single_char_names)]
    fn try_from(input: &'a str) -> Result<PublicKey, ParsingError<'a>> {
        use crate::parsing::dns_record::Tag;

        let mut version: Option<&'a str> = None;
        let mut acceptable_hash_algorithms: Option<Vec<&'a str>> = None;
        let mut key_type: Option<&'a str> = None;
        let mut key_data: Option<Vec<u8>> = None;
        let mut service_types: Option<Vec<&'a str>> = None;
        let mut flags: Option<Vec<&'a str>> = None;
        let mut notes: Option<String> = None;

        for tag in tag_list(input, &dns_record_tag)? {
            #[inline(always)]
            fn replace<'a, T>(
                to: &mut Option<T>,
                from: T,
                name: &'static str,
            ) -> Result<(), ParsingError<'a>> {
                if to.replace(from).is_some() {
                    Err(ParsingError::DuplicatedField(name))
                } else {
                    Ok(())
                }
            }

            match tag {
                Tag::Version(v) => replace(&mut version, v, "v")?,
                Tag::AcceptableHashAlgorithms(algorithms) => {
                    replace(&mut acceptable_hash_algorithms, algorithms, "h")?
                }
                Tag::KeyType(k) => replace(&mut key_type, k, "k")?,
                Tag::Notes(n) => replace(&mut notes, n, "n")?,
                Tag::PublicKey(data) => replace(&mut key_data, data, "p")?,
                Tag::ServiceTypes(services) => replace(&mut service_types, services, "s")?,
                Tag::Flags(t) => replace(&mut flags, t, "f")?,
                Tag::Unknown(_n, _v) => (),
            }
        }

        if let Some(version) = version {
            if version != "DKIM1" {
                return Err(ParsingError::UnsupportedVersion(version));
            }
        }

        if let Some(service_types) = &service_types {
            if !service_types.contains(&"email") && !service_types.contains(&"*") {
                return Err(ParsingError::UnableToAccomodateParameter("s", "This public is not intended to be used by emails."));
            }
        }

        Ok(PublicKey {
            acceptable_hash_algorithms,
            key_type: key_type.unwrap_or("rsa"),
            key_data: key_data.ok_or(ParsingError::MissingTag("p"))?,
            service_types: service_types.unwrap_or(vec!["*"]),
            flags: flags.unwrap_or(Vec::new()),
            notes,
        })
    }
}

impl<'a> PublicKey<'a> {
    /// Creates a new PublicKey with all fields specified.
    pub fn new(
        acceptable_hash_algorithms: Option<Vec<&'a str>>,
        key_type: &'a str,
        key_data: Vec<u8>,
        service_types: Vec<&'a str>,
        flags: Vec<&'a str>,
        notes: Option<String>,
    ) -> PublicKey<'a> {
        PublicKey {
            acceptable_hash_algorithms,
            key_type,
            key_data,
            service_types,
            flags,
            notes,
        }
    }

    /// Loads a public key from the DNS.
    pub fn load(selector: &str, domain: &str) -> Result<Vec<String>, ParsingError<'a>> {
        use trust_dns_resolver::config::*;
        use trust_dns_resolver::Resolver;

        let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default()).unwrap();
        let txt_fields = resolver
            .txt_lookup(&format!("{}._domainkey.{}", selector, domain))
            .unwrap();

        let mut records = Vec::new();
        for packets in txt_fields.iter().map(|data| data.txt_data()) {
            let mut response = Vec::new();
            for packet in packets {
                response.extend(packet.iter());
            }
            let response = String::from_utf8(response).unwrap();
            records.push(response);
        }

        if records.is_empty() {
            Err(ParsingError::Other("No valid TXT record found on the DNS."))
        } else {
            Ok(records)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;

    #[test]
    fn get_dkim_record() {
        println!("{:?}", PublicKey::load("20161025", "gmail.com").unwrap());
    }
}