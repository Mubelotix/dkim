pub mod verifier;
pub mod canonicalization;
pub mod hash;

pub enum SigningAlgorithm {
    RSASha1,
    RSASha256,
}

pub enum MessageCanonicalization {
    Simple,
    Relaxed
}

#[cfg(test)]
mod tests {
    const MAIL: &str = include_str!("mail.txt");
    #[test]
    fn it_works() {
        use base64::{decode, encode};
        let mail = email::MimeMessage::parse(MAIL);
        let headers = crate::canonicalization::canonicalize_headers_relaxed(MAIL, vec!["mime-version","references","in-reply-to","from","date","message-id","subject","to"]);
        let headers = crate::canonicalization::canonicalize_headers_relaxed("A: X\r\nB : Y\t\r\n\tZ  \r\n\r\n", vec!["a","b"]);
        
        let hash = crate::hash::hash_sha256(&headers);
        println!("{:?}", headers);
        println!("{:?}", encode(&hash));

        //assert!(crate::verifier::verify(&decode("9/XsYLqJKQrztUhUgJ9FwqroX+RBKlWMkPyJIZsPcpU=").unwrap(), &decode("hXPEvSUoK25Mz25ddgi7+JP3B55j4q56hNdaqkGKDhIJJSdkEnsZMmwJ2O9lyjSYSaWFGUjDHzO9yBqjjDgFp87aA9WnJ5/t/onCXxeUsifo61DLLYf1hEuq4via2MPS4tKAM3D9yQ8yZjhD5y6vS2YEZj6o6FP9G+wgE8PpZmLqYGGNrkyOKDaLFHWOn7ZqkL1bgmRoOfvsbYSnPEKsnrNb/csU2RCKwRwlWehjTgAKGRS4R0Qop8Z/hTAZCkCTD9XCgihv0X9ia8ecBplISlwigHPmNnlIykVKr1vopL8mCvFo10XPGoKracbRwbW+UrPnsyOyJuK267zwyytyPw==").unwrap()));
    }
}