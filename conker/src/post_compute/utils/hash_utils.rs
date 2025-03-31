use sha3::Digest;

pub fn concatenate_and_hash(hexa_strings: &[&str]) -> String {
    let mut res: Vec<u8> = vec![];
    for hexa_string in hexa_strings {
        let mut hexa_string_as_vec = string_to_bytes(hexa_string).to_vec();
        res.append(&mut hexa_string_as_vec);
    }
    return to_hex_string(sha3(res.as_slice()).as_ref());
}

pub fn get_message_hash(result_hash: &str, result_seal: &str) -> String {
    let message_hash_args = [result_hash, result_seal];
    concatenate_and_hash(&message_hash_args)
}

pub fn string_to_bytes(hexa_string: &str) -> Vec<u8> {
    hex_string_to_byte_array(hexa_string)
}

fn hex_string_to_byte_array(input: &str) -> Vec<u8> {
    let clean_input = clean_hex_prefix(input);
    let len = clean_input.len();
    if len == 0 {
        return vec![];
    }

    let mut data: Vec<u8> = vec![];
    let start_idx;
    let mut chars = clean_input.chars();
    if len % 2 != 0 {
        let ch = chars.next().unwrap();
        let byte = digit(&ch);
        data.push(byte);
        start_idx = 1;
    } else {
        start_idx = 0;
    }

    for i in (start_idx..len).step_by(2) {
        let byte = (digit(&chars.next().unwrap()) << 4) + digit(&chars.next().unwrap());
        data.push(byte);
    }

    data
}

pub fn clean_hex_prefix(input: &str) -> &str {
    match input.strip_prefix("0x") {
        None => input,
        Some(stripped_input) => stripped_input,
    }
}

fn digit(ch: &char) -> u8 {
    ch.to_digit(16).unwrap().try_into().unwrap()
}

const HEX_CHAR_MAP: &[char] = &[
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
];

fn to_hex_string(bytes: &[u8]) -> String {
    let mut output: Vec<char> = vec![];
    let length = bytes.len();

    for i in 0..length {
        let v = bytes[i];
        let first_byte_index: usize = (v >> 4) as usize;
        let second_byte_index: usize = (v & 0x0F) as usize;
        output.append(&mut vec![
            HEX_CHAR_MAP[first_byte_index],
            HEX_CHAR_MAP[second_byte_index],
        ]);
    }

    let hex_string: String = output.into_iter().collect();

    format!("0x{}", hex_string)
}

fn sha3(input: &[u8]) -> Box<[u8]> {
    // create a SHA3-256 object
    let mut hasher = sha3::Keccak256::new();

    // write input message
    Digest::update(&mut hasher, input);

    // read hash digest
    let result = hasher.finalize();
    let result = result.as_slice();

    Box::from(result)
}

pub fn sha256(utf8_string: &str) -> String {
    let bytes = utf8_string.as_bytes();
    sha256::digest(bytes)
}

// region Tests
#[cfg(test)]
mod tests {
    use crate::post_compute::utils::hash_utils::{concatenate_and_hash, sha3, to_hex_string};

    #[test]
    fn test_to_hex_string() {
        let v: Vec<u8> = vec![
            179, 177, 220, 201, 87, 53, 30, 255, 103, 134, 108, 188, 148, 123, 225, 4, 167, 29, 9,
            255, 126, 20, 106, 44, 66, 232, 247, 237, 194, 191, 80, 28,
        ];
        assert_eq!(
            "0xb3b1dcc957351eff67866cbc947be104a71d09ff7e146a2c42e8f7edc2bf501c",
            to_hex_string(v.as_slice())
        )
    }

    #[test]
    fn test_sha3() {
        let v: Vec<u8> = vec![
            139, 115, 195, 198, 155, 184, 254, 61, 81, 46, 204, 76, 247, 89, 204, 121, 35, 159,
            123, 23, 155, 15, 250, 202, 169, 167, 93, 82, 43, 57, 64, 15, 156, 38, 170, 121, 241,
            79, 124, 16, 207, 70, 98, 77, 53, 192, 147, 185, 29, 54, 73, 120, 83, 104, 17, 104, 61,
            109, 215, 156, 247, 233, 195, 19, 200, 158, 253, 170, 84, 192, 242, 12, 122, 223, 97,
            40, 130, 223, 9, 80, 245, 169, 81, 99, 126, 3, 7, 205, 203, 76, 103, 47, 41, 139, 139,
            198, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 1,
        ];
        assert_eq!(
            "0xb3b1dcc957351eff67866cbc947be104a71d09ff7e146a2c42e8f7edc2bf501c",
            to_hex_string(sha3(v.as_slice()).as_ref())
        );
    }

    #[test]
    fn should_concatenate_one_value() {
        let hexa1 = "0x748e091bf16048cb5103E0E10F9D5a8b7fBDd860";

        let expected = "0x7ec1be13dbade2e3bfde8c2bdf68859dfff4ea620b3340c451ec56b5fa505ab1";

        assert_eq!(expected, concatenate_and_hash(&[hexa1]));
    }

    #[test]
    fn should_concatenate_two_values() {
        let hexa1 = "0x748e091bf16048cb5103E0E10F9D5a8b7fBDd860";
        let hexa2 = "0xd94b63fc2d3ec4b96daf84b403bbafdc8c8517e8e2addd51fec0fa4e67801be8";

        let expected = "0x9ca8cbf81a285c62778678c874dae13fdc6857566b67a9a825434dd557e18a8d";

        assert_eq!(expected, concatenate_and_hash(&[hexa1, hexa2]));
    }

    #[test]
    fn should_concatenate_three_values() {
        let hexa1 = "0x748e091bf16048cb5103E0E10F9D5a8b7fBDd860";
        let hexa2 = "0xd94b63fc2d3ec4b96daf84b403bbafdc8c8517e8e2addd51fec0fa4e67801be8";
        let hexa3 = "0x9a43BB008b7A657e1936ebf5d8e28e5c5E021596";

        let expected = "0x54a76d209e8167e1ffa3bde8e3e7b30068423ca9554e1d605d8ee8fd0f165562";

        assert_eq!(expected, concatenate_and_hash(&[hexa1, hexa2, hexa3]));
    }
}
// endregion
