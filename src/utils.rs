/// Parses an octal digit and turns it to a `[bool; 3]` based on its bits.
/// **Note:** The number must be within `0..=7` range.
///
///
/// Examples:
/// <br>
/// ```
/// 0 -> 000 -> [false, false, false]
/// 1 -> 001 -> [false, false, true]
/// 2 -> 010 -> [false, true, false]
/// 4 -> 100 -> [true, false, false]
/// ```
pub fn parse_octal_digit(digit: u8) -> Result<[bool; 3], String> {
    if digit > 7 {
        return Err(format!(
            "The digit must be within 0..=7 range. Found {digit}!"
        ));
    }

    let permission: [bool; 3] = format!("{:03b}", digit)
        .chars()
        .map(|char| char == '1')
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    Ok(permission)
}

/// Takes an array of bool (\[read, write, execute]) and returns the octal digit
pub fn bool_arr_to_octal_digit(arr: &[bool; 3]) -> u8 {
    let bin_str = arr.map(|perm| if perm { "1" } else { "0" }).join("");
    u8::from_str_radix(&bin_str, 2).unwrap()
}

/// Parses the last char of permission bits (e.g., the `x` of `"rwx"`) and
/// returns `(execute, special)`
pub fn parse_symbolic_execution_bit(bit: char) -> (bool, bool) {
    if "ST".contains(bit) {
        return (false, true);
    }

    if "st".contains(bit) {
        return (true, true);
    }

    if bit == 'x' {
        return (true, false);
    }

    return (false, false);
}

/// Returns the full file type from the symbolic file type char. For example:
/// `'d' -> "Directory"`.
pub fn get_filetype_from_char(ft_char: char) -> String {
    let file_type = match ft_char {
        '-' => "Regular File",
        'd' => "Directory",
        'l' => "Symbolic Link",
        'b' => "Block Device",
        'c' => "Character Device",
        's' => "Socket",
        'p' => "Named Pipe",
        _ => "Unknown",
    };

    file_type.to_string()
}

#[allow(unused)]
struct TestCase<I, O> {
    input: I,
    output: O,
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CASES: [(u8, [bool; 3]); 8] = [
        (0, [false; 3]),
        (1, [false, false, true]),
        (2, [false, true, false]),
        (3, [false, true, true]),
        (4, [true, false, false]),
        (5, [true, false, true]),
        (6, [true, true, false]),
        (7, [true, true, true]),
    ];

    #[test]
    fn test_parse_octal_digit() {
        for (digit, output) in TEST_CASES {
            assert_eq!(parse_octal_digit(digit), Ok(output));
        }
    }

    #[test]
    fn test_bool_arr_to_octal_digit() {
        for (digit, array) in TEST_CASES {
            assert_eq!(bool_arr_to_octal_digit(&array), digit);
        }
    }
}
