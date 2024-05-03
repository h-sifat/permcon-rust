#[allow(unused)]
pub fn parse_octal_digit(digit: u8) -> [bool; 3] {
    let permission: Vec<bool> = format!("{:03b}", digit)
        .chars()
        .map(|char| char == '1')
        .collect();

    permission.try_into().unwrap_or([false; 3])
}

/// Take an array of bool ([read, write, execute]) and returns the octal digit
pub fn bool_arr_to_octal_digit(arr: [bool; 3]) -> u8 {
    let bin_str = arr.map(|perm| if perm { "1" } else { "0" }).join("");
    u8::from_str_radix(&bin_str, 2).unwrap()
}

/// Parses the last char of permission bits (e.g., `"rwxrwxrwx"`, x) and
/// returns `(execute, special)`
#[allow(unused)]
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
