#[allow(unused)]
pub fn parse_octal_digit(digit: u8) -> [bool; 3] {
    let permission: Vec<bool> = format!("{:03b}", digit)
        .chars()
        .map(|char| char == '1')
        .collect();

    permission.try_into().unwrap_or([false; 3])
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
