#[allow(unused)]
use permcon::Octal;

#[derive(Debug)]
#[allow(dead_code)]
enum SpecialPermission {
    SUID,
    SGID,
    StickyBit,
    None,
}

impl SpecialPermission {}

struct FilePermission {
    user: Permission,
    group: Permission,
    other: Permission,
    special: [SpecialPermission; 3],
}

impl FilePermission {
    fn to_symbolic_string() -> String {
        let permission = String::new();
        return permission;
    }
}

#[derive(Debug)]
#[allow(dead_code)]
struct Permission {
    read: bool,
    write: bool,
    execute: bool,
    special: bool,
}

impl Permission {
    fn from_symbolic_bits(bits: &str) -> Result<Self, String> {
        let chars: Vec<char> = bits.chars().collect();

        match chars[..] {
            [r, w, x] => {
                let (execute, special) = parse_symbolic_execution_bit(x);

                return Ok(Permission {
                    execute,
                    special,
                    read: r == 'r',
                    write: w == 'w',
                });
            }
            _ => return Err(String::from("Invalid permission bits length!")),
        }
    }

    fn from_octal_digit(digit: u8, is_special: bool) -> Result<Self, String> {
        let [read, write, execute] = parse_octal_digit(digit);
        return Ok(Permission {
            read,
            write,
            execute,
            special: is_special,
        });
    }

    fn to_string(self, special_char: char) {
        let mut permission = String::new();
        permission.push(if self.read { 'r' } else { '-' });
        permission.push(if self.write { 'w' } else { '-' });

        if self.special {
            permission.push(if self.execute {
                special_char
            } else {
                special_char.to_uppercase().next().unwrap()
            });
        } else {
            permission.push(if self.execute { 'x' } else { '-' });
        }
    }
}

/// Parses the last char of permission bits (e.g., `"rwxrwxrwx"`, x) and
/// returns `(execute, special)`
#[allow(unused)]
fn parse_symbolic_execution_bit(bit: char) -> (bool, bool) {
    if "ST".contains(bit) {
        return (false, true);
    }

    if "stx".contains(bit) {
        return (true, true);
    }

    return (false, false);
}

fn parse_octal_digit(digit: u8) -> [bool; 3] {
    let permission: Vec<bool> = format!("{:03b}", digit)
        .chars()
        .map(|char| char == '1')
        .collect();

    permission.try_into().unwrap_or([false; 3])
}

fn main() {
    let x = parse_octal_digit(2u8);
    println!("{:?}", x);

    // use permcon::Symbolic;
    // let perm_str = "drwxrwxr-x";
    // let _ = Symbolic::from_str(perm_str);
    // let x = Permission::from_symbolic_bits("rwS");
    // println!("{:#?}", x);
}
