use std::str::FromStr;

use crate::{
    symbolic::Symbolic,
    utils::{get_filetype_from_char, parse_octal_digit, parse_symbolic_execution_bit},
};

const SPECIAL_CHARS: [char; 3] = ['s', 's', 't'];

#[derive(Debug)]
pub enum SpecialPermission {
    SUID,
    SGID,
    StickyBit,
    Nil,
}

use crate::perm::SpecialPermission::*;

#[derive(Debug)]
pub struct FilePermission {
    user: Permission,
    group: Permission,
    other: Permission,
    filetype: String,
    special: [SpecialPermission; 3],
}

#[allow(dead_code)]
impl FilePermission {
    pub fn to_symbolic_string(&self) -> String {
        return [&self.user, &self.group, &self.other]
            .iter()
            .zip(SPECIAL_CHARS.iter())
            .map(|(perm, special_char)| perm.to_string(special_char))
            .collect::<Vec<String>>()
            .join("");
    }
}

impl FromStr for FilePermission {
    type Err = String;

    fn from_str(permission: &str) -> Result<Self, Self::Err> {
        if Symbolic::is_valid(permission) {}

        return Err(String::new());
    }
}

impl From<Symbolic> for FilePermission {
    fn from(symbolic_perm: Symbolic) -> Self {
        let [user, group, other]: [Permission; 3] =
            [symbolic_perm.user, symbolic_perm.group, symbolic_perm.other]
                .iter()
                .map(|perm_bits| Permission::from_symbolic_bits(&perm_bits).unwrap())
                .collect::<Vec<Permission>>()
                .try_into()
                .unwrap();

        let special_perms: [SpecialPermission; 3] = [&user, &group, &other]
            .iter()
            .zip([SUID, SGID, StickyBit])
            .map(|(perm, special_perm)| if perm.special { special_perm } else { Nil })
            .collect::<Vec<SpecialPermission>>()
            .try_into()
            .unwrap();

        FilePermission {
            user,
            group,
            other,
            special: special_perms,
            filetype: get_filetype_from_char(symbolic_perm.filetype),
        }
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct Permission {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    pub special: bool,
}

#[allow(dead_code)]
impl Permission {
    pub fn from_symbolic_bits(bits: &str) -> Result<Self, String> {
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

    pub fn from_octal_digit(digit: u8, is_special: bool) -> Result<Self, String> {
        let [read, write, execute] = parse_octal_digit(digit);
        return Ok(Permission {
            read,
            write,
            execute,
            special: is_special,
        });
    }

    pub fn to_string(&self, special_char: &char) -> String {
        let mut permission = String::new();

        permission.push(if self.read { 'r' } else { '-' });
        permission.push(if self.write { 'w' } else { '-' });

        if self.special {
            permission.push(if self.execute {
                special_char.clone()
            } else {
                special_char.to_uppercase().next().unwrap()
            });
        } else {
            permission.push(if self.execute { 'x' } else { '-' });
        }

        return permission;
    }
}
