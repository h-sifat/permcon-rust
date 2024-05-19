use std::str::FromStr;

use crate::{
    octal::Octal,
    symbolic::Symbolic,
    utils::{
        bool_arr_to_octal_digit, get_filetype_from_char, parse_octal_digit,
        parse_symbolic_execution_bit,
    },
};

use serde::{Serialize, Serializer};

const SPECIAL_CHARS: [char; 3] = ['s', 's', 't'];

#[derive(Debug, PartialEq, Serialize, Clone)]
pub enum SpecialPermission {
    SUID,
    SGID,
    StickyBit,
    Nil,
}

use crate::perm::SpecialPermission::*;

#[derive(Debug, PartialEq, Serialize)]
pub enum SourceFormat {
    Octal,
    Symbolic,
}

#[derive(Debug, Serialize)]
pub struct FilePermission {
    pub user: Permission,
    pub group: Permission,
    pub other: Permission,

    pub filetype: String,
    #[serde(skip_serializing)]
    pub source_format: Option<SourceFormat>,

    #[serde(serialize_with = "serialize_special_permissions")]
    pub special: [SpecialPermission; 3],
}

#[allow(dead_code)]
impl FilePermission {
    pub fn to_symbolic_str(&self) -> String {
        return self.to_symbolic_bits_arr().join("");
    }

    pub fn to_symbolic_bits_arr(&self) -> [String; 3] {
        return [&self.user, &self.group, &self.other]
            .iter()
            .zip(SPECIAL_CHARS.iter())
            .map(|(perm, special_char)| perm.to_symbolic_str(special_char))
            .collect::<Vec<String>>()
            .try_into()
            .unwrap();
    }

    pub fn to_octal_str(&self) -> String {
        let special_digit = {
            let special: [bool; 3] = self
                .special
                .iter()
                .map(|val| (*val != Nil))
                .collect::<Vec<bool>>()
                .try_into()
                .unwrap();

            bool_arr_to_octal_digit(special).to_string()
        };

        let group_digits = [&self.user, &self.group, &self.other]
            .map(|perm| perm.to_octal_str().to_string())
            .join("");

        special_digit + &group_digits
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
            source_format: Some(SourceFormat::Symbolic),
            filetype: get_filetype_from_char(symbolic_perm.filetype),
        }
    }
}

impl From<Octal> for FilePermission {
    fn from(octal_perm: Octal) -> Self {
        let special_perms = parse_octal_digit(octal_perm.special);

        let [user, group, other]: [Permission; 3] =
            [octal_perm.user, octal_perm.group, octal_perm.other]
                .iter()
                .zip(special_perms.iter())
                .map(|(digit, is_special)| {
                    Permission::from_octal_digit(*digit, *is_special).unwrap()
                })
                .collect::<Vec<Permission>>()
                .try_into()
                .unwrap();

        let special_perms: [SpecialPermission; 3] = special_perms
            .iter()
            .zip([SUID, SGID, StickyBit])
            .map(|(is_special, perm)| if *is_special { perm } else { Nil })
            .collect::<Vec<SpecialPermission>>()
            .try_into()
            .unwrap();

        FilePermission {
            user,
            group,
            other,
            special: special_perms,
            filetype: get_filetype_from_char('0'),
            source_format: Some(SourceFormat::Octal),
        }
    }
}

impl TryFrom<&str> for FilePermission {
    type Error = String;

    fn try_from(perm_str: &str) -> Result<Self, Self::Error> {
        if Symbolic::is_valid(perm_str) {
            let symbolic = Symbolic::from_str(perm_str).unwrap();
            return Ok(FilePermission::from(symbolic));
        }

        if Octal::is_valid(perm_str) {
            let octal = Octal::from_str(perm_str).unwrap();
            return Ok(FilePermission::from(octal));
        }

        return Err(format!("Invalid file permission: {perm_str}!"));
    }
}

#[derive(Debug, Serialize)]
#[allow(dead_code)]
pub struct Permission {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    #[serde(skip_serializing)]
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

    pub fn to_symbolic_str(&self, special_char: &char) -> String {
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

    pub fn to_octal_str(&self) -> u8 {
        bool_arr_to_octal_digit([self.read, self.write, self.execute])
    }
}

// ---------- Util to serialize FilePermission::special field -------------
fn serialize_special_permissions<S>(
    permissions: &[SpecialPermission; 3],
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    #[derive(Serialize)]
    struct SerializedSpecialPermissions {
        suid: bool,
        sgid: bool,
        sticky_bit: bool,
    }

    let [suid, sgid, sticky_bit]: [bool; 3] = permissions
        .iter()
        .map(|perm| *perm != SpecialPermission::Nil)
        .collect::<Vec<bool>>()
        .try_into()
        .unwrap();

    let special_permissions = SerializedSpecialPermissions {
        suid,
        sgid,
        sticky_bit,
    };

    special_permissions.serialize(serializer)
}
