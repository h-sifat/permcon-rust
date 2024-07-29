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
const SPECIAL_PERMISSIONS_ORDER: [SpecialPermission; 3] = [SUID, SGID, StickyBit];

#[derive(Debug, PartialEq, Serialize, Clone)]
pub enum SpecialPermission {
    Nil,
    SGID,
    SUID,
    StickyBit,
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
    pub filetype_char: char,

    #[serde(skip_serializing)]
    pub source_format: Option<SourceFormat>,

    #[serde(serialize_with = "serialize_special_permissions")]
    pub special: [SpecialPermission; 3],
}

#[allow(dead_code)]
impl FilePermission {
    pub fn to_symbolic_str(&self) -> String {
        self.filetype_char.to_string() + self.to_symbolic_bits_arr().join("").as_str()
    }

    pub fn to_symbolic_bits_arr(&self) -> [String; 3] {
        [&self.user, &self.group, &self.other]
            .iter()
            .zip(SPECIAL_CHARS.iter())
            .map(|(perm, special_char)| perm.to_symbolic_str(special_char))
            .collect::<Vec<String>>()
            .try_into()
            .unwrap()
    }

    pub fn to_octal_str(&self) -> String {
        let special_digit = {
            let special: &[bool; 3] = &self.special.clone().map(|val| (val != Nil));
            bool_arr_to_octal_digit(special).to_string()
        };

        let group_digits = [&self.user, &self.group, &self.other]
            .map(|perm| perm.to_octal_digit().to_string())
            .join("");

        special_digit + &group_digits
    }

    pub fn to_perm_group_array(&self) -> [&Permission; 3] {
        [&self.user, &self.group, &self.other]
    }
}

fn get_special_perms_array<T, U>(source_array: &[T; 3], is_special: U) -> [SpecialPermission; 3]
where
    U: Fn(&T) -> bool,
{
    source_array
        .iter()
        .zip(SPECIAL_PERMISSIONS_ORDER)
        .map(|(source_val, perm)| if is_special(source_val) { perm } else { Nil })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

impl From<Symbolic> for FilePermission {
    fn from(symbolic_perm: Symbolic) -> Self {
        let perm_group_array: [Permission; 3] =
            [symbolic_perm.user, symbolic_perm.group, symbolic_perm.other]
                .map(|perm_bits| Permission::from_symbolic_bits(&perm_bits).unwrap());

        let special_perms = get_special_perms_array(&perm_group_array, |perm| perm.special);
        let [user, group, other] = perm_group_array;

        FilePermission {
            user,
            group,
            other,
            special: special_perms,
            filetype_char: symbolic_perm.filetype,
            source_format: Some(SourceFormat::Symbolic),
            filetype: get_filetype_from_char(symbolic_perm.filetype),
        }
    }
}

impl From<Octal> for FilePermission {
    fn from(octal_perm: Octal) -> Self {
        let special_perms = parse_octal_digit(octal_perm.special).unwrap();

        let [user, group, other]: [Permission; 3] =
            [octal_perm.user, octal_perm.group, octal_perm.other]
                .iter()
                .zip(special_perms)
                .map(|(digit, is_special)| {
                    Permission::from_octal_digit(*digit, is_special).unwrap()
                })
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();

        let special_perms = get_special_perms_array(&special_perms, |is_special| *is_special);

        FilePermission {
            user,
            group,
            other,
            filetype_char: '-',
            special: special_perms,
            filetype: get_filetype_from_char('0'),
            source_format: Some(SourceFormat::Octal),
        }
    }
}

impl TryFrom<&str> for FilePermission {
    type Error = String;

    fn try_from(perm_str: &str) -> Result<Self, Self::Error> {
        if let Ok(symbolic) = Symbolic::from_str(perm_str) {
            return Ok(FilePermission::from(symbolic));
        }

        if let Ok(octal) = Octal::from_str(perm_str) {
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
        let [read, write, execute] = parse_octal_digit(digit).unwrap();

        Ok(Permission {
            read,
            write,
            execute,
            special: is_special,
        })
    }

    pub fn to_symbolic_str(&self, special_char: &char) -> String {
        let mut permission: String = ['r', 'w', 'x']
            .into_iter()
            .zip(self.as_rwx_array())
            .map(|(char, is_present)| if is_present { char } else { '-' })
            .collect();

        if !self.special {
            return permission;
        }

        let mut x = *special_char;
        if !self.execute {
            x = special_char.to_ascii_uppercase()
        }

        permission.pop();
        permission.push(x);

        permission
    }

    pub fn to_octal_digit(&self) -> u8 {
        bool_arr_to_octal_digit(&self.as_rwx_array())
    }

    pub fn as_rwx_array(&self) -> [bool; 3] {
        [self.read, self.write, self.execute]
    }
}

// ---------- Util to serialize FilePermission::special field -------------
fn serialize_special_permissions<S>(
    perms: &[SpecialPermission; 3],
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

    let is_set = |value: &SpecialPermission| value == &SpecialPermission::Nil;

    let special_permissions = SerializedSpecialPermissions {
        suid: is_set(&perms[0]),
        sgid: is_set(&perms[1]),
        sticky_bit: is_set(&perms[2]),
    };

    special_permissions.serialize(serializer)
}
