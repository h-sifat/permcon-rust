use crate::{
    octal::Octal,
    symbolic::Symbolic,
    utils::{
        bool_arr_to_octal_digit, get_filetype_from_char, parse_octal_digit,
        parse_symbolic_execution_bit,
    },
};
use serde::{Serialize, Serializer};
use serde_json::{json, to_string_pretty};
use std::str::FromStr;

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

/// Represents the source notation (symbolic or octal) from which the FilePermission has been
/// parsed.
#[derive(Debug, PartialEq, Serialize)]
pub enum SourceFormat {
    Octal,
    Symbolic,
}

/// Represents a parsed file permission and provides methods to convert the
/// file permission to different notations.
#[derive(Debug, Serialize, PartialEq)]
pub struct FilePermission {
    pub user: GroupPermission,
    pub group: GroupPermission,
    pub other: GroupPermission,

    pub filetype: String,

    #[serde(skip_serializing)]
    pub filetype_char: char,

    #[serde(skip_serializing)]
    pub source_format: Option<SourceFormat>,

    #[serde(serialize_with = "serialize_special_permissions")]
    pub special: [SpecialPermission; 3],
}

impl FilePermission {
    /// Serializes the `FilePermission` into symbolic notation.
    pub fn to_symbolic_str(&self) -> String {
        self.filetype_char.to_string() + self.to_symbolic_bits_arr().join("").as_str()
    }

    /// Returns symbolic bin_str (e.g., `rwx`) (`[String; 3]`) array.
    pub fn to_symbolic_bits_arr(&self) -> [String; 3] {
        [&self.user, &self.group, &self.other]
            .iter()
            .zip(SPECIAL_CHARS.iter())
            .map(|(perm, special_char)| perm.to_symbolic_str(special_char))
            .collect::<Vec<String>>()
            .try_into()
            .unwrap()
    }

    /// Serializes the `FilePermission` into octal notation.
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

    /// Returns `[&GroupPermission; 3]` as `[user, group, other]`
    pub fn to_perm_group_array(&self) -> [&GroupPermission; 3] {
        [&self.user, &self.group, &self.other]
    }

    /// Returns a serialized JSON string. If `pretty` is `true` then beautifies
    /// the JSON string.
    pub fn to_json(&self, pretty: bool) -> String {
        let perm_json = json!(&self);

        if pretty {
            return to_string_pretty(&perm_json).unwrap();
        }

        perm_json.to_string()
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
        let perm_group_array: [GroupPermission; 3] =
            [symbolic_perm.user, symbolic_perm.group, symbolic_perm.other]
                .map(|perm_bits| GroupPermission::from_symbolic_bits(&perm_bits).unwrap());

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

        let [user, group, other]: [GroupPermission; 3] =
            [octal_perm.user, octal_perm.group, octal_perm.other]
                .iter()
                .zip(special_perms)
                .map(|(digit, is_special)| {
                    GroupPermission::from_octal_digit(*digit, is_special).unwrap()
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

/// Represents a parsed group (user, group and other) permission.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct GroupPermission {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    #[serde(skip_serializing)]
    pub special: bool,
}

impl GroupPermission {
    /// Tries to parse symbolic_bits (e.g., `rwx`) into `GroupPermission`.
    /// <br>
    /// ## Example
    /// ```rust
    /// use permcon::perm::GroupPermission;
    ///
    /// let bits = "r-t";
    /// assert_eq!(
    ///     GroupPermission::from_symbolic_bits(bits).unwrap(),
    ///     GroupPermission {
    ///         read: true,
    ///         write: false,
    ///         execute: true,
    ///         special: true,
    ///     }
    /// );
    /// ```
    pub fn from_symbolic_bits(bits: &str) -> Result<Self, String> {
        let chars: Vec<char> = bits.chars().collect();

        match chars[..] {
            [r, w, x] => {
                let (execute, special) = parse_symbolic_execution_bit(x);

                return Ok(GroupPermission {
                    execute,
                    special,
                    read: r == 'r',
                    write: w == 'w',
                });
            }
            _ => return Err(String::from("Invalid permission bits length!")),
        }
    }

    /// Tries to parse an octal digit into a `GroupPermission`.
    /// <br>
    /// ## Example
    ///
    /// ```rust
    /// use permcon::perm::GroupPermission;
    ///
    /// assert_eq!(
    ///     GroupPermission::from_octal_digit(5u8, false).unwrap(),
    ///     GroupPermission {
    ///         read: true,
    ///         write: false,
    ///         execute: true,
    ///         special: false,
    ///     }
    /// );
    /// ```
    pub fn from_octal_digit(digit: u8, is_special: bool) -> Result<Self, String> {
        let [read, write, execute] = parse_octal_digit(digit).unwrap();

        Ok(GroupPermission {
            read,
            write,
            execute,
            special: is_special,
        })
    }

    /// Returns a symbolic  triplet (e.g., `rwx`) representing the GroupPermission;
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

    /// Returns an octal digit representing the `GroupPermission`.
    pub fn to_octal_digit(&self) -> u8 {
        bool_arr_to_octal_digit(&self.as_rwx_array())
    }

    /// Returns `[read, write, execute]` as `[bool; 3]`.
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
