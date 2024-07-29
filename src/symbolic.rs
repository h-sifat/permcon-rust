use lazy_static::lazy_static;
use regex::Regex;
use std::str::FromStr;

const SYMBOLIC_PATTERN_GROUPS: [&str; 4] = ["filetype", "user", "group", "other"];

lazy_static! {
    pub static ref SYMBOLIC_PATTERN: Regex = Regex::new(
        r"(?x)^ (?P<filetype>[bcdlps-])? (?P<user>[r-][w-][xsS-]) (?P<group>[r-][w-][xsS-]) (?P<other>[r-][w-][xtT-])$"
    )
    .unwrap();
}

#[derive(Debug)]
pub struct Symbolic {
    pub filetype: char,
    pub user: String,
    pub group: String,
    pub other: String,
}

#[allow(dead_code)]
impl Symbolic {
    /// Checks whether the given permission string is a valid permission in the
    /// symbolic notation.
    pub fn is_valid(permission: &str) -> bool {
        return SYMBOLIC_PATTERN.is_match(permission);
    }

    pub(crate) fn from_array(values: [String; 4]) -> Self {
        let [filetype, user, group, other] = values;

        Symbolic {
            user,
            group,
            other,
            filetype: filetype.chars().next().unwrap(),
        }
    }

    pub fn to_perm_struct() {}
}

impl FromStr for Symbolic {
    type Err = String;

    /// Tries to parse the permission string with symbolic format
    fn from_str(permission: &str) -> Result<Self, Self::Err> {
        if !Self::is_valid(permission) {
            return Err(String::from("Invalid symbolic permission."));
        }

        let caps = SYMBOLIC_PATTERN
            .captures(permission)
            .expect("The permission should be valid because of the previous check.");

        let values = SYMBOLIC_PATTERN_GROUPS
            .map(|group_name| caps.name(group_name).map_or("-", |val| val.as_str()))
            .map(|val| String::from(val));

        Ok(Symbolic::from_array(values))
    }
}
