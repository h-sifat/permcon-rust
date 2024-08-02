use lazy_static::lazy_static;
use regex::Regex;
use std::str::FromStr;

const SYMBOLIC_PATTERN_GROUPS: [&str; 4] = ["filetype", "user", "group", "other"];

lazy_static! {
    /// A regex pattern to parse symbolic (e.g., `drwxr-xr-x`) permission string.
    ///
    /// `pattern = r"(?x)^ (?P<filetype>[bcdlps-])? (?P<user>[r-][w-][xsS-]) (?P<group>[r-][w-][xsS-]) (?P<other>[r-][w-][xtT-])$"`
    pub static ref SYMBOLIC_PATTERN: Regex = Regex::new(
        r"(?x)^ (?P<filetype>[bcdlps-])? (?P<user>[r-][w-][xsS-]) (?P<group>[r-][w-][xsS-]) (?P<other>[r-][w-][xtT-])$"
    )
    .unwrap();
}

/// Represents a parsed symbolic permission.
/// <br>
/// ```rust
/// use std::str::FromStr;
/// use permcon::symbolic::Symbolic;
///
/// let perm = "drwxr-xr-x";
///
/// assert!(Symbolic::is_valid(perm));
///
/// let parsed = Symbolic::from_str(perm).unwrap();
/// assert_eq!(parsed, Symbolic {
///     filetype: 'd',
///     user: String::from("rwx"),
///     group: String::from("r-x"),
///     other: String::from("r-x"),
/// });
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct Symbolic {
    pub filetype: char,
    pub user: String,
    pub group: String,
    pub other: String,
}

impl Symbolic {
    /// Checks whether the given permission string is a valid permission in the
    /// symbolic notation.
    pub fn is_valid(permission: &str) -> bool {
        return SYMBOLIC_PATTERN.is_match(permission);
    }
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

        let [filetype, user, group, other] = values;

        Ok(Symbolic {
            user,
            group,
            other,
            filetype: filetype.chars().next().unwrap(),
        })
    }
}
