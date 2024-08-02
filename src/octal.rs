#[allow(unused)]
use lazy_static::lazy_static;
use regex::Regex;

const OCTAL_PATTERN_GROUPS: [&str; 4] = ["special", "user", "group", "other"];

lazy_static! {
    /// A pattern to parse file permission in octal (1666) notation.
    ///
    /// `pattern = r"(?x)^(?P<special>[0-7])?(?P<user>[0-7])(?P<group>[0-7])(?P<other>[0-7])$"`
    pub static ref OCTAL_PATTERN: Regex =
        Regex::new(r"(?x)^(?P<special>[0-7])?(?P<user>[0-7])(?P<group>[0-7])(?P<other>[0-7])$")
            .unwrap();
}

/// Represents a parsed octal permission.
///
/// ``` rust
/// use permcon::octal::Octal;
///
/// let perm = "1641";
///
/// assert!(Octal::is_valid(perm));
/// assert_eq!(Octal::from_str(perm).unwrap(), Octal {
///     special: 1,
///     user: 6,
///     group: 4,
///     other: 1,
/// });
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct Octal {
    pub special: u8,
    pub user: u8,
    pub group: u8,
    pub other: u8,
}

impl Octal {
    /// Checks whether the given permission string is a valid permission in the
    /// octal notation.
    pub fn is_valid(permission: &str) -> bool {
        return OCTAL_PATTERN.is_match(permission);
    }

    /// Tries to parse the permission string into the Octal struct
    pub fn from_str(permission: &str) -> Result<Self, String> {
        if !Self::is_valid(permission) {
            return Err(String::from("Invalid octal permission."));
        }

        let caps = OCTAL_PATTERN.captures(permission).expect(
            "The permission must be valid as we've already checked with the is_valid method.",
        );

        let [special, user, group, other] = OCTAL_PATTERN_GROUPS.map(|group_name| {
            caps.name(group_name)
                .map_or(0, |val| val.as_str().parse::<u8>().unwrap())
        });

        Ok(Octal {
            user,
            group,
            other,
            special,
        })
    }
}
