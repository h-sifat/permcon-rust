#[allow(unused)]
use lazy_static::lazy_static;
use regex::Regex;

const OCTAL_PATTERN_GROUPS: [&str; 4] = ["special", "user", "group", "other"];
pub const SYMBOLIC_PATTERN_GROUPS: [&str; 4] = ["filetype", "user", "group", "other"];

lazy_static! {
    pub static ref OCTAL_PATTERN: Regex =
        Regex::new(r"(?x)^(?P<special>[0-7])?(?P<user>[0-7])(?P<group>[0-7])(?P<other>[0-7])$")
            .unwrap();

    pub static ref SYMBOLIC_PATTERN: Regex = Regex::new(
        r"(?x)^ (?P<filetype>[bcdlps-])? (?P<user>[r-][w-][xsS-]) (?P<group>[r-][w-][xsS-]) (?P<other>[r-][w-][xtT-])$"
    )
    .unwrap();
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct Symbolic {
    filetype: String,
    user: String,
    group: String,
    other: String,
}

impl Symbolic {
    pub fn from_str(permission: &str) -> Result<Self, String> {
        if !SYMBOLIC_PATTERN.is_match(permission) {
            return Err(String::from("Invalid symbolic permission."));
        }

        let caps = SYMBOLIC_PATTERN.captures(permission).unwrap();

        let values = SYMBOLIC_PATTERN_GROUPS
            .map(|group_name| caps.name(group_name).map_or("-", |val| val.as_str()))
            .map(|val| String::from(val));

        Ok(Symbolic::from_array(values))
    }

    pub fn from_array(values: [String; 4]) -> Self {
        let [filetype, user, group, other] = values;

        Symbolic {
            filetype,
            user,
            group,
            other,
        }
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct Octal {
    special: u8,
    user: u8,
    group: u8,
    other: u8,
}

impl Octal {
    pub fn from_array(values: [u8; 4]) -> Self {
        let [special, user, group, other] = values;

        Octal {
            special,
            user,
            group,
            other,
        }
    }

    pub fn from_str(permission: &str) -> Result<Self, String> {
        if !OCTAL_PATTERN.is_match(permission) {
            return Err(String::from("Invalid octal permission."));
        }

        let caps = OCTAL_PATTERN.captures(permission).unwrap();

        let values = OCTAL_PATTERN_GROUPS.map(|group_name| {
            caps.name(group_name)
                .map_or(0, |val| val.as_str().parse::<u8>().unwrap())
        });

        Ok(Octal::from_array(values))
    }
}
