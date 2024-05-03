#[allow(unused)]
use lazy_static::lazy_static;
use regex::Regex;

const OCTAL_PATTERN_GROUPS: [&str; 4] = ["special", "user", "group", "other"];

lazy_static! {
    pub static ref OCTAL_PATTERN: Regex =
        Regex::new(r"(?x)^(?P<special>[0-7])?(?P<user>[0-7])(?P<group>[0-7])(?P<other>[0-7])$")
            .unwrap();
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct Octal {
    pub special: u8,
    pub user: u8,
    pub group: u8,
    pub other: u8,
}

#[allow(dead_code)]
impl Octal {
    pub fn from_array(values: [u8; 4]) -> Self {
        let [special, user, group, other] = values;

        Octal {
            user,
            group,
            other,
            special,
        }
    }

    pub fn is_valid(permission: &str) -> bool {
        return OCTAL_PATTERN.is_match(permission);
    }

    pub fn from_str(permission: &str) -> Result<Self, String> {
        if !Self::is_valid(permission) {
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
