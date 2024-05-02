#[allow(unused)]
use permcon::OCTAL_PATTERN;

const PERMISSION_ORDER: [&str; 4] = ["special", "user", "group", "other"];

#[derive(Debug)]
struct Octal {
    special: u8,
    user: u8,
    group: u8,
    other: u8,
}

impl Octal {
    fn from_array(values: [u8; 4]) -> Self {
        let [special, user, group, other] = values;

        Octal {
            special,
            user,
            group,
            other,
        }
    }

    fn from_str(permission: &str) -> Result<Self, String> {
        if !OCTAL_PATTERN.is_match(permission) {
            return Err(String::from("Invalid octal permission."));
        }

        let caps = OCTAL_PATTERN.captures(permission).unwrap();

        let values = PERMISSION_ORDER.map(|group_name| {
            caps.name(group_name)
                .map_or(0, |val| val.as_str().parse::<u8>().unwrap())
        });

        Ok(Octal::from_array(values))
    }
}

fn main() {
    let perm = Octal::from_str("7666");

    println!("{:?}", perm);
}
