#[allow(unused)]
use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    pub static ref OCTAL_PATTERN: Regex =
        Regex::new(r"(?x)^(?P<special>[0-7])?(?P<user>[0-7])(?P<group>[0-7])(?P<other>[0-7])$")
            .unwrap();
    pub static ref SYMBOLIC_PATTERN: Regex =
        Regex::new(r"^[bcdlps-]?[r-][w-][xsS-][r-][w-][xsS-][r-][w-][xtT-]$").unwrap();
}
