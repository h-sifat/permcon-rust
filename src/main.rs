mod octal;
mod perm;
mod symbolic;
mod utils;

use crate::perm::FilePermission;
use std::str::FromStr;
use symbolic::Symbolic;
// use crate::utils::parse_octal_digit;

#[allow(unused)]

fn main() {
    let symbolic = Symbolic::from_str("crwxrwSr-t").unwrap();
    let perm = FilePermission::from(symbolic);

    println!("{:#?}", perm);
}
