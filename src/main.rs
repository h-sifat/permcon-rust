mod octal;
mod perm;
mod symbolic;
mod utils;

use crate::perm::FilePermission;
// use crate::utils::parse_octal_digit;

#[allow(unused)]

fn main() {
    let perm1 = FilePermission::try_from("crwxrwSr-t").unwrap();
    let perm2 = FilePermission::try_from("6755").unwrap();

    // println!("{:#?}", perm1);
    // println!("{:#?}", perm2);
    println!(
        "{}, {}, {}, {}",
        perm1.to_symbolic_str(),
        perm2.to_symbolic_str(),
        perm1.to_octal_str(),
        perm2.to_octal_str()
    );

    println!("json: {}", serde_json::to_string(&perm1).unwrap())
}
