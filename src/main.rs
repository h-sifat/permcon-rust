#[allow(unused)]
use permcon::Octal;
use permcon::Symbolic;

fn main() {
    let perm_str = "drwxrwxr-x";
    let _ = Symbolic::from_str(perm_str);
}
