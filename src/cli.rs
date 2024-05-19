use clap::Parser;
use serde_json::{json, to_string_pretty};
use yansi::Paint;

use crate::perm::{FilePermission, Permission, SourceFormat, SpecialPermission};

/// A CLI to parse Linux file system permissions and convert them
/// between symbolic and octal formats.
#[derive(Debug, Parser)]
#[command(version)]
struct Cli {
    /// The permission string, either octal or symbolic
    permission: String,

    /// Print detailed analysis
    #[arg(short, long, conflicts_with = "json")]
    analyze: bool,

    /// Don't use ascii color codes, just print raw text
    #[arg(short, long, requires = "analyze")]
    no_color: bool,

    /// Print parsed result in JSON format
    #[arg(short, long)]
    json: bool,

    /// Beautify JSON
    #[arg(short, long, requires = "json")]
    pretty: bool,
}

pub fn run_cli() {
    let cli = Cli::parse();

    let permission = FilePermission::try_from(cli.permission.as_str());

    match permission {
        Ok(permission) => {
            // print json
            if cli.json {
                let perm_json = json!(&permission);

                let json_str = if cli.pretty {
                    to_string_pretty(&perm_json).unwrap()
                } else {
                    perm_json.to_string()
                };

                println!("{}", json_str);
                return;
            }

            // convert to the other format
            if !cli.analyze {
                if permission.source_format.as_ref().unwrap() == &SourceFormat::Octal {
                    println!("{}", permission.to_symbolic_str())
                } else {
                    println!("{}", permission.to_octal_str())
                }

                return;
            }

            // disable color if no_color flag is provided
            if cli.no_color {
                yansi::disable()
            }

            let [user_bits, group_bits, other_bits] = permission.to_symbolic_bits_arr();
            let [user_digit, group_digit, other_digit] = [
                permission.user.to_octal_str(),
                permission.group.to_octal_str(),
                permission.other.to_octal_str(),
            ];
            let [suid, sgid, sticky_bit] = &permission.special;

            println!("file type    : {}", permission.filetype);
            println!("symbolic     : {}", permission.to_symbolic_str().green());
            println!("octal        : {}", permission.to_octal_str().yellow());
            println!("------------------------");
            println!(
                "{}{}, {}{}: {}",
                "user (".green(),
                user_bits,
                user_digit,
                ")".green(),
                get_perm_description(&permission.user, suid),
            );
            println!(
                "{}{}, {}{}: {}",
                "group(".cyan(),
                group_bits,
                group_digit,
                ")".cyan(),
                get_perm_description(&permission.group, sgid),
            );
            println!(
                "{}{}, {}{}: {}",
                "other(".yellow(),
                other_bits,
                other_digit,
                ")".yellow(),
                get_perm_description(&permission.other, sticky_bit),
            );
            println!("------------------------");

            let special_perm_str = permission
                .special
                .clone()
                .iter()
                .filter(|perm| **perm != SpecialPermission::Nil)
                .map(|perm| serde_json::to_string(perm).unwrap())
                .map(|str| str.trim_matches('"').to_string())
                .collect::<Vec<String>>()
                .join(", ");

            println!("{}: {}", "special permissions".green(), special_perm_str)
        }
        Err(message) => {
            eprintln!("{}", message);
            std::process::exit(1);
        }
    }
}

fn get_perm_description(perm: &Permission, special: &SpecialPermission) -> String {
    let mut desc = String::new();
    if perm.read {
        desc.push_str("read")
    }

    if perm.write {
        desc.push_str(", write")
    }

    let special_str = if *special != SpecialPermission::Nil {
        let str = serde_json::to_string(&special).unwrap();
        str.trim_matches('"').to_string()
    } else {
        String::new()
    };

    if perm.execute {
        if !special_str.is_empty() {
            desc.push_str(format!(", (execute, {})", special_str.as_str()).as_str());
        } else {
            desc.push_str(", execute");
        }
    } else if !special_str.is_empty() {
        desc.push_str(format!(", (_, {})", special_str.as_str()).as_str());
    }

    return desc;
}
