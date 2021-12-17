use std::env;

use log4j_interpreter::Findings;

fn main() {
    let args = env::args().collect::<Vec<_>>();
    if args.len() > 1 {
        match log4j_interpreter::parse_str(args.get(1).unwrap(), usize::MAX) {
            Ok((substituted, findings)) => {
                let Findings {
                    saw_jndi,
                    saw_env,
                    hit_recursion_limit,
                    ..
                } = findings;
                println!(
                    "Substituted: {}\nJNDI: {}\nENV: {}\nRecursion Limit: {}",
                    substituted, saw_jndi, saw_env, hit_recursion_limit
                );
            }
            Err(error) => {
                eprintln!("Error: {:?}", error);
            }
        }
    } else {
        eprintln!(
            "Usage: {} [test string]",
            args.get(0).unwrap_or(&"log4j_interpreter".into())
        );
    }
}
