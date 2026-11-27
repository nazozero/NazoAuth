use std::io::{Read, stdin};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut challenge = String::new();
    stdin().read_to_string(&mut challenge)?;
    let solution = spow::pow::Pow::work(challenge.trim())?;
    println!("{solution}");
    Ok(())
}
