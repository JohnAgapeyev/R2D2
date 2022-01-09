use r2d2::*;

#[obfuscate]
fn main() {
    println!("Hello, world!");
    let x = "foobar";
    println!("{}", x);
    println!("String formatting {}", "Inner String");
    println!("{} is {number:.prec$}", "x", prec=5, number=0.01)
}
