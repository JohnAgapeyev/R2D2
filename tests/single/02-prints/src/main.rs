use r2d2::*;

fn main() {
    println!("Hello, world!");
    let x = "foobar";
    println!("{}", x);
    println!("String formatting {}", "Inner String");
    println!("{} is {number:.prec$}", "x", prec=5, number=0.01);

    let x = {
        let mut _y = 5;
        _y += 7;
        "foobar"
    };
    println!("{}", x);

    println!("Real reference random number {}", r2d2::rand::rngs::OsRng.next_u32());
    println!("Byte string literal {:?}", b"Fancy byte string literal");
    println!("Raw string literal {}", r#"Lame raw string literal"#);
    println!("Complicated string literal {:?}", br#"Lame raw string literal"#);
}
