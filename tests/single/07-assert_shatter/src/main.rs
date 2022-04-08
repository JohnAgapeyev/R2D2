fn main() {
    let x = 7;
    println!("X is {x}");
    assert!(x == 7);
    println!("After assert 1");
    assert!(x == 7, "I don't really trust that it's actually 7");
    println!("After assert 2");
    assert_eq!(x, 7);
    println!("After assert 3");
    assert_eq!(x, 7, "But now with a fancy message");
    println!("After assert 4");
    assert_ne!(x, 8);
    println!("After assert 5");
    assert_ne!(x, 8, "I do love {} messages", "fancy");
    println!("After assert 6");
    debug_assert!(x == 7);
    println!("After assert 7");
    debug_assert!(x == 7, "I don't really trust that it's actually 7");
    println!("After assert 8");
    debug_assert_eq!(x, 7);
    println!("After assert 9");
    debug_assert_eq!(x, 7, "But now with a fancy message");
    println!("After assert 10");
    debug_assert_ne!(x, 8);
    println!("After assert 11");
    debug_assert_ne!(x, 8, "I do love {} messages", "fancy");
    println!("After assert 12");
}
