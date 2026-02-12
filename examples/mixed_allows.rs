#[allow(dead_code)]
fn never_called() -> u64 {
    0xDEAD
}

#[allow(dead_code)]
struct Phantom {
    secret: i32,
}

#[allow(unused_variables)]
fn ignore_param(unused_param: i32) -> &'static str {
    "I don't care about the argument"
}

#[allow(non_snake_case)]
fn NotSnakeCase() -> bool {
    true
}

#[allow(unused_mut)]
fn unnecessary_mut() -> Vec<i32> {
    let mut v = vec![1, 2, 3];
    v
}

#[allow(clippy::needless_return)]
fn explicit_return(x: i32) -> i32 {
    return x + 1;
}

#[allow(unused_imports)]
use std::fmt::Debug;

#[allow(dead_code)]
fn actually_called() -> i32 {
    100
}

#[allow(unused_variables)]
fn all_used(a: i32, b: i32) -> i32 {
    a + b
}

#[allow(non_snake_case)]
fn already_snake() -> &'static str {
    "perfectly fine name"
}

#[allow(unreachable_code)]
fn fully_reachable(n: i32) -> i32 {
    if n > 0 { n } else { -n }
}

#[allow(clippy::needless_return)]
fn no_explicit_return(x: i32) -> i32 {
    x * 3
}

#[allow(unused_imports)]
use std::collections::HashMap;

fn main() {
    println!("ignore_param: {}", ignore_param(999));
    println!("NotSnakeCase: {}", NotSnakeCase());
    println!("unnecessary_mut: {:?}", unnecessary_mut());
    println!("explicit_return: {}", explicit_return(41));

    println!("actually_called: {}", actually_called());
    println!("all_used: {}", all_used(3, 4));
    println!("already_snake: {}", already_snake());
    println!("fully_reachable: {}", fully_reachable(-5));
    println!("no_explicit_return: {}", no_explicit_return(7));

    let mut map = HashMap::<&str, i32>::new();
    map.insert("value", 42);
    println!("map: {map:?}");
}
