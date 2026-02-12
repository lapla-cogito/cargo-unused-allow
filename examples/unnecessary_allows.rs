#[allow(dead_code)]
fn actually_used() -> i32 {
    42
}

#[allow(unused_variables)]
fn all_vars_used(x: i32, y: i32) -> i32 {
    x + y
}

#[allow(unused_imports)]
use std::collections::HashMap;

#[allow(non_snake_case)]
fn properly_snake_case() -> bool {
    true
}

#[allow(unused_mut)]
fn mutation_happens() -> Vec<i32> {
    let mut v = Vec::new();
    v.push(1);
    v.push(2);
    v
}

#[allow(unreachable_code)]
fn totally_reachable(flag: bool) -> &'static str {
    if flag { "yes" } else { "no" }
}

#[allow(clippy::needless_return)]
fn clean_return(x: i32) -> i32 {
    x * 2
}

#[allow(dead_code, unused_variables)]
fn also_used(a: i32) -> i32 {
    a
}

fn main() {
    let mut map = HashMap::<&str, i32>::new();
    map.insert("answer", actually_used());
    map.insert("sum", all_vars_used(1, 2));

    println!("snake: {}", properly_snake_case());
    println!("vec: {:?}", mutation_happens());
    println!("reachable: {}", totally_reachable(true));
    println!("clean: {}", clean_return(21));
    println!("also: {}", also_used(7));
    println!("map: {map:?}");

    #[allow(clippy::big_endian_bytes)]
    let _x = 42;
}
