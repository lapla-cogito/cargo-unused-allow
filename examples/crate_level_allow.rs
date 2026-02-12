#![allow(non_camel_case_types)]
#![allow(unreachable_code)]
#![allow(unused_assignments)]

struct ProperlyNamed {
    value: i32,
}

fn always_reachable(flag: bool) -> &'static str {
    if flag { "yes" } else { "no" }
}

fn used_assignment() -> i32 {
    let mut x = 0;
    x += 10;
    x
}

fn main() {
    let s = ProperlyNamed { value: 42 };
    println!("value: {}", s.value);
    println!("reachable: {}", always_reachable(true));
    println!("assigned: {}", used_assignment());
}
