macro_rules! define_fn {
    ($name:ident) => {
        #[allow(dead_code)]
        fn $name() -> i32 {
            42
        }
    };
}

macro_rules! define_fn_with_param {
    ($name:ident) => {
        #[allow(dead_code, unused_variables)]
        fn $name(x: i32) -> &'static str {
            "I might not use x"
        }
    };
}

define_fn!(used_fn);
define_fn!(unused_fn);

define_fn_with_param!(called_with_param);
define_fn_with_param!(not_called_with_param);

#[allow(dead_code)]
fn actually_called() -> i32 {
    100
}

#[allow(unused_variables)]
fn all_vars_used(a: i32, b: i32) -> i32 {
    a + b
}

fn main() {
    println!("used_fn: {}", used_fn());
    println!("called_with_param: {}", called_with_param(99));
    println!("actually_called: {}", actually_called());
    println!("all_vars_used: {}", all_vars_used(1, 2));
}
