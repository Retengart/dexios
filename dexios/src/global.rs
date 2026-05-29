pub(crate) mod parameters;
pub(crate) mod states;
pub(crate) mod structs;

#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {
        println!("[i] {}", format!($($arg)*))
    }
}

#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {
        println!("[!] {}", format!($($arg)*))
    }
}

#[macro_export]
macro_rules! success {
    ($($arg:tt)*) => {
        println!("[+] {}", format!($($arg)*))
    }
}

#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => {
        eprintln!("[-] {}", format!($($arg)*))
    }
}

#[macro_export]
macro_rules! question {
    ($($arg:tt)*) => {
        print!("[?] {}", format!($($arg)*));

    }
}
