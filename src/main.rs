// The storage layer lands before its callers; remove this allow once Unseal/Sign are wired up.
#[allow(dead_code, unused_imports)]
mod storage;

#[allow(dead_code)]
mod unseal;

fn main() {
    println!("Hello, world!");
}
