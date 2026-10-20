// The storage layer lands before its callers; remove this allow once Unseal/Sign are wired up.
#[allow(dead_code, unused_imports)]
mod storage;

fn main() {
    println!("Hello, world!");
}
