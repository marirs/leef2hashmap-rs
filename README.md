# LEEF to HashMap

Convert a syslog LEEF string or a regular LEEF string to a HashMap object.

### Requirements
- Rust 1.56+ (2021 edition)

### Example Usage

```toml
[dependencies]
leef2hashmap = "0.1.3"
```

and then

```rust
use leef2hashmap::LeefToHashMap;

fn main() {
    let example = "<134>2022-02-14T03:17:30-08:00 2001:db8:3333:4444:5555:6666:7777:8888 Jan 18 11:07:53 198.76.5.4 LEEF:1.0|VMware Carbon_Black|App Control|8.6.0.155|NEW_PORT_DISCOVERD|<tab>|src=172.5.6.67<tab>dst=172.50.123.1<tab>sev=5<tab>cat=anomaly<tab>msg=there are spaces in this message";
    println!("{:#?}", example.to_hashmap(true));
}
```
- pass `false` to `.to_hashmap(false)` if you don't want to preserve the original event

---
License: MIT
