use leef2hashmap::LeefToHashMap;

fn main() {
    let examples = include_str!("examples.txt").trim();
    for (i, eg) in examples.lines().enumerate() {
        println!("--- Example Line #{} ---", i + 1);
        println!("{:#?}", eg.to_hashmap(true));
        println!();
    }
}
