mod to_map;
pub use to_map::LeefToHashMap;

#[cfg(test)]
mod tests;

mod error;
pub use error::Error;
pub type Result<T> = std::result::Result<T, error::Error>;
