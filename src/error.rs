use std::fmt;

pub enum Error {
    NotLeef,
    MalformedLeef,
    Generic(String),
}

impl From<&str> for Error {
    fn from(err: &str) -> Error {
        Error::Generic(err.to_string())
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Generic(msg) => write!(f, "Generic Error: {}", msg)?,
            Error::NotLeef => write!(f, "Not a LEEF String")?,
            Error::MalformedLeef => write!(f, "Could be a malformed LEEF string")?,
        }
        Ok(())
    }
}
