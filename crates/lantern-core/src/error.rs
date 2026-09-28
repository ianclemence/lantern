use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("storage budget exceeded: {0}")]
    BudgetExceeded(String),

    #[error("target outside of declared scope: {0}")]
    OutOfScope(String),

    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),

    #[error("io error at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("{0}")]
    Other(String),
}

impl CoreError {
    pub fn io(path: impl Into<String>, source: std::io::Error) -> Self {
        CoreError::Io {
            path: path.into(),
            source,
        }
    }
}

pub type Result<T> = std::result::Result<T, CoreError>;
