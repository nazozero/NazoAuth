//! Database configuration normalization.

pub fn normalize_database_url(url: &str) -> String {
    url.replace("postgresql+psycopg://", "postgresql://")
}
