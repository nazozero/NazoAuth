use diesel_async::{AsyncConnection as _, AsyncPgConnection, SimpleAsyncConnection as _};

/// Owns a test database and any cluster roles created exclusively for it.
/// The cleanup thread also works during unwinding inside an async test runtime.
#[allow(dead_code)]
pub struct OwnedDatabase {
    pub url: String,
    pub roles: Vec<String>,
    base: String,
}

#[allow(dead_code)]
impl OwnedDatabase {
    pub async fn new(base: &str) -> Self {
        Self {
            url: create(base).await,
            roles: Vec::new(),
            base: base.to_owned(),
        }
    }
}

impl Drop for OwnedDatabase {
    fn drop(&mut self) {
        let base = self.base.clone();
        let database = url::Url::parse(&self.url)
            .unwrap()
            .path()
            .trim_start_matches('/')
            .to_owned();
        let roles = std::mem::take(&mut self.roles);
        let cleanup = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let mut connection = AsyncPgConnection::establish(&base).await.unwrap();
                    connection
                        .batch_execute(&format!("DROP DATABASE \"{database}\" WITH (FORCE)"))
                        .await
                        .unwrap();
                    for role in roles {
                        let role = role.replace('"', "\"\"");
                        connection
                            .batch_execute(&format!("DROP ROLE IF EXISTS \"{role}\""))
                            .await
                            .unwrap();
                    }
                });
        })
        .join();
        if let Err(error) = cleanup {
            if std::thread::panicking() {
                eprintln!("test database cleanup failed while unwinding: {error:?}");
            } else {
                std::panic::resume_unwind(error);
            }
        }
    }
}

/// Isolate the complete production schema, including public audit authorities.
pub async fn create(base: &str) -> String {
    let database = format!("nazo_test_{}", uuid::Uuid::now_v7().simple());
    let mut connection = AsyncPgConnection::establish(base).await.unwrap();
    connection
        .batch_execute(&format!("CREATE DATABASE {database}"))
        .await
        .unwrap();
    let mut url = url::Url::parse(base).unwrap();
    url.set_path(&database);
    url.to_string()
}

#[allow(dead_code)] // Baseline-only fixtures apply a selected production migration first.
pub async fn migrate(base: &str) -> String {
    let url = create(base).await;
    nazo_postgres::run_pending_migrations(&url).await.unwrap();
    url
}

#[allow(dead_code)] // Some repository suites retain their fixtures until the test server exits.
pub async fn drop(url: &str) {
    let mut admin = url::Url::parse(url).unwrap();
    let database = admin.path().trim_start_matches('/').to_owned();
    assert!(database.starts_with("nazo_test_"));
    admin.set_path("postgres");
    let mut connection = AsyncPgConnection::establish(admin.as_str()).await.unwrap();
    connection
        .batch_execute(&format!("DROP DATABASE {database} WITH (FORCE)"))
        .await
        .unwrap();
}
