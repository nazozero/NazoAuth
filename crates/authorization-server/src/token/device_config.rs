#[derive(Clone)]
pub struct DeviceConfig {
    pub issuer: Box<str>,
    pub mtls_endpoint_base_url: Box<str>,
    pub frontend_base_url: Box<str>,
    pub client_secret_pepper: Box<str>,
    pub default_audience: Box<str>,
    pub ttl_seconds: u64,
    pub poll_interval_seconds: u64,
    pub pairwise_subject_secret: Option<Box<str>>,
}
