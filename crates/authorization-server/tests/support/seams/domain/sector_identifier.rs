pub(crate) fn sector_identifier_hostname(uri: &str) -> Result<String, SectorIdentifierError> {
    let parsed = url::Url::parse(uri).map_err(|_| SectorIdentifierError::InvalidUri)?;
    parsed
        .host_str()
        .map(ToOwned::to_owned)
        .ok_or(SectorIdentifierError::InvalidUri)
}
