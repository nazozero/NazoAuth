pub(crate) struct EmailRecipient {
    pub(crate) normalized: String,
    pub(crate) mailbox: Mailbox,
}

pub(crate) fn parse_email_recipient(raw: &str) -> anyhow::Result<EmailRecipient> {
    let address = parse_email_address(raw)?;
    let normalized = address.to_string();
    Ok(EmailRecipient {
        normalized,
        mailbox: Mailbox::new(None, address),
    })
}
