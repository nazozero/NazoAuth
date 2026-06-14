//! 邮件投递封装。

use std::time::Duration;

use anyhow::{Context, bail};
use lettre::{
    Address, AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{Mailbox, SinglePart, header::ContentType},
    transport::smtp::{
        authentication::Credentials,
        client::{Tls, TlsParameters},
    },
};

use crate::settings::{EmailDelivery, Settings, SmtpEmailSettings, SmtpTlsMode};

use super::email_templates::VerificationEmail;

pub(crate) struct EmailRecipient {
    pub(crate) normalized: String,
    pub(crate) mailbox: Mailbox,
}

pub(crate) fn normalize_email_address(raw: &str) -> anyhow::Result<String> {
    Ok(parse_email_address(raw)?.to_string())
}

fn parse_email_address(raw: &str) -> anyhow::Result<Address> {
    let normalized = raw.trim().to_ascii_lowercase();
    normalized
        .parse::<Address>()
        .context("email address is invalid")
}

pub(crate) fn parse_email_recipient(raw: &str) -> anyhow::Result<EmailRecipient> {
    let address = parse_email_address(raw)?;
    let normalized = address.to_string();
    Ok(EmailRecipient {
        normalized,
        mailbox: Mailbox::new(None, address),
    })
}

pub(crate) fn email_delivery_configured(settings: &Settings) -> bool {
    matches!(&settings.email.delivery, EmailDelivery::Smtp(_))
}

pub(crate) async fn send_verification_email(
    settings: &Settings,
    recipient: Mailbox,
    code: &str,
) -> anyhow::Result<()> {
    let EmailDelivery::Smtp(smtp) = &settings.email.delivery else {
        bail!("email delivery is disabled");
    };

    let message = Message::builder()
        .from(smtp.from.clone())
        .to(recipient)
        .subject("Nazo OAuth 注册验证码")
        .singlepart(html_part(
            VerificationEmail::new(code, settings.email.code_ttl_seconds).render_html(),
        ))
        .context("failed to build verification email")?;

    build_smtp_transport(smtp)?
        .send(message)
        .await
        .context("failed to send verification email")?;
    Ok(())
}

fn build_smtp_transport(
    smtp: &SmtpEmailSettings,
) -> anyhow::Result<AsyncSmtpTransport<Tokio1Executor>> {
    let tls_parameters =
        || TlsParameters::new(smtp.host.clone()).context("failed to build SMTP TLS parameters");

    let tls = match smtp.tls {
        SmtpTlsMode::StartTls => Tls::Required(tls_parameters()?),
        SmtpTlsMode::ImplicitTls => Tls::Wrapper(tls_parameters()?),
        SmtpTlsMode::None => Tls::None,
    };

    let mut builder = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&smtp.host)
        .port(smtp.port)
        .tls(tls)
        .timeout(Some(Duration::from_secs(30)));

    if let (Some(username), Some(password)) = (&smtp.username, &smtp.password) {
        builder = builder.credentials(Credentials::new(username.clone(), password.clone()));
    }

    Ok(builder.build())
}

fn html_part(body: String) -> SinglePart {
    SinglePart::builder()
        .header(ContentType::TEXT_HTML)
        .body(body)
}

#[cfg(test)]
#[path = "../../tests/unit/src/support/tests/email.rs"]
mod tests;
