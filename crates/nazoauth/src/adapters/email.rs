//! 邮件投递封装。

use std::time::Duration;

use anyhow::Context;
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

pub(crate) fn normalize_email_address(raw: &str) -> anyhow::Result<String> {
    Ok(nazo_identity::email::normalize_email_address(raw)?)
}

fn parse_email_address(raw: &str) -> anyhow::Result<Address> {
    let normalized = raw.trim().to_ascii_lowercase();
    normalized
        .parse::<Address>()
        .context("email address is invalid")
}

pub(crate) fn email_delivery_configured(settings: &Settings) -> bool {
    matches!(&settings.identity.email.delivery, EmailDelivery::Smtp(_))
}

async fn send_verification_email_with_ttl(
    from: &Mailbox,
    transport: &AsyncSmtpTransport<Tokio1Executor>,
    recipient: Mailbox,
    code: &str,
    code_ttl_seconds: u64,
) -> anyhow::Result<()> {
    let message = Message::builder()
        .from(from.clone())
        .to(recipient)
        .subject("Nazo OAuth 注册验证码")
        .singlepart(html_part(
            VerificationEmail::new(code, code_ttl_seconds).render_html(),
        ))
        .context("failed to build verification email")?;

    transport
        .send(message)
        .await
        .context("failed to send verification email")?;
    Ok(())
}

#[derive(Clone)]
pub(crate) struct SmtpVerificationEmailDelivery {
    smtp: Option<(Mailbox, AsyncSmtpTransport<Tokio1Executor>)>,
}

impl SmtpVerificationEmailDelivery {
    pub(crate) fn from_delivery(delivery: &EmailDelivery) -> anyhow::Result<Self> {
        Ok(Self {
            smtp: match delivery {
                EmailDelivery::Disabled => None,
                EmailDelivery::Smtp(smtp) => Some((smtp.from.clone(), build_smtp_transport(smtp)?)),
            },
        })
    }
}

impl nazo_identity::ports::VerificationEmailDeliveryPort for SmtpVerificationEmailDelivery {
    fn deliver<'a>(
        &'a self,
        normalized_email: &'a str,
        code: &'a str,
        code_ttl_seconds: u64,
    ) -> nazo_identity::ports::RepositoryFuture<'a, ()> {
        Box::pin(async move {
            let (from, transport) = self.smtp.as_ref().ok_or_else(|| {
                nazo_identity::ports::RepositoryError::Unexpected(
                    "email delivery is disabled".to_owned(),
                )
            })?;
            let address = parse_email_address(normalized_email).map_err(|error| {
                nazo_identity::ports::RepositoryError::Unexpected(error.to_string())
            })?;
            send_verification_email_with_ttl(
                from,
                transport,
                Mailbox::new(None, address),
                code,
                code_ttl_seconds,
            )
            .await
            .map_err(|error| nazo_identity::ports::RepositoryError::Unexpected(error.to_string()))
        })
    }
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
#[path = "../../tests/unit/adapters/email.rs"]
mod tests;
