//! 邮件投递封装。

use std::time::Duration;

use anyhow::{Context, bail};
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{Mailbox, MultiPart, SinglePart, header::ContentType},
    transport::smtp::{
        authentication::Credentials,
        client::{Tls, TlsParameters},
    },
};

use crate::domain::{EmailDelivery, Settings, SmtpEmailSettings, SmtpTlsMode};

pub(crate) fn parse_email_recipient(raw: &str) -> anyhow::Result<Mailbox> {
    raw.parse::<Mailbox>()
        .context("recipient email address is invalid")
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
        .multipart(
            MultiPart::alternative()
                .singlepart(text_part(render_verification_text(
                    code,
                    settings.email.code_ttl_seconds,
                )))
                .singlepart(html_part(render_verification_html(
                    code,
                    settings.email.code_ttl_seconds,
                ))),
        )
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

fn text_part(body: String) -> SinglePart {
    SinglePart::builder()
        .header(ContentType::TEXT_PLAIN)
        .body(body)
}

fn html_part(body: String) -> SinglePart {
    SinglePart::builder()
        .header(ContentType::TEXT_HTML)
        .body(body)
}

fn render_verification_text(code: &str, ttl_seconds: u64) -> String {
    format!(
        "你的 Nazo OAuth 注册验证码是：{code}\n\n验证码将在 {} 后失效。如非本人操作，请忽略这封邮件。",
        expiry_text(ttl_seconds)
    )
}

fn render_verification_html(code: &str, ttl_seconds: u64) -> String {
    let expiry = expiry_text(ttl_seconds);
    format!(
        r#"<!doctype html>
<html lang="zh-CN">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Nazo OAuth 注册验证码</title>
  </head>
  <body style="margin:0;padding:0;background:#f4f6f8;color:#111827;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','PingFang SC','Microsoft YaHei',Arial,sans-serif;">
    <div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent;">你的 Nazo OAuth 注册验证码是 {code}</div>
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#f4f6f8;margin:0;padding:32px 16px;">
      <tr>
        <td align="center">
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:560px;background:#ffffff;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden;">
            <tr>
              <td style="padding:28px 32px 18px 32px;border-bottom:1px solid #edf0f3;">
                <div style="font-size:13px;line-height:18px;color:#6b7280;font-weight:600;letter-spacing:0;text-transform:uppercase;">Nazo OAuth</div>
                <h1 style="margin:8px 0 0 0;font-size:22px;line-height:30px;color:#111827;font-weight:700;">注册验证码</h1>
              </td>
            </tr>
            <tr>
              <td style="padding:30px 32px 8px 32px;">
                <p style="margin:0 0 18px 0;font-size:15px;line-height:24px;color:#374151;">请在注册页面输入下面的验证码：</p>
                <div style="margin:0 0 20px 0;padding:18px 20px;background:#f8fafc;border:1px solid #dbe3ea;border-radius:8px;text-align:center;">
                  <div style="font-size:34px;line-height:42px;color:#111827;font-weight:700;letter-spacing:8px;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono','Courier New',monospace;">{code}</div>
                </div>
                <p style="margin:0;font-size:14px;line-height:22px;color:#4b5563;">验证码将在 <strong style="color:#111827;">{expiry}</strong> 后失效。</p>
              </td>
            </tr>
            <tr>
              <td style="padding:18px 32px 30px 32px;">
                <div style="padding:14px 16px;background:#fff7ed;border:1px solid #fed7aa;border-radius:8px;color:#9a3412;font-size:13px;line-height:20px;">如非本人操作，请忽略这封邮件。不要将验证码转发给任何人。</div>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>"#
    )
}

fn expiry_text(ttl_seconds: u64) -> String {
    if ttl_seconds >= 60 && ttl_seconds.is_multiple_of(60) {
        format!("{} 分钟", ttl_seconds / 60)
    } else {
        format!("{ttl_seconds} 秒")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verification_text_uses_human_readable_expiry() {
        let body = render_verification_text("123456", 900);

        assert!(body.contains("123456"));
        assert!(body.contains("15 分钟"));
    }

    #[test]
    fn verification_html_contains_code_and_inline_styles() {
        let body = render_verification_html("123456", 900);

        assert!(body.contains("<!doctype html>"));
        assert!(body.contains("123456"));
        assert!(body.contains("letter-spacing:8px"));
        assert!(body.contains("15 分钟"));
    }
}
