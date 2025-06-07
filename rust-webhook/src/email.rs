// Utility to send email using AWS SES
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_ses::{Client, Error as SesError};

pub async fn send_admin_email(subject: &str, body: &str) -> Result<(), String> {
    let admin_email = std::env::var("ADMIN_EMAIL").map_err(|_| "ADMIN_EMAIL not set")?;
    let region_provider = RegionProviderChain::default_provider().or_else("us-east-1");
    let config = aws_config::from_env().region(region_provider).load().await;
    let client = Client::new(&config);

    let subject_content = aws_sdk_ses::types::Content::builder()
        .data(subject)
        .charset("UTF-8")
        .build()
        .map_err(|e| format!("SES subject build error: {e}"))?;
    let body_content = aws_sdk_ses::types::Content::builder()
        .data(body)
        .charset("UTF-8")
        .build()
        .map_err(|e| format!("SES body build error: {e}"))?;

    let message = aws_sdk_ses::types::Message::builder()
        .subject(subject_content)
        .body(
            aws_sdk_ses::types::Body::builder()
                .text(body_content)
                .build(),
        )
        .build();

    let destination = aws_sdk_ses::types::Destination::builder()
        .to_addresses(admin_email.clone())
        .build();

    client
        .send_email()
        .destination(destination)
        .message(message)
        .source(admin_email.clone())
        .send()
        .await
        .map_err(|e| format!("SES send error: {e}"))?;
    Ok(())
}
