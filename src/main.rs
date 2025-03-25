use lambda_http::{service_fn, tracing, Body, Error, Request};
mod http_handler;
use lambda_runtime::Diagnostic;
use octocrab::{
    models::{
        pulls::PullRequestAction,
        webhook_events::{
            payload::{PullRequestWebhookEventAction, PullRequestWebhookEventPayload},
            WebhookEvent, WebhookEventPayload,
        },
        Author, UserId,
    },
    Octocrab,
};
use serde_json::Value;

mod signature;

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing::init_default_subscriber();

    lambda_http::run(service_fn(handle_webhook_event)).await
}

async fn handle_webhook_event(request: Request) -> Result<String, ExecutionError> {
    let (event, body) = event_and_body(&request).await?;
    let webhook_event = WebhookEvent::try_from_header_and_body(event, body).unwrap();
    match &webhook_event.specific {
        WebhookEventPayload::PullRequest(pr) => {
            handle_pull_request_event(&request, body, &webhook_event, pr).await
        }
        _ => Ok("not a pull request event".into()),
    }
}

async fn handle_pull_request_event(
    request: &Request,
    body: &String,
    webhook_event: &WebhookEvent,
    pr: &PullRequestWebhookEventPayload,
) -> Result<String, ExecutionError> {
    let author = webhook_event.sender.as_ref().unwrap();

    Ok(
        if is_dependabot(author) && pr.action == PullRequestWebhookEventAction::Opened {
            handle_pull_request_opened_by_dependabot(request, body, pr).await?
        } else {
            "NOT PR opened by dependabot. No action.".into()
        },
    )
}

async fn handle_pull_request_opened_by_dependabot(
    request: &Request,
    body: &String,
    _pr: &PullRequestWebhookEventPayload,
) -> Result<String, ExecutionError> {
    let Some(signature) = request
        .headers()
        .get("X-Hub-Signature-256")
        .map(|h| h.to_str().unwrap())
    else {
        return Err(ExecutionError::MalformedRequest(
            "missing X-Hub-Signature-256 header".into(),
        ));
    };

    let Some(secret) = get_secret("auto-merge-dependabot-pull-requests-webhook-secret").await
    else {
        return Err(ExecutionError::MalformedRequest(
            "failed to get webhook secret".into(),
        ));
    };

    let sender = match signature::verify(signature, &secret, body.as_bytes()) {
        signature::VerificationResult::Success => Sender::GitHub,
        signature::VerificationResult::Failure => Sender::Unknown,
    };

    if sender == Sender::GitHub {
        let app_id = 1162951; // https://github.com/settings/apps/auto-merge-dependabot-prs
        let Some(private_key) =
            get_secret("auto-merge-dependabot-pull-requests-private-key-1").await
        else {
            return Err(ExecutionError::MalformedRequest(
                "failed to get webhook secret".into(),
            ));
        };
        let key = jsonwebtoken::EncodingKey::from_ed_pem(private_key.as_bytes()).unwrap();

        let octocrab = Octocrab::builder().app(app_id.into(), key).build().unwrap();
        octocrab
            .pulls()
            .merge("octocrab", "octocrab", 1)
            .await
            .unwrap();

        Ok("signature verified".into())
    } else {
        Err(ExecutionError::MalformedRequest(
            "invalid dependabot signature".into(),
        ))
    }
}

fn is_dependabot(author: &Author) -> bool {
    author.login == "dependabot[bot]" && author.id == UserId(49699333)
}

async fn request_secret(aws_session_token: String, secret_id: &str) -> reqwest::Result<Value> {
    // static AWS_SESSION_TOKEN: std::sync::LazyLock<>
    //
    //
    let client = reqwest::Client::new();
    client
        .get(format!(
            "http://localhost:2773/secretsmanager/get?secretId={secret_id}"
        ))
        .header("X-Aws-Parameters-Secrets-Token", aws_session_token)
        .send()
        .await?
        .json::<Value>()
        .await
}

async fn get_secret(secret_id: &str) -> Option<String> {
    let Ok(aws_session_token) = std::env::var("AWS_SESSION_TOKEN") else {
        eprintln!("AWS_SESSION_TOKEN not set");
        return None;
    };

    let Ok(json) = request_secret(aws_session_token, secret_id).await else {
        eprintln!("Failed to get secret from AWS");
        return None;
    };

    json.get("SecretString")
        .and_then(|s| s.as_str())
        .map(ToString::to_string)
}

/*

    let body = handle_webhook_event_with_secret(request, &secret).await?;
    Ok(body)

    let secret = match get_webhook_secret().await {
        Some(secret) => secret,
        None => {
            eprintln!("Failed to get secret from JSON. Using dummy secret.");
            "dummy-secret".to_owned()
        }
    };

*/

#[derive(Debug, thiserror::Error)]
pub enum ExecutionError {
    #[error("unexpected error: {0}")]
    MalformedRequest(String),
}

impl From<ExecutionError> for Diagnostic {
    fn from(value: ExecutionError) -> Diagnostic {
        let (error_type, error_message) = match value {
            ExecutionError::MalformedRequest(err) => ("MalformedRequest", err.to_string()),
        };
        Diagnostic {
            error_type: error_type.into(),
            error_message: error_message.into(),
        }
    }
}

#[derive(PartialEq, Eq, Debug)]
enum Sender {
    GitHub,
    Unknown,
}

async fn event_and_body(request: &Request) -> Result<(&str, &String), ExecutionError> {
    let Some(event) = request
        .headers()
        .get("X-GitHub-Event")
        .map(|h| h.to_str().unwrap())
    else {
        return Err(ExecutionError::MalformedRequest(
            "missing X-GitHub-Event header".into(),
        ));
    };

    let Body::Text(body) = request.body() else {
        return Err(ExecutionError::MalformedRequest(
            "request body is not text".into(),
        ));
    };

    Ok((event, body))
}

/*
#[cfg(test)]
mod tests {
    use lambda_http::http::{self};

    use super::*;

    #[tokio::test]
    async fn test_pull_request_opened_by_dependabot() {
        let payload = include_str!(
            "../tests/webhook-request-examples/pull-request-opened-by-dependabot/payload.json"
        );
        let secret = "not-secret-secret";

        // let headers = include_str!("../tests/webhook-request-examples/pull-request-opened-by-dependabot/headers.txt");
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri("/webhook")
            .header("X-GitHub-Event", "pull_request")
            .header(
                "X-Hub-Signature-256",
                &format!(
                    "sha256={}",
                    hex::encode(&signature::calculate(secret, payload.as_bytes()))
                ),
            )
            .body(lambda_http::Body::Text(payload.into()))
            .unwrap();

        let response = handle_webhook_event_with_secret(request, secret)
            .await
            .unwrap();

        println!("{:?}", response);
    }
}
 */
