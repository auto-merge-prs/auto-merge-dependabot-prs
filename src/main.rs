use lambda_http::{service_fn, Body, Error, Request};
mod http_handler;
use lambda_runtime::Diagnostic;
use octocrab::models::{
    webhook_events::{payload::PullRequestWebhookEventPayload, WebhookEvent, WebhookEventPayload},
    Author, UserId,
};

mod signature;

fn is_dependabot(author: &Author) -> bool {
    author.login == "dependabot[bot]" && author.id == UserId(49699333)
}

async fn handle_pull_request_event(
    sender: Sender,
    webhook_event: &WebhookEvent,
    _pr: &PullRequestWebhookEventPayload,
) -> Result<String, ExecutionError> {
    let author = webhook_event.sender.as_ref().unwrap();

    Ok(if sender == Sender::GitHub {
        if is_dependabot(author) {
            "Auto-merge! Pull request opened by dependabot."
        } else {
            "NOT opened dependabot. No action."
        }
    } else {
        "NOT sent by GitHub. No action."
    }
    .into())
}

async fn handle_webhook_event_with_secret(
    request: Request,
    secret: &str,
) -> Result<String, ExecutionError> {
    let Body::Text(body) = request.body() else {
        return Err(ExecutionError::MalformedRequest(
            "request body is not text".into(),
        ));
    };

    let Some(event) = request
        .headers()
        .get("X-GitHub-Event")
        .map(|h| h.to_str().unwrap())
    else {
        return Err(ExecutionError::MalformedRequest(
            "missing X-GitHub-Event header".into(),
        ));
    };

    let Some(signature) = request
        .headers()
        .get("X-Hub-Signature-256")
        .map(|h| h.to_str().unwrap())
    else {
        return Err(ExecutionError::MalformedRequest(
            "missing X-Hub-Signature-256 header".into(),
        ));
    };

    let sender = match signature::verify(signature, secret, body.as_bytes()) {
        signature::VerificationResult::Success => Sender::GitHub,
        signature::VerificationResult::Failure => Sender::Unknown,
    };

    let webhook_event = WebhookEvent::try_from_header_and_body(event, body).unwrap();
    return match &webhook_event.specific {
        WebhookEventPayload::PullRequest(pr) => {
            handle_pull_request_event(sender, &webhook_event, pr).await
        }
        _ => Ok("not a pull request event".into()),
    };
}

async fn handle_webhook_event(request: Request) -> Result<String, ExecutionError> {
    let secret = "TODO";
    handle_webhook_event_with_secret(request, secret).await
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let func = service_fn(handle_webhook_event);
    lambda_http::run(func).await?;
    Ok(())
}

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

#[cfg(test)]
mod tests {
    use lambda_http::http::{self};
    use openssl::sign;

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
