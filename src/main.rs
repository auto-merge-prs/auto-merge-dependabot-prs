use lambda_http::{service_fn, Body, Error, Request};
mod http_handler;
use lambda_runtime::Diagnostic;
use octocrab::models::webhook_events::{
    payload::PullRequestWebhookEventPayload, WebhookEvent, WebhookEventPayload,
};

mod signature;

async fn handle_pull_request_event(
    webhook_event: WebhookEvent,
    pr: PullRequestWebhookEventPayload,
) -> Result<String, ExecutionError> {
    let sender = webhook_event.sender.unwrap();

    return Ok(format!(
        "Pull request! action={:?} login={} id={}",
        pr.action, sender.login, sender.id
    ));
}

async fn handle_webhook_event(request: Request) -> Result<String, ExecutionError> {
    let Some(event) = request.headers().get("X-GitHub-Event") else {
        return Err(ExecutionError::MalformedRequest(
            "missing X-GitHub-Event header".into(),
        ));
    };

    let event = event.to_str().unwrap();
    if let Body::Text(body) = request.body() {
        let webhook_event = WebhookEvent::try_from_header_and_body(event, body).unwrap();
        return match webhook_event.specific {
            WebhookEventPayload::PullRequest(pr) => {
                handle_pull_request_event(webhook_event, pr).await
            }
            _ => Ok("not a pull request event".into()),
        };
    } else {
        return Err(ExecutionError::MalformedRequest(
            "missing request body".into(),
        ));
    }
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

#[cfg(test)]
mod tests {
    use lambda_http::http::{self};

    use super::*;

    #[tokio::test]
    async fn test_pull_request_opened_by_dependabot() {
        let payload = include_str!(
            "../tests/webhook-request-examples/pull-request-opened-by-dependabot/payload.json"
        );

        // let headers = include_str!("../tests/webhook-request-examples/pull-request-opened-by-dependabot/headers.txt");
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri("/webhook")
            .header("X-GitHub-Event", "pull_request")
            .body(lambda_http::Body::Text(payload.into()))
            .unwrap();

        let response = handle_webhook_event(request).await.unwrap();

        println!("{:?}", response);
    }
}
