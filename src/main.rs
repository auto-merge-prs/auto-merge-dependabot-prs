use lambda_http::{service_fn, Body, Error, Request};
mod http_handler;
use lambda_runtime::Diagnostic;
use octocrab::models::{events::payload::PullRequestEventPayload, webhook_events::{WebhookEvent, WebhookEventPayload, WebhookEventType}};
use serde_json::json;

async fn handle_webhook_event(request: Request) -> Result<String, ExecutionError> {
    if let Some(event) = request.headers().get("X-GitHub-Event") {
        let event = event.to_str().unwrap();
        if let Body::Text(body) = request.body() {
            let webhook_event = WebhookEvent::try_from_header_and_body(event, body).unwrap();
            if let WebhookEventPayload::PullRequest(pull_request) = webhook_event.payload {
                let pull_request = pull_request.into();
                let pull_request = PullRequestEventPayload::from(pull_request);
                let pull_request = json!(pull_request);
                return Ok(pull_request.to_string());
            }
            match webhook_event.kind {
                WebhookEventType::PullRequest => {
                    return handle_pull_request_event();
                }
                _ => return Err(ExecutionError::MalformedRequest("unsupported event".into())),
            }
        } else {
            return Err(ExecutionError::MalformedRequest("missing request body".into()));
        }
    } else {
        return Err(ExecutionError::MalformedRequest("missing X-GitHub-Event".into()));
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
    #[error("transient database error: {0}")]
    DatabaseError(String),
    #[error("unexpected error: {0}")]
    MalformedRequest(String),
}

impl From<ExecutionError> for Diagnostic {
    fn from(value: ExecutionError) -> Diagnostic {
        let (error_type, error_message) = match value {
            ExecutionError::DatabaseError(err) => ("Retryable", err.to_string()),
            ExecutionError::MalformedRequest(err) => ("NonRetryable", err.to_string()),
        };
        Diagnostic {
            error_type: error_type.into(),
            error_message: error_message.into(),
        }
    }
}


#[cfg(test)]
mod tests {
    use lambda_http::http::{self, Request};

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
            .body(payload.to_string())
            .unwrap();

        let response = handle_webhook_event(Request::new(lambda_http::Body::Text(payload.into())))
            .await
            .unwrap();
    }
}
