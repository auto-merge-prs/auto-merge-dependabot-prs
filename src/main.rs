use lambda_http::{service_fn, Body, Error, Request};
mod http_handler;
use lambda_runtime::Diagnostic;
use octocrab::models::{events::payload::PullRequestEventPayload, webhook_events::WebhookEvent};
use serde_json::json;

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

async fn handle_webhook_event(request: Request) -> Result<String, ExecutionError> {
    if let Some(event) = request.headers().get("X-GitHub-Event") {
        let event = event.to_str().unwrap();
        if let Body::Text(body) = request.body() {
            let payload = body.to_string();
            let webhook_event = WebhookEvent::try_from_header_and_body(event, &payload);
            match webhook_event {
                Ok(WebhookEvent::PullRequest(pull_request_webhook_event_payload)) => {
                    let pull_request = pull_request_webhook_event_payload.pull_request;
                    let action = pull_request_webhook_event_payload.action;
                    let changes = pull_request_webhook_event_payload.changes;
                    let changes = match changes {
                        Some(changes) => {
                            let title = changes.title.map(|title| title.from);
                            let body = changes.body.map(|body| body.from);
                            Some(PullRequestEventChanges {
                                title,
                                body,
                            })
                        }
                        None => None,
                    };
                    let pull_request = PullRequestEventPayload {
                        action,
                        number: pull_request.number,
                        pull_request: pull_request.pull_request,
                        changes,
                    };
                    return Ok(json!(pull_request).to_string());
                }
                _ => return Err(ExecutionError::MalformedRequest("unsupported event".into())),
            }
        }
        let webhook_event = WebhookEvent::try_from_header_and_body(event, request.body())

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
