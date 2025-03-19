use lambda_http::{service_fn, Error};
mod http_handler;
use lambda_runtime::LambdaEvent;
use octocrab::models::{events::payload::PullRequestEventPayload, webhook_events::WebhookEvent};

async fn handle_webhook_event(
    lambda_event: LambdaEvent<WebhookEvent>,
) -> Result<String, Error> {
    match lambda_event.into_parts().0.specific {
        octocrab::models::webhook_events::WebhookEventPayload::PullRequest(pull_request_webhook_event_payload) => todo!(),
        _ => return Ok("TODO: More specific error"),
    }
    let (event, _context) = ;
    let pr = event.specific;
    Ok(format!("Got {:?} from {:?} ({:?}).", event.action, pr));
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let func = service_fn(handle_pull_request_event);
    lambda_runtime::run(func).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pull_request_opened_by_dependabot() {
        let payload = include_str!("../tests/webhook-request-examples/pull-request-opened-by-dependabot/payload.json");
        let headers = include_str!("../tests/webhook-request-examples/pull-request-opened-by-dependabot/headers.txt");
        let request 
        
    }
}