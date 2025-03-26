use configuration::Configuration;
use lambda_http::{service_fn, tracing, Body, Error, Request};
mod http_handler;
use lambda_runtime::Diagnostic;
use octocrab::{
    models::{
        webhook_events::{
            payload::{PullRequestWebhookEventAction, PullRequestWebhookEventPayload},
            WebhookEvent, WebhookEventPayload,
        },
        Author, InstallationId, UserId,
    },
    Octocrab,
};
use serde_json::Value;

mod configuration;
mod signature;

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing::init_default_subscriber();

    lambda_http::run(service_fn(handle_webhook_event)).await
}

async fn handle_webhook_event(request: Request) -> Result<String, ExecutionError> {
    let context = Context::new(request).await?;
    context.handle_webhook_event().await
}

struct Context {
    body: Body,
    webhook_event: WebhookEvent,
    conf: Configuration,
    expected_signature: String,
}

impl Context {
    async fn new(request: Request) -> Result<Self, ExecutionError> {
        let (github_event, expected_signature, body) =
            request_into_event_and_signature_and_body(request)
                .map_err(|e| ExecutionError::MalformedRequest(e.to_string()))?;
        let webhook_event = WebhookEvent::try_from_header_and_body(&github_event, &body)
            .map_err(|e| ExecutionError::MalformedRequest(e.to_string()))?;

        Ok(Self {
            body,
            webhook_event,
            conf: Configuration::from_env(),
            expected_signature,
        })
    }

    async fn handle_webhook_event(&self) -> Result<String, ExecutionError> {
        match &self.webhook_event.specific {
            WebhookEventPayload::PullRequest(pr) => self.handle_pull_request_event(pr).await,
            _ => Ok("not a pull request event".into()),
        }
    }

    async fn handle_pull_request_event(
        &self,
        pr: &PullRequestWebhookEventPayload,
    ) -> Result<String, ExecutionError> {
        let author = self
            .webhook_event
            .sender
            .as_ref()
            .ok_or(ExecutionError::MalformedRequest("missing sender".into()))?;

        Ok(
            if is_dependabot(author) && pr.action == PullRequestWebhookEventAction::Opened {
                self.handle_pull_request_opened_by_dependabot(pr).await?
            } else {
                "PR not by dependabot or action not 'opened'".into()
            },
        )
    }

    async fn handle_pull_request_opened_by_dependabot(
        &self,
        pr: &PullRequestWebhookEventPayload,
    ) -> Result<String, ExecutionError> {
        let sender = self.sender().await?;
        if sender == Sender::GitHub {
            self.enable_auto_merge(pr).await
        } else {
            Err(ExecutionError::MalformedRequest(
                "invalid dependabot signature".into(),
            ))
        }
    }

    async fn enable_auto_merge(
        &self,
        pr: &PullRequestWebhookEventPayload,
    ) -> Result<String, ExecutionError> {
        let octocrab = self.github_app_installation_instance().await?;
        match octocrab.issues("cargo-public-api", "cargo-public-api").create_comment(pr.number, "Dry-run (no action taken): If CI passes, this dependabot PR will be [auto-merged](https://github.com/cargo-public-api/cargo-public-api/blob/main/.github/workflows/Auto-merge-dependabot-PRs.yml) 🚀").await {
            Ok(_) => Ok("created dry-run comment".into()),
            Err(e) => Ok(format!("Failed to create dry-run comment {:?}", e)),
        }
    }

    async fn github_app_installation_instance(&self) -> Result<Octocrab, ExecutionError> {
        let private_key = get_secret("AUTO_MERGE_DEPENDABOT_PRS_SECRET_ID_PRIVATE_KEY").await?;
        let jwt_key = jsonwebtoken::EncodingKey::from_rsa_pem(private_key.as_bytes()).unwrap();
        Octocrab::builder()
            .app(self.conf.app_id, jwt_key)
            .build()
            .unwrap()
            .installation(self.installation_id())
            .map_err(|e| {
                ExecutionError::MalformedRequest(format!(
                    "could not get installation instance: {e}"
                ))
            })
    }

    fn installation_id(&self) -> InstallationId {
        match self.webhook_event.installation.as_ref().unwrap() {
            octocrab::models::webhook_events::EventInstallation::Full(installation) => {
                installation.id
            }
            octocrab::models::webhook_events::EventInstallation::Minimal(event_installation_id) => {
                event_installation_id.id
            }
        }
    }

    async fn sender(&self) -> Result<Sender, ExecutionError> {
        let webhook_secret =
            get_secret("AUTO_MERGE_DEPENDABOT_PRS_SECRET_ID_WEBHOOK_SECRET").await?;
        Ok(
            match signature::verify(
                &self.expected_signature,
                &webhook_secret,
                self.body.as_ref(),
            ) {
                signature::VerificationResult::Success => Sender::GitHub,
                signature::VerificationResult::Failure => Sender::Unknown,
            },
        )
    }
}

fn is_dependabot(author: &Author) -> bool {
    author.login == "dependabot[bot]" && author.id == UserId(49699333)
}

async fn request_secret(aws_session_token: String, secret_id: &str) -> reqwest::Result<Value> {
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

async fn get_secret(secret_id_env_var_name: &str) -> Result<String, ExecutionError> {
    let aws_session_token = std::env::var("AWS_SESSION_TOKEN")
        .map_err(|_| ExecutionError::MalformedRequest("AWS_SESSION_TOKEN not set".to_string()))?;

    let secret_id = std::env::var(secret_id_env_var_name).map_err(|_| {
        ExecutionError::MalformedRequest(format!("Failed to get env var {secret_id_env_var_name}"))
    })?;

    let json = request_secret(aws_session_token, &secret_id)
        .await
        .map_err(|_| {
            ExecutionError::MalformedRequest(format!("Failed to get secret id {secret_id} "))
        })?;

    json.get("SecretString")
        .and_then(|s| s.as_str())
        .map(ToString::to_string)
        .ok_or(ExecutionError::MalformedRequest(format!(
            "No SecretString in JSON"
        )))
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
            error_message,
        }
    }
}

#[derive(PartialEq, Eq, Debug)]
enum Sender {
    GitHub,
    Unknown,
}

fn request_into_event_and_signature_and_body(
    request: Request,
) -> Result<(String, String, Body), ExecutionError> {
    let signature = request
        .headers()
        .get("X-Hub-Signature-256")
        .map(|v| v.to_str().unwrap())
        .ok_or(ExecutionError::MalformedRequest(
            "missing X-Hub-Signature-256 header".into(),
        ))?;

    let event = request
        .headers()
        .get("X-GitHub-Event")
        .map(|v| v.to_str().unwrap())
        .ok_or(ExecutionError::MalformedRequest(
            "missing X-GitHub-Event header".into(),
        ))?;

    Ok((
        event.to_string(),
        signature.to_string(),
        request.into_body(),
    ))
}
