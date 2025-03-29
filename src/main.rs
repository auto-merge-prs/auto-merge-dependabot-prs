use graphql_client::GraphQLQuery;
use lambda_http::{service_fn, tracing, Body, Error, Request};
mod http_handler;
use lambda_runtime::Diagnostic;
use octocrab::{
    models::{
        webhook_events::{
            payload::{PullRequestWebhookEventAction, PullRequestWebhookEventPayload},
            WebhookEvent, WebhookEventPayload,
        },
        AppId, Author,
    },
    Octocrab,
};
use serde_json::{json, Value};

mod signature;

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing::init_default_subscriber();

    lambda_http::run(service_fn(handle_webhook_event)).await
}

async fn handle_webhook_event(request: Request) -> Result<&'static str, ExecutionError> {
    let context = Context::new(request).await?;
    context.handle_webhook_event().await
}

struct Context {
    body: Body,
    webhook_event: WebhookEvent,
    expected_signature: String,
}

impl Context {
    async fn new(request: Request) -> Result<Self, ExecutionError> {
        let (github_event, expected_signature, body) =
            request_into_event_and_signature_and_body(request)?;

        let webhook_event = WebhookEvent::try_from_header_and_body(&github_event, &body)
            .map_err(|_| ExecutionError::MalformedRequest("not a webhook event"))?;

        Ok(Self {
            body,
            webhook_event,
            expected_signature,
        })
    }

    async fn handle_webhook_event(&self) -> Result<&'static str, ExecutionError> {
        match &self.webhook_event.specific {
            WebhookEventPayload::PullRequest(pr) => self.handle_pull_request_event(pr).await,
            _ => Ok("not a pull request event"),
        }
    }

    async fn handle_pull_request_event(
        &self,
        pr: &PullRequestWebhookEventPayload,
    ) -> Result<&'static str, ExecutionError> {
        let author = self
            .webhook_event
            .sender
            .as_ref()
            .ok_or(ExecutionError::MalformedRequest("missing sender"))?;

        Ok(
            if is_dependabot(author)? && pr.action == PullRequestWebhookEventAction::Opened {
                self.handle_pull_request_opened_by_dependabot(pr).await?
            } else {
                "PR not by dependabot or action not 'opened'"
            },
        )
    }

    async fn handle_pull_request_opened_by_dependabot(
        &self,
        pr: &PullRequestWebhookEventPayload,
    ) -> Result<&'static str, ExecutionError> {
        let sender = self.sender().await?;
        if sender == Sender::GitHub {
            self.announce_and_enable_auto_merge(pr).await
        } else {
            Err(ExecutionError::MalformedRequest(
                "invalid dependabot signature",
            ))
        }
    }

    async fn announce_auto_merge(
        &self,
        octocrab: &Octocrab,
        pr_id: String,
    ) -> Result<(), ExecutionError> {
        #[derive(graphql_client::GraphQLQuery)]
        #[graphql(
            schema_path = "github_schema.graphql",
            query_path = "src/add_comment.graphql"
        )]
        pub struct AddComment;

        let variables = add_comment::Variables {
            id: pr_id.to_string(),
            body: "(dry-run test 7) If CI passes, this dependabot PR will be [auto-merged](https://github.com/apps/auto-merge-dependabot-prs) 🚀".to_string(),
        };

        let response: graphql_client::Response<add_comment::ResponseData> = octocrab
            .graphql(&AddComment::build_query(variables))
            .await
            .map_err(|e| ExecutionError::GitHubError(e.to_string()))?;
        if response
            .data
            .and_then(|x| x.add_comment)
            .and_then(|x| x.subject)
            .map(|x| x.id)
            .unwrap_or_default()
            == pr_id
        {
            Ok(())
        } else {
            Err(ExecutionError::GitHubError("subject id mismatch".into()))
        }
    }

    async fn enable_auto_merge(
        &self,
        octocrab: &Octocrab,
        pr_id: &str,
    ) -> Result<&'static str, ExecutionError> {
        if !std::env::var("AUTO_MERGE_DEPENDABOT_PRS_ACTUALLY_MERGE").is_ok() {
            return Ok("skipping auto-merge for now, set AUTO_MERGE_DEPENDABOT_PRS_ACTUALLY_MERGE=1 to enable");
        }

        let graphql_auto_merge = json!({
            "query": "mutation($id: ID!) {
                enablePullRequestAutoMerge(input: { pullRequestId: $id }) {
                    pullRequest {
                        id
                    }
                }
            }",
            "variables": {
                "id": pr_id
            }
        });
        let add_comment_response: Value = octocrab
            .graphql(&graphql_auto_merge)
            .await
            .map_err(|e| ExecutionError::GitHubError(e.to_string()))?;
        let response_pr_id = add_comment_response
            .get("data")
            .and_then(|data| data.get("addComment"))
            .and_then(|add_comment| add_comment.get("pullRequest"))
            .and_then(|subject| subject.get("id"))
            .and_then(|id| id.as_str())
            .ok_or(ExecutionError::GitHubError("could not get PR id".into()))?;
        if response_pr_id != pr_id {
            return Err(ExecutionError::GitHubError("PR id mismatch".into()));
        }
        Ok("enabled auto-merge via graphql")
    }

    async fn announce_and_enable_auto_merge(
        &self,
        pr: &PullRequestWebhookEventPayload,
    ) -> Result<&'static str, ExecutionError> {
        let octocrab = self.github_app_installation_instance().await?;
        let pr_id = pr.pull_request.node_id.as_ref().unwrap();
        self.announce_auto_merge(&octocrab, pr_id.into()).await?;
        self.enable_auto_merge(&octocrab, pr_id).await
    }

    async fn github_app_installation_instance(&self) -> Result<Octocrab, ExecutionError> {
        let private_key = get_secret("AUTO_MERGE_DEPENDABOT_PRS_SECRET_ID_PRIVATE_KEY").await?;
        let jwt_key = jsonwebtoken::EncodingKey::from_rsa_pem(private_key.as_bytes()).unwrap();
        let app_id = get_required_env_var("AUTO_MERGE_DEPENDABOT_PRS_GITHUB_APP_ID")?;
        Octocrab::builder()
            .app(AppId(app_id.parse().unwrap()), jwt_key)
            .build()
            .unwrap()
            .installation(self.webhook_event.installation.as_ref().unwrap().id())
            .map_err(|_| ExecutionError::ConfigurationError("could not get installation instance"))
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

fn is_dependabot(author: &Author) -> Result<bool, ExecutionError> {
    let name_and_id =
        get_required_env_var("AUTO_MERGE_DEPENDABOT_PRS_DEPENDABOT_USER_NAME_AND_ID")?;
    Ok(format!("{},{}", author.login, author.id) == name_and_id)
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

fn get_required_env_var(env_var_name: &'static str) -> Result<String, ExecutionError> {
    std::env::var(env_var_name).map_err(|_| ExecutionError::EnvVarNotSet(env_var_name))
}

async fn get_secret(secret_id_env_var_name: &'static str) -> Result<String, ExecutionError> {
    let aws_session_token = get_required_env_var("AWS_SESSION_TOKEN")?;
    let secret_id = get_required_env_var(secret_id_env_var_name)?;

    let json = request_secret(aws_session_token, &secret_id)
        .await
        .map_err(|_| ExecutionError::MissingSecretId(secret_id))?;

    json.get("SecretString")
        .and_then(|s| s.as_str())
        .map(ToString::to_string)
        .ok_or(ExecutionError::MalformedRequest("No SecretString in JSON"))
}

#[derive(Debug, thiserror::Error)]
pub enum ExecutionError {
    /// Reduce risk of secrets leaking by only allowing static strings
    #[error("malformed request: {0}")]
    MalformedRequest(&'static str),
    #[error("malformed request: {0}")]
    ConfigurationError(&'static str),
    #[error("missing env var: {0}")]
    EnvVarNotSet(&'static str),
    #[error("missing secret with id: {0}")]
    MissingSecretId(String),
    #[error("git hub error: {0}")]
    GitHubError(String),
}

// NORDH Ok(Object {"data": Object {"addComment": Object {"subject": Object {"id": String("PR_kwDOGpYTtM6P-Rmm")}}}})

impl From<ExecutionError> for Diagnostic {
    fn from(value: ExecutionError) -> Diagnostic {
        let (error_type, error_message) = match value {
            ExecutionError::MalformedRequest(err) => ("MalformedRequest", err.to_string()),
            ExecutionError::EnvVarNotSet(err) => ("EnvVarNotSet", err.to_string()),
            ExecutionError::MissingSecretId(err) => ("MissingSecretId", err.to_string()),
            ExecutionError::ConfigurationError(err) => ("ConfigurationError", err.to_string()),
            ExecutionError::GitHubError(err) => ("GitHubError", err.to_string()),
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
            "missing X-Hub-Signature-256 header",
        ))?;

    let event = request
        .headers()
        .get("X-GitHub-Event")
        .map(|v| v.to_str().unwrap())
        .ok_or(ExecutionError::MalformedRequest(
            "missing X-GitHub-Event header",
        ))?;

    Ok((
        event.to_string(),
        signature.to_string(),
        request.into_body(),
    ))
}
