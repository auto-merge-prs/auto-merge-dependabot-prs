//! Copyright (c) 2025 Martin Nordholts
//!
//! This Source Code Form is subject to the terms of the Mozilla Public
//! License, v. 2.0. If a copy of the MPL was not distributed with this
//! file, You can obtain one at https://mozilla.org/MPL/2.0/.

use graphql_client::GraphQLQuery;
use lambda_http::{
    IntoResponse, Request, service_fn,
    tracing::{self, info},
};
use lambda_runtime::Diagnostic;
use octocrab::{
    Octocrab,
    models::{
        AppId, InstallationId, UserId,
        webhook_events::{
            WebhookEvent, WebhookEventPayload, payload::PullRequestWebhookEventAction,
        },
    },
};
use reqwest::StatusCode;
use serde_json::Value;

mod signature;

#[derive(PartialEq, Eq, Debug)]
enum Sender {
    GitHub,
    Unknown,
}

#[derive(Debug, serde::Serialize, PartialEq)]
enum Outcome {
    /// Auto-merge was enabled!
    EnabledAutoMerge,

    /// Auto-merge was not enabled. Event was not for an opened PR.
    NotOpenedPr,

    /// Auto-merge was not enabled. PR not opened by dependabot.
    NotOpenedByDependabotBut {
        name: Option<String>,
        id: Option<UserId>,
    },

    /// Auto-merge was not enabled. Possibly malicious actor tries to hack us.
    NotSentByGitHub,

    /// Auto-merge was not enabled. Some kind of server error happened. Reduce
    /// risk of accidentally leaking secrets because of programmer error by only
    /// allowing static strings.
    MissingEnvVar(&'static str),
    MissingHeader(&'static str),
    MissingSecret(&'static str),
    MissingSecretJson(&'static str),
    MissingInstallationId(Option<InstallationId>),
    GraphQlError(String),
    InvalidBody,
}

#[derive(Debug)]
enum Error {
    /// HTTP 400
    ClientError(Outcome),
    /// HTTP 500
    ServerError(Outcome),
}

type OutcomeResult = Result<Outcome, Error>;

#[tokio::main]
async fn main() -> Result<(), lambda_http::Error> {
    tracing::init_default_subscriber();

    lambda_http::run(service_fn(handle_event)).await
}

// Put all error info in the response visible at
// https://github.com/settings/apps/auto-merge-dependabot-prs/advanced
// to avoid need to look at AWS logs. If we return an error the body
// will not be shown there.
async fn handle_event(request: Request) -> Result<impl IntoResponse, Error> {
    let (code, outcome) = match handle_possible_webhook_event(request).await {
        Ok(outcome) => (
            if outcome == Outcome::EnabledAutoMerge {
                StatusCode::OK
            } else {
                StatusCode::PRECONDITION_FAILED
            },
            outcome,
        ),
        Err(Error::ClientError(outcome)) => (StatusCode::BAD_REQUEST, outcome),
        Err(Error::ServerError(outcome)) => (StatusCode::INTERNAL_SERVER_ERROR, outcome),
    };

    Ok((code, serde_json::to_string(&outcome).unwrap()))
}

async fn handle_possible_webhook_event(request: Request) -> Result<Outcome, Error> {
    // Ensure this an Opened event of a PR.
    let event = extract_header(&request, "X-GitHub-Event")?;
    let webhook_event = WebhookEvent::try_from_header_and_body(event, request.body())
        .map_err(|_| Error::ClientError(Outcome::InvalidBody))?;
    let Some(pr_id) = pr_id_of_event(&webhook_event) else {
        return Ok(Outcome::NotOpenedPr);
    };

    // Ensure it was dependabot who opened the PR.
    let sender_login: Option<String> = webhook_event.sender.clone().map(|s| s.login);
    let sender_id: Option<UserId> = webhook_event.sender.clone().map(|s| s.id);
    if !is_dependabot(sender_login.clone(), sender_id.clone())? {
        return Ok(Outcome::NotOpenedByDependabotBut {
            name: sender_login,
            id: sender_id,
        });
    }

    // Ensure the event was actually sent by GitHub and not by a malicious
    // actor. Do this as late as possible since it requires obtaing a secret
    // from AWS, and each such request carries a small cost.
    if event_sender(&request).await? != Sender::GitHub {
        return Ok(Outcome::NotSentByGitHub);
    }

    // Enable auto-merge because this PR is opened by dependabot.
    let octocrab = octocrab_for_installation(webhook_event.installation.map(|i| i.id())).await?;
    enable_pull_request_auto_merge(&octocrab, &pr_id).await?;
    announce_pull_request_auto_merge(&octocrab, &pr_id).await
}

async fn octocrab_for_installation(id: Option<InstallationId>) -> Result<Octocrab, Error> {
    let Some(id) = id else {
        return Err(Error::ServerError(Outcome::MissingInstallationId(id)));
    };

    let app_id = get_required_env_var("AUTO_MERGE_DEPENDABOT_PRS_GITHUB_APP_ID")?;
    let private_key = get_secret("AUTO_MERGE_DEPENDABOT_PRS_PRIVATE_KEY_SECRET_ID").await?;
    let jwt_key = jsonwebtoken::EncodingKey::from_rsa_pem(private_key.as_bytes()).unwrap();
    Octocrab::builder()
        .app(AppId(app_id.parse().unwrap()), jwt_key)
        .build()
        .unwrap()
        .installation(id)
        .map_err(|_| Error::ServerError(Outcome::MissingInstallationId(Some(id))))
}

async fn enable_pull_request_auto_merge(octocrab: &Octocrab, pr_id: &str) -> Result<(), Error> {
    #[derive(graphql_client::GraphQLQuery)]
    #[graphql(
        schema_path = "src/graphql/github_schema.graphql",
        query_path = "src/graphql/enable_pull_request_auto_merge.graphql"
    )]
    pub struct EnablePullRequestAutoMerge;

    let variables = enable_pull_request_auto_merge::Variables {
        id: pr_id.to_string(),
    };

    let response: graphql_client::Response<enable_pull_request_auto_merge::ResponseData> = octocrab
        .graphql(&EnablePullRequestAutoMerge::build_query(variables))
        .await
        .map_err(|e| Error::ServerError(Outcome::GraphQlError(e.to_string())))?;
    let response_pr_id = response
        .data
        .and_then(|x| x.enable_pull_request_auto_merge)
        .and_then(|x| x.pull_request)
        .map(|x| x.id)
        .unwrap_or_default();
    if response_pr_id == pr_id {
        Ok(())
    } else {
        Err(Error::ServerError(Outcome::GraphQlError(format!(
            "PR id mismatch: `{}` != `{}`. Errors=`{:?}`",
            response_pr_id, pr_id, response.errors
        ))))
    }
}

async fn announce_pull_request_auto_merge(octocrab: &Octocrab, pr_id: &str) -> OutcomeResult {
    #[derive(graphql_client::GraphQLQuery)]
    #[graphql(
        schema_path = "src/graphql/github_schema.graphql",
        query_path = "src/graphql/add_comment.graphql"
    )]
    pub struct AddComment;

    let variables = add_comment::Variables {
        id: pr_id.to_string(),
        body: format!(
            "If CI passes, this dependabot PR will be [auto-merged](https://github.com/apps/auto-merge-dependabot-prs) 🚀"
        ),
    };

    let response: graphql_client::Response<add_comment::ResponseData> = octocrab
        .graphql(&AddComment::build_query(variables))
        .await
        .map_err(|e| Error::ServerError(Outcome::GraphQlError(e.to_string())))?;
    let response_pr_id = response
        .data
        .and_then(|x| x.add_comment)
        .and_then(|x| x.subject)
        .map(|x| x.id)
        .unwrap_or_default();
    if response_pr_id == pr_id {
        Ok(Outcome::EnabledAutoMerge)
    } else {
        // Examples of what the errors can look like:
        //
        //     Errors=`Some([Error { message: "Pull request Pull request is in clean status", locations: Some([Location { line: 2, column: 5 }]), path: Some([Key("enablePullRequestAutoMerge")]), extensions: None }])`
        //
        //     Errors=`Some([Error { message: "Pull request Auto merge is not allowed for this repository", locations: Some([Location { line: 2, column: 5 }]), path: Some([Key("enablePullRequestAutoMerge")]), extensions: None }])`
        //
        Err(Error::ServerError(Outcome::GraphQlError(format!(
            "PR id mismatch: `{}` != `{}`. Errors=`{:?}`",
            response_pr_id, pr_id, response.errors
        ))))
    }
}

fn is_dependabot(sender_login: Option<String>, sender_id: Option<UserId>) -> Result<bool, Error> {
    let dependabot = get_required_env_var("AUTO_MERGE_DEPENDABOT_PRS_DEPENDABOT_USER_NAME_AND_ID")?;
    let pr_author = format!(
        "{},{}",
        sender_login.unwrap_or_default(),
        sender_id.map(|id| id.0).unwrap_or_default(),
    );
    Ok(pr_author == dependabot)
}

async fn event_sender(request: &Request) -> Result<Sender, Error> {
    let signature = extract_header(&request, "X-Hub-Signature-256")?;
    let webhook_secret = get_secret("AUTO_MERGE_DEPENDABOT_PRS_WEBHOOK_SECRET_ID").await?;
    let body = request.body();
    Ok(
        match signature::verify_sha256(&signature, &webhook_secret, body) {
            signature::VerificationResult::Success => Sender::GitHub,
            signature::VerificationResult::Failure => Sender::Unknown,
        },
    )
}

fn extract_header<'a>(request: &'a Request, header_name: &'static str) -> Result<&'a str, Error> {
    request
        .headers()
        .get(header_name)
        .and_then(|h| h.to_str().ok())
        .ok_or(Error::ServerError(crate::Outcome::MissingHeader(
            header_name,
        )))
}

async fn get_secret(secret_id_env_var_name: &'static str) -> Result<String, Error> {
    let aws_session_token = get_required_env_var("AWS_SESSION_TOKEN")?;
    let secret_id = get_required_env_var(secret_id_env_var_name)?;

    let json = request_secret(aws_session_token, &secret_id)
        .await
        .map_err(|_| Error::ServerError(crate::Outcome::MissingSecret(secret_id_env_var_name)))?;

    json.get("SecretString")
        .and_then(|s| s.as_str())
        .map(ToString::to_string)
        .ok_or(Error::ServerError(crate::Outcome::MissingSecretJson(
            secret_id_env_var_name,
        )))
}

async fn request_secret(aws_session_token: String, secret_id: &str) -> reqwest::Result<Value> {
    let client = reqwest::Client::new();
    client
        .get(format!(
            "http://localhost:2773/secretsmanager/get?secretId={secret_id}"
        ))
        .header("X-Aws-Parameters-Secrets-Token", aws_session_token)
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
}

fn pr_id_of_event(webhook_event: &WebhookEvent) -> Option<String> {
    match &webhook_event.specific {
        WebhookEventPayload::PullRequest(pr)
            if pr.action == PullRequestWebhookEventAction::Opened =>
        {
            pr.pull_request.node_id.as_ref().map(|id| id.to_string())
        }
        _ => None,
    }
}

fn get_required_env_var(env_var_name: &'static str) -> Result<String, Error> {
    std::env::var(env_var_name)
        .map_err(|_| Error::ServerError(crate::Outcome::MissingEnvVar(env_var_name)))
}

impl From<Error> for Diagnostic {
    fn from(_: Error) -> Self {
        // To avoid having to look at AWS logs we transform all errors to
        // regular HTTP responses that can be seen at
        // https://github.com/settings/apps/auto-merge-dependabot-prs/advanced,
        // so we will never trigger this code path.
        unreachable!("Never triggered");
    }
}
