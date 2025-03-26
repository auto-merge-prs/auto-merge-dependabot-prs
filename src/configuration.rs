use octocrab::models::AppId;

pub struct Configuration {
    app_id: AppId,
}

impl Configuration {
    fn from_env() -> Self {
        Self {
            app_id: AppId(
                std::env::var("AUTO_MERGE_DEPENDABOT_PRS_GITHUB_APP_ID")
                    .unwrap()
                    .parse()
                    .unwrap(),
            ),
        }
    }
}
