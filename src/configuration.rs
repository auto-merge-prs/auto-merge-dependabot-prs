use octocrab::models::AppId;

pub struct Configuration {
    pub app_id: AppId,
}

impl Configuration {
    pub fn from_env() -> Self {
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
