use serde::Serialize;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorKind {
    ApiToken,
    Admin,
    System,
}

impl ActorKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ApiToken => "api_token",
            Self::Admin => "admin",
            Self::System => "system",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemActor {
    LocalCli,
}

impl SystemActor {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalCli => "local_cli",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ToolActor {
    ApiToken {
        id: String,
        name_snapshot: Option<String>,
    },
    Admin {
        id: i64,
    },
    System(SystemActor),
}

impl ToolActor {
    pub fn api_token(id: impl Into<String>, name_snapshot: Option<String>) -> Self {
        Self::ApiToken {
            id: id.into(),
            name_snapshot,
        }
    }

    pub const fn admin(id: i64) -> Self {
        Self::Admin { id }
    }

    pub const fn local_cli() -> Self {
        Self::System(SystemActor::LocalCli)
    }

    pub const fn kind(&self) -> ActorKind {
        match self {
            Self::ApiToken { .. } => ActorKind::ApiToken,
            Self::Admin { .. } => ActorKind::Admin,
            Self::System(_) => ActorKind::System,
        }
    }

    pub fn id(&self) -> String {
        match self {
            Self::ApiToken { id, .. } => id.clone(),
            Self::Admin { id } => id.to_string(),
            Self::System(actor) => actor.as_str().to_owned(),
        }
    }

    pub fn name_snapshot(&self) -> Option<&str> {
        match self {
            Self::ApiToken { name_snapshot, .. } => name_snapshot.as_deref(),
            Self::Admin { .. } | Self::System(_) => None,
        }
    }

    pub fn api_token_id(&self) -> Option<&str> {
        match self {
            Self::ApiToken { id, .. } => Some(id),
            Self::Admin { .. } | Self::System(_) => None,
        }
    }

    pub(crate) fn from_stored(
        kind: &str,
        id: String,
        api_token_id: Option<String>,
        name_snapshot: Option<String>,
    ) -> Option<Self> {
        match kind {
            "api_token" if api_token_id.as_deref() == Some(id.as_str()) => {
                Some(Self::ApiToken { id, name_snapshot })
            }
            "admin" if api_token_id.is_none() => id.parse().ok().map(|id| Self::Admin { id }),
            "system" if api_token_id.is_none() && id == SystemActor::LocalCli.as_str() => {
                Some(Self::System(SystemActor::LocalCli))
            }
            _ => None,
        }
    }
}
