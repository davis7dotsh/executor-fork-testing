use std::{collections::VecDeque, convert::Infallible, sync::Arc};

use serde_json::json;
use tokio::sync::{Barrier, Mutex};

use super::*;
use crate::{
    AppConfig, ExecutorApp,
    catalog::{
        AuditContext, CatalogError, CreateSource, CredentialPayload, ListToolsFilter, SourceKind,
        ToolBinding,
    },
};

struct Fetcher {
    pages: VecDeque<ToolPage>,
    cursors: Vec<Option<String>>,
}

struct FailingFetcher {
    calls: usize,
}

#[async_trait]
impl ToolPageFetcher for FailingFetcher {
    type Error = std::io::Error;

    async fn fetch_tools_page(&mut self, _cursor: Option<&str>) -> Result<ToolPage, Self::Error> {
        self.calls += 1;
        if self.calls == 1 {
            Ok(ToolPage {
                tools: vec![tool("partial")],
                next_cursor: Some("next".to_owned()),
            })
        } else {
            Err(std::io::Error::other("transient upstream failure"))
        }
    }
}

#[async_trait]
impl ToolPageFetcher for Fetcher {
    type Error = Infallible;

    async fn fetch_tools_page(&mut self, cursor: Option<&str>) -> Result<ToolPage, Self::Error> {
        self.cursors.push(cursor.map(str::to_owned));
        Ok(self.pages.pop_front().expect("test page exists"))
    }
}

fn basis() -> DiscoveryBasis {
    DiscoveryBasis {
        expected_source_revision: 7,
        expected_credential_revision: Some(3),
        protocol_version: "2025-11-25".to_owned(),
        server_name: "fixture".to_owned(),
        server_version: "1.2.3".to_owned(),
        server_title: Some("Fixture server".to_owned()),
        instructions: None,
        capabilities: json!({ "tools": { "listChanged": true } }),
        tools_list_changed: true,
    }
}

fn tool(name: &str) -> DiscoveredMcpTool {
    DiscoveredMcpTool {
        name: name.to_owned(),
        title: None,
        description: Some(format!("Run {name}")),
        input_schema: json!({ "type": "object", "properties": {} }),
        output_schema: None,
        annotations: None,
        meta: Map::new(),
    }
}

fn read_only_tool(name: &str) -> DiscoveredMcpTool {
    DiscoveredMcpTool {
        annotations: Some(McpToolAnnotations {
            read_only_hint: Some(true),
            destructive_hint: Some(false),
            ..McpToolAnnotations::default()
        }),
        ..tool(name)
    }
}

#[tokio::test]
async fn pages_all_tools_before_returning_an_atomic_stable_plan() {
    let mut fetcher = Fetcher {
        pages: VecDeque::from([
            ToolPage {
                tools: vec![tool("zeta")],
                next_cursor: Some("page-2".to_owned()),
            },
            ToolPage {
                tools: vec![read_only_tool("alpha")],
                next_cursor: None,
            },
        ]),
        cursors: Vec::new(),
    };
    let plan = discover(&mut fetcher, basis())
        .await
        .expect("discovery succeeds");

    assert_eq!(fetcher.cursors, [None, Some("page-2".to_owned())]);
    assert_eq!(
        plan.tools
            .iter()
            .map(|tool| tool.stable_key.as_str())
            .collect::<Vec<_>>(),
        ["alpha", "zeta"]
    );
    assert_eq!(plan.catalog_snapshot().expected_source_revision, 7);
    assert_eq!(
        plan.catalog_snapshot().expected_credential_revision,
        Some(3)
    );
    assert_eq!(plan.artifacts[0].kind, ArtifactKind::McpCapabilities);
    assert_eq!(plan.tools[0].stable_key, "alpha");
    assert_eq!(plan.tools[0].intrinsic_mode, ToolMode::Enabled);
    assert_eq!(plan.tools[1].stable_key, "zeta");
    assert_eq!(plan.tools[1].intrinsic_mode, ToolMode::Ask);
    assert!(plan.bindings.iter().all(|binding| matches!(
        &binding.binding,
        ToolBinding::McpHttpV1(definition) if definition.tool_name == binding.stable_key
    )));
}

#[tokio::test]
async fn exact_name_is_identity_across_reordering_and_stdio_conversion() {
    let page = |tools| Fetcher {
        pages: VecDeque::from([ToolPage {
            tools,
            next_cursor: None,
        }]),
        cursors: Vec::new(),
    };
    let mut first = page(vec![tool("a.b"), tool("a-b")]);
    let mut second = page(vec![tool("a-b"), tool("a.b")]);
    let first = discover(&mut first, basis()).await.unwrap();
    let second = bindings_for_source_kind(discover(&mut second, basis()).await.unwrap(), true);
    assert_eq!(
        first
            .tools
            .iter()
            .map(|tool| &tool.stable_key)
            .collect::<Vec<_>>(),
        second
            .tools
            .iter()
            .map(|tool| &tool.stable_key)
            .collect::<Vec<_>>()
    );
    assert!(
        second
            .bindings
            .iter()
            .all(|binding| matches!(binding.binding, ToolBinding::McpStdioV1(_)))
    );
}

#[tokio::test]
async fn destructive_annotations_choose_conservative_intrinsic_modes() {
    let mut destructive = tool("destructive");
    destructive.annotations = Some(McpToolAnnotations {
        read_only_hint: Some(true),
        destructive_hint: Some(true),
        ..McpToolAnnotations::default()
    });
    let mut non_destructive = tool("non-destructive");
    non_destructive.annotations = Some(McpToolAnnotations {
        destructive_hint: Some(false),
        ..McpToolAnnotations::default()
    });
    let mut fetcher = Fetcher {
        pages: VecDeque::from([ToolPage {
            tools: vec![
                destructive,
                non_destructive,
                tool("unspecified"),
                read_only_tool("safe"),
            ],
            next_cursor: None,
        }]),
        cursors: Vec::new(),
    };
    let plan = discover(&mut fetcher, basis()).await.unwrap();
    let modes = plan
        .tools
        .iter()
        .map(|tool| (tool.stable_key.as_str(), tool.intrinsic_mode))
        .collect::<Vec<_>>();
    assert_eq!(
        modes,
        [
            ("destructive", ToolMode::Ask),
            ("non-destructive", ToolMode::Ask),
            ("safe", ToolMode::Enabled),
            ("unspecified", ToolMode::Ask),
        ]
    );
}

#[tokio::test]
async fn rejects_cursor_cycles_duplicates_invalid_schemas_and_limits_without_partial_plan() {
    let mut failed = FailingFetcher { calls: 0 };
    assert!(matches!(
        discover(&mut failed, basis()).await,
        Err(DiscoveryError::Fetch(_))
    ));

    let mut cycle = Fetcher {
        pages: VecDeque::from([
            ToolPage {
                tools: vec![],
                next_cursor: Some("again".to_owned()),
            },
            ToolPage {
                tools: vec![],
                next_cursor: Some("again".to_owned()),
            },
        ]),
        cursors: Vec::new(),
    };
    assert!(matches!(
        discover(&mut cycle, basis()).await,
        Err(DiscoveryError::CursorCycle)
    ));

    let mut duplicates = Fetcher {
        pages: VecDeque::from([ToolPage {
            tools: vec![tool("same"), tool("same")],
            next_cursor: None,
        }]),
        cursors: Vec::new(),
    };
    assert!(matches!(
        discover(&mut duplicates, basis()).await,
        Err(DiscoveryError::DuplicateTool { .. })
    ));

    let mut invalid = tool("invalid");
    invalid.input_schema = json!(true);
    let mut invalid = Fetcher {
        pages: VecDeque::from([ToolPage {
            tools: vec![invalid],
            next_cursor: None,
        }]),
        cursors: Vec::new(),
    };
    assert!(matches!(
        discover(&mut invalid, basis()).await,
        Err(DiscoveryError::InvalidTool { .. })
    ));

    let mut limited = Fetcher {
        pages: VecDeque::from([ToolPage {
            tools: vec![tool("one"), tool("two")],
            next_cursor: None,
        }]),
        cursors: Vec::new(),
    };
    let limits = DiscoveryLimits {
        max_tools: 1,
        ..DiscoveryLimits::default()
    };
    assert!(matches!(
        discover_with_limits(&mut limited, basis(), limits).await,
        Err(DiscoveryError::TooManyTools { maximum: 1 })
    ));

    let mut variant = tool("schema-variants");
    variant.title = Some(String::new());
    variant.description = Some(String::new());
    variant.annotations = Some(McpToolAnnotations {
        title: Some(String::new()),
        ..McpToolAnnotations::default()
    });
    variant.input_schema = json!({});
    variant.output_schema = Some(json!({ "allOf": [{ "type": "object" }] }));
    let mut schema_variants = Fetcher {
        pages: VecDeque::from([ToolPage {
            tools: vec![variant],
            next_cursor: None,
        }]),
        cursors: Vec::new(),
    };
    let normalized = discover(&mut schema_variants, basis())
        .await
        .expect("object schemas need not declare type at the root");
    assert_eq!(normalized.tools[0].display_name, "schema-variants");
    assert_eq!(normalized.tools[0].description, None);
}

#[tokio::test]
async fn list_changed_bursts_coalesce_and_failed_refresh_remains_pending() {
    let coalescer = ListChangedCoalescer::default();
    assert!(coalescer.notify_changed());
    let started = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let calls = Arc::new(Mutex::new(0usize));
    let runner = {
        let coalescer = coalescer.clone();
        let started = started.clone();
        let release = release.clone();
        let calls = calls.clone();
        tokio::spawn(async move {
            coalescer
                .refresh_pending(|| {
                    let started = started.clone();
                    let release = release.clone();
                    let calls = calls.clone();
                    async move {
                        let mut count = calls.lock().await;
                        *count += 1;
                        let first = *count == 1;
                        drop(count);
                        if first {
                            started.wait().await;
                            release.wait().await;
                        }
                        Ok::<_, &'static str>(())
                    }
                })
                .await
        })
    };
    started.wait().await;
    for _ in 0..20 {
        assert!(!coalescer.notify_changed());
    }
    release.wait().await;
    assert_eq!(runner.await.unwrap().unwrap(), 2);
    assert_eq!(*calls.lock().await, 2);

    assert!(coalescer.notify_changed());
    assert_eq!(
        coalescer
            .refresh_pending(|| async { Err::<(), _>("transient") })
            .await,
        Err("transient")
    );
    assert!(coalescer.has_pending());
    assert_eq!(
        coalescer
            .refresh_pending(|| async { Ok::<_, &'static str>(()) })
            .await
            .unwrap(),
        1
    );
    assert!(!coalescer.has_pending());
}

#[tokio::test]
async fn catalog_commit_is_atomic_cas_guarded_and_preserves_tombstone_identity() {
    let directory = tempfile::tempdir().unwrap();
    let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
        .await
        .unwrap();
    let mut initial_fetcher = Fetcher {
        pages: VecDeque::from([ToolPage {
            tools: vec![tool("alpha"), tool("beta")],
            next_cursor: None,
        }]),
        cursors: Vec::new(),
    };
    let initial = discover(&mut initial_fetcher, basis()).await.unwrap();
    let (source, _) = app
        .catalog()
        .create_source_with_catalog(
            CreateSource {
                kind: SourceKind::McpHttp,
                preferred_slug: "mcp-fixture".to_owned(),
                display_name: "MCP fixture".to_owned(),
                description: None,
                configuration: Map::new(),
            },
            &CredentialPayload {
                schema_version: 1,
                payload: json!({}),
            },
            initial.initial_catalog_snapshot(),
            initial.bindings,
            AuditContext::system(Some("mcp-create")),
        )
        .await
        .unwrap();
    let mut wrong_kind_fetcher = Fetcher {
        pages: VecDeque::from([ToolPage {
            tools: vec![tool("alpha"), tool("beta")],
            next_cursor: None,
        }]),
        cursors: Vec::new(),
    };
    let mut wrong_kind_basis = basis();
    wrong_kind_basis.expected_source_revision = source.revision;
    wrong_kind_basis.expected_credential_revision = Some(0);
    let wrong_kind = bindings_for_source_kind(
        discover(&mut wrong_kind_fetcher, wrong_kind_basis)
            .await
            .unwrap(),
        true,
    );
    assert!(matches!(
        app.catalog()
            .sync_catalog_with_bindings(
                &source.id,
                wrong_kind.catalog_snapshot(),
                wrong_kind.bindings,
                AuditContext::system(Some("mcp-wrong-kind")),
            )
            .await,
        Err(CatalogError::Validation {
            code: "invalid_source_kind",
            ..
        })
    ));
    assert_eq!(
        app.catalog().source(&source.id).await.unwrap().revision,
        source.revision
    );
    let mut mismatched_fetcher = Fetcher {
        pages: VecDeque::from([ToolPage {
            tools: vec![tool("alpha"), tool("beta")],
            next_cursor: None,
        }]),
        cursors: Vec::new(),
    };
    let mut mismatch_basis = basis();
    mismatch_basis.expected_source_revision = source.revision;
    mismatch_basis.expected_credential_revision = Some(0);
    let mut mismatched = discover(&mut mismatched_fetcher, mismatch_basis)
        .await
        .unwrap();
    let ToolBinding::McpHttpV1(definition) = &mut mismatched.bindings[0].binding else {
        panic!("HTTP discovery creates HTTP bindings")
    };
    definition.tool_name = "another-upstream-tool".to_owned();
    assert!(matches!(
        app.catalog()
            .sync_catalog_with_bindings(
                &source.id,
                mismatched.catalog_snapshot(),
                mismatched.bindings,
                AuditContext::system(Some("mcp-mismatched-name")),
            )
            .await,
        Err(CatalogError::Validation {
            code: "invalid_tool_binding",
            ..
        })
    ));
    let initial_page = app
        .catalog()
        .list_tools(ListToolsFilter {
            source_id: Some(source.id.clone()),
            include_tombstoned: true,
            limit: 100,
            ..ListToolsFilter::default()
        })
        .await
        .unwrap();
    let beta_id = initial_page
        .items
        .iter()
        .find(|tool| tool.stable_key == "beta")
        .unwrap()
        .id
        .clone();

    let mut refresh_basis = basis();
    refresh_basis.expected_source_revision = source.revision;
    refresh_basis.expected_credential_revision = Some(0);
    let mut removed_fetcher = Fetcher {
        pages: VecDeque::from([ToolPage {
            tools: vec![tool("alpha")],
            next_cursor: None,
        }]),
        cursors: Vec::new(),
    };
    let removed = discover(&mut removed_fetcher, refresh_basis).await.unwrap();
    app.catalog()
        .sync_catalog_with_bindings(
            &source.id,
            removed.catalog_snapshot(),
            removed.bindings.clone(),
            AuditContext::system(Some("mcp-remove")),
        )
        .await
        .unwrap();
    let stale_error = app
        .catalog()
        .sync_catalog_with_bindings(
            &source.id,
            removed.catalog_snapshot(),
            removed.bindings,
            AuditContext::system(Some("mcp-stale")),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        stale_error,
        CatalogError::RevisionConflict {
            scope: "source",
            ..
        }
    ));
    let tombstoned_page = app
        .catalog()
        .list_tools(ListToolsFilter {
            source_id: Some(source.id.clone()),
            include_tombstoned: true,
            limit: 100,
            ..ListToolsFilter::default()
        })
        .await
        .unwrap();
    let tombstoned = tombstoned_page
        .items
        .iter()
        .find(|tool| tool.stable_key == "beta")
        .unwrap();
    assert_eq!(tombstoned.id, beta_id);
    assert!(!tombstoned.present);

    let refreshed_source = app.catalog().source(&source.id).await.unwrap();
    let mut restore_basis = basis();
    restore_basis.expected_source_revision = refreshed_source.revision;
    restore_basis.expected_credential_revision = Some(0);
    let mut restore_fetcher = Fetcher {
        pages: VecDeque::from([ToolPage {
            tools: vec![tool("beta"), tool("alpha")],
            next_cursor: None,
        }]),
        cursors: Vec::new(),
    };
    let restored = discover(&mut restore_fetcher, restore_basis).await.unwrap();
    app.catalog()
        .sync_catalog_with_bindings(
            &source.id,
            restored.catalog_snapshot(),
            restored.bindings,
            AuditContext::system(Some("mcp-restore")),
        )
        .await
        .unwrap();
    let restored_page = app
        .catalog()
        .list_tools(ListToolsFilter {
            source_id: Some(source.id),
            include_tombstoned: true,
            limit: 100,
            ..ListToolsFilter::default()
        })
        .await
        .unwrap();
    let restored_beta = restored_page
        .items
        .iter()
        .find(|tool| tool.stable_key == "beta")
        .unwrap();
    assert_eq!(restored_beta.id, beta_id);
    assert!(restored_beta.present);
}
