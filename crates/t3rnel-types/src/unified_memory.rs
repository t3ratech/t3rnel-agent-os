use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug)]
pub struct AccessContext {
    agent_id: String,
    team_ids: Vec<String>,
    project_ids: Vec<String>,
    session_id: Option<String>,
    global_write: bool,
}

impl AccessContext {
    pub fn for_agent(agent_id: impl Into<String>) -> Self {
        Self {
            agent_id: agent_id.into(),
            team_ids: Vec::new(),
            project_ids: Vec::new(),
            session_id: None,
            global_write: false,
        }
    }

    pub fn with_global_write(mut self) -> Self {
        self.global_write = true;
        self
    }

    pub fn can_write_global(&self) -> bool {
        self.global_write
    }

    pub fn with_verified_memberships(
        mut self,
        team_ids: Vec<String>,
        project_ids: Vec<String>,
    ) -> Self {
        self.team_ids = team_ids;
        self.project_ids = project_ids;
        self
    }

    pub fn with_session(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    pub fn team_ids(&self) -> &[String] {
        &self.team_ids
    }

    pub fn project_ids(&self) -> &[String] {
        &self.project_ids
    }

    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MemoryKind {
    #[default]
    Fact,
    Lesson,
    Decision,
    TaskOutcome,
    Episode,
    Preference,
    Handover,
    MarketIntel,
    Codefact,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RetentionClass {
    Durable,
    Session,
    TimeSensitive,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MemoryStatus {
    /// Live belief eligible for recall.
    #[default]
    Active,
    /// Retired by a policy rule or explicit call; still recallable with its stamp.
    Expired,
    /// Replaced by a newer belief; the archived body stays queryable as-of.
    Superseded,
}

impl MemoryStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Expired => "expired",
            Self::Superseded => "superseded",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "expired" => Some(Self::Expired),
            "superseded" => Some(Self::Superseded),
            _ => None,
        }
    }
}

impl MemoryKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fact => "fact",
            Self::Lesson => "lesson",
            Self::Decision => "decision",
            Self::TaskOutcome => "task_outcome",
            Self::Episode => "episode",
            Self::Preference => "preference",
            Self::Handover => "handover",
            Self::MarketIntel => "market_intel",
            Self::Codefact => "codefact",
        }
    }

    pub fn retention(self) -> RetentionClass {
        match self {
            Self::Episode | Self::Handover => RetentionClass::Session,
            Self::MarketIntel => RetentionClass::TimeSensitive,
            _ => RetentionClass::Durable,
        }
    }

    pub fn recall_weight(self) -> f32 {
        match self {
            Self::Lesson | Self::Decision | Self::Handover => 1.2,
            Self::Episode => 0.7,
            Self::MarketIntel => 0.9,
            _ => 1.0,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MemoryVisibility {
    #[default]
    Private,
    Team,
    Project,
    Global,
}

impl MemoryVisibility {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Private => "private",
            Self::Team => "team",
            Self::Project => "project",
            Self::Global => "global",
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct MemoryScope {
    pub visibility: MemoryVisibility,
    pub team_id: Option<String>,
    pub project_id: Option<String>,
    pub session_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct MemoryProvenance {
    pub source: String,
    pub source_id: Option<String>,
    pub evidence: Vec<String>,
}

impl Default for MemoryProvenance {
    fn default() -> Self {
        Self {
            source: "agent".into(),
            source_id: None,
            evidence: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RememberRequest {
    pub kind: MemoryKind,
    pub scope: MemoryScope,
    pub key: Option<String>,
    pub content: String,
    pub summary: Option<String>,
    pub confidence: f32,
    pub provenance: MemoryProvenance,
    pub metadata: serde_json::Value,
    /// Record id this write replaces; the target is archived as superseded.
    pub supersedes: Option<String>,
    /// When the claim became true in the world (defaults to record time).
    pub valid_from: Option<DateTime<Utc>>,
    /// When the claim stops being true; an open claim carries none.
    pub valid_to: Option<DateTime<Utc>>,
}

impl Default for RememberRequest {
    fn default() -> Self {
        Self {
            kind: MemoryKind::Fact,
            scope: MemoryScope::default(),
            key: None,
            content: String::new(),
            summary: None,
            confidence: 1.0,
            provenance: MemoryProvenance::default(),
            metadata: serde_json::json!({}),
            supersedes: None,
            valid_from: None,
            valid_to: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MemoryDepth {
    Index,
    #[default]
    Summary,
    Full,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MemoryBudget {
    pub max_tokens: usize,
    pub max_bytes: usize,
}

impl Default for MemoryBudget {
    fn default() -> Self {
        Self {
            max_tokens: 2048,
            max_bytes: 8192,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MemoryQuery {
    pub text: String,
    pub kind: Option<MemoryKind>,
    pub scope: Option<MemoryScope>,
    pub depth: MemoryDepth,
    pub budget: MemoryBudget,
    pub limit: usize,
    pub offset: usize,
    /// Restrict to a stable key (e.g. one handover bucket).
    pub key: Option<String>,
    /// Restrict to keys sharing a prefix (e.g. `security:` for the findings
    /// intake queue). Exact `key` wins when both are set.
    pub key_prefix: Option<String>,
    /// Point-in-time recall: only versions recorded at or before this instant.
    pub as_of: Option<DateTime<Utc>>,
    /// Also return expired and superseded records with their stamps.
    pub include_inactive: bool,
}

impl Default for MemoryQuery {
    fn default() -> Self {
        Self {
            text: String::new(),
            kind: None,
            scope: None,
            depth: MemoryDepth::Summary,
            budget: MemoryBudget::default(),
            limit: 20,
            offset: 0,
            key: None,
            key_prefix: None,
            as_of: None,
            include_inactive: false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct MemoryRecord {
    pub id: String,
    pub uri: String,
    pub agent_id: String,
    pub kind: MemoryKind,
    pub scope: MemoryScope,
    pub key: Option<String>,
    pub content: String,
    pub summary: String,
    pub confidence: f32,
    pub provenance: MemoryProvenance,
    pub metadata: serde_json::Value,
    pub retention: RetentionClass,
    pub recall_weight: f32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub depth: MemoryDepth,
    pub truncated: bool,
    pub revision: u64,
    #[serde(default)]
    pub status: MemoryStatus,
    /// When the claim became true in the world.
    #[serde(default)]
    pub valid_from: Option<DateTime<Utc>>,
    /// When the claim ceased to be true (exclusive); open when absent.
    #[serde(default)]
    pub valid_to: Option<DateTime<Utc>>,
    /// When this version was recorded; equals updated_at on the live row.
    #[serde(default)]
    pub recorded_from: Option<DateTime<Utc>>,
    /// When this version was superseded or deleted; absent while current.
    #[serde(default)]
    pub recorded_to: Option<DateTime<Utc>>,
    /// Rule or caller that expired the record.
    #[serde(default)]
    pub expired_by: Option<String>,
    /// Id of the record this one replaced.
    #[serde(default)]
    pub supersedes: Option<String>,
}

pub fn tool_definitions() -> Vec<crate::tool::ToolDefinition> {
    use serde_json::json;
    let scope = json!({"type":"object","description":"Scope within the caller's verified memberships; omitted means the daemon project","additionalProperties":false,"properties":{
        "visibility":{"type":"string","enum":["private","team","project","global"],"description":"Who may read the record"},
        "team_id":{"type":"string","description":"Verified team identifier"},
        "project_id":{"type":"string","description":"Verified project identifier"},
        "session_id":{"type":"string","description":"Current session identifier"}
    }});
    let query = json!({"type":"object","additionalProperties":false,"properties":{
        "text":{"type":"string","maxLength":1024,"description":"Full-text query; empty lists recent records"},
        "kind":{"type":"string","enum":["fact","lesson","decision","task_outcome","episode","preference","handover","market_intel","codefact"],"description":"Record kind filter"},
        "scope":scope,
        "depth":{"type":"string","enum":["index","summary","full"],"default":"summary","description":"Disclosure level; use get for a full record"},
        "limit":{"type":"integer","minimum":0,"maximum":100,"default":20,"description":"Maximum result count"},
        "offset":{"type":"integer","minimum":0,"maximum":10000,"description":"Result offset"},
        "key":{"type":"string","maxLength":200,"description":"Stable key filter (e.g. one handover bucket)"},
        "as_of":{"type":"string","format":"date-time","description":"Recall what was believed at this instant"},
        "include_inactive":{"type":"boolean","default":false,"description":"Include expired and superseded records with their stamps"},
        "budget":{"type":"object","additionalProperties":false,"description":"Complete record-array byte budget and conservative token upper bound","properties":{
            "max_tokens":{"type":"integer","minimum":0,"maximum":65536,"default":2048,"description":"Conservative byte-based token ceiling"},
            "max_bytes":{"type":"integer","minimum":0,"maximum":65536,"default":8192,"description":"Serialized record byte ceiling"}
        }}
    }});
    let mut tools: Vec<_> = [
        (
            "memory_search",
            "Search scoped memory with a bounded summary response",
        ),
        (
            "memory_ls",
            "List scoped memory references without record bodies",
        ),
        (
            "memory_handover",
            "Read the latest scoped handover and whether newer context makes it stale; pass key for one bucket",
        ),
        (
            "memory_brief",
            "Assemble a salience-ranked briefing: handover, lessons, decisions and recent outcomes within budget",
        ),
    ]
    .into_iter()
    .map(|(name, description)| crate::tool::ToolDefinition {
        name: name.into(),
        description: description.into(),
        input_schema: query.clone(),
    })
    .collect();
    tools.push(crate::tool::ToolDefinition { name:"memory_get".into(),description:"Read a permitted full record by UUID or t3rnel URI".into(),input_schema:json!({"type":"object","additionalProperties":false,"required":["id"],"properties":{"id":{"type":"string","description":"Record UUID or t3rnel URI returned by search"}}}) });
    tools.push(crate::tool::ToolDefinition { name:"memory_remember".into(),description:"Store a deduplicated scoped fact, lesson, decision or handover; secrets are refused".into(),input_schema:json!({"type":"object","additionalProperties":false,"required":["content"],"properties":{
        "content":{"type":"string","minLength":1,"maxLength":32768,"description":"Evidence-backed memory content without credentials"},
        "summary":{"type":"string","maxLength":2048,"description":"Compact continuation summary"},
        "kind":query["properties"]["kind"],"scope":scope,
        "key":{"type":"string","maxLength":200,"description":"Optional stable key; repeated writes update this record"},
        "confidence":{"type":"number","minimum":0,"maximum":1,"description":"Confidence in the recorded observation"},
        "supersedes":{"type":"string","description":"Record id this belief replaces; the target is archived as superseded"},
        "valid_from":{"type":"string","format":"date-time","description":"When the claim became true (defaults to now)"},
        "valid_to":{"type":"string","format":"date-time","description":"When the claim stops being true"},
        "metadata":{"type":"object","description":"Non-secret structured attributes"},
        "provenance":{"type":"object","additionalProperties":false,"description":"Origin and supporting evidence","properties":{
            "source":{"type":"string","description":"Source category"},"source_id":{"type":"string","description":"Source identifier"},"evidence":{"type":"array","items":{"type":"string"},"description":"Supporting evidence references"}
        }}
    }}) });
    tools.push(crate::tool::ToolDefinition { name:"memory_supersede".into(),description:"Replace a record's belief, archiving the prior body so as-of recall still answers what was believed".into(),input_schema:json!({"type":"object","additionalProperties":false,"required":["id","content"],"properties":{
        "id":{"type":"string","description":"Record UUID or t3rnel URI to supersede"},
        "content":{"type":"string","minLength":1,"maxLength":32768,"description":"Replacement belief"},
        "summary":{"type":"string","maxLength":2048,"description":"Compact continuation summary"},
        "reason":{"type":"string","maxLength":200,"description":"Why the prior belief is superseded"}
    }}) });
    tools.push(crate::tool::ToolDefinition { name:"memory_expire".into(),description:"Retire a record under a named reason; expired records still recall with their stamp".into(),input_schema:json!({"type":"object","additionalProperties":false,"required":["id"],"properties":{
        "id":{"type":"string","description":"Record UUID or t3rnel URI to expire"},
        "reason":{"type":"string","maxLength":200,"description":"Audit reason stamped as expired_by"}
    }}) });
    tools.push(crate::tool::ToolDefinition { name:"memory_restore".into(),description:"Return an expired record to active".into(),input_schema:json!({"type":"object","additionalProperties":false,"required":["id"],"properties":{
        "id":{"type":"string","description":"Record UUID or t3rnel URI to restore"}
    }}) });
    tools.push(crate::tool::ToolDefinition { name:"memory_history".into(),description:"Read the full version chain of one record, oldest first".into(),input_schema:json!({"type":"object","additionalProperties":false,"required":["id"],"properties":{
        "id":{"type":"string","description":"Record UUID or t3rnel URI"}
    }}) });
    tools.push(crate::tool::ToolDefinition { name:"memory_events".into(),description:"Tail the scoped memory event feed since a sequence cursor".into(),input_schema:json!({"type":"object","additionalProperties":false,"properties":{
        "since":{"type":"integer","minimum":0,"default":0,"description":"Sequence cursor; only events after it are returned"},
        "limit":{"type":"integer","minimum":1,"maximum":1000,"default":100}
    }}) });
    tools.push(crate::tool::ToolDefinition { name:"memory_conflicts".into(),description:"List likely contradictions among active records in scope for review".into(),input_schema:json!({"type":"object","additionalProperties":false,"properties":{
        "limit":{"type":"integer","minimum":1,"maximum":100,"default":20}
    }}) });
    tools
}

pub type UnifiedRememberRequest = RememberRequest;
pub type UnifiedMemoryQuery = MemoryQuery;
pub type UnifiedMemoryRecord = MemoryRecord;
