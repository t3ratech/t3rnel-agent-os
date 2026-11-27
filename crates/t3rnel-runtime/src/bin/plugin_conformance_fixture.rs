//! Conformance fixture plugin.
//!
//! A real plugin program used to prove, with the real supervisor, sandbox, proxy
//! and dispatch, what a confined plugin can and cannot do. It is also the
//! smallest working example of a plugin: it finds its two inherited streams,
//! calls the host services over one and serves `PluginCallbacks` on the other.
//!
//! Behaviour is chosen by the text in `./mode` (the plugin's own `data/`
//! folder, which is its working directory):
//!
//! - `crash` — exit with an error at once (restart and quarantine tests);
//! - `hang` — never serve callbacks (start-up timeout test);
//! - `ok` — serve callbacks, answer health, then run the probes below and write
//!   the outcome to `./probe.json`.
//!
//! The probes are the things a malicious plugin would try:
//! a raw network connection, reading a file outside its folder, rewriting its
//! own installed files, finding a secret in its environment, asking the host to
//! make a request, and acting as a different plugin.

use std::io::Write;
use std::os::fd::FromRawFd;

use hyper_util::rt::TokioIo;
use t3rnel_runtime::plugin_grpc::pb;
use tonic::transport::{Endpoint, Uri};

fn fd_from_env(index: usize) -> Option<i32> {
    std::env::var("T3RNEL_HOST_STREAMS")
        .ok()?
        .split(',')
        .nth(index)?
        .parse()
        .ok()
}

fn stream_on(fd: i32) -> tokio::net::UnixStream {
    // SAFETY: the supervisor placed a connected stream at this descriptor and
    // nothing else in this process owns it.
    let std_stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
    std_stream.set_nonblocking(true).expect("nonblocking");
    tokio::net::UnixStream::from_std(std_stream).expect("tokio stream")
}

struct Callbacks {
    id: String,
}

#[tonic::async_trait]
impl pb::plugin_callbacks_server::PluginCallbacks for Callbacks {
    async fn health(
        &self,
        _: tonic::Request<pb::HealthRequest>,
    ) -> Result<tonic::Response<pb::HealthResponse>, tonic::Status> {
        Ok(tonic::Response::new(pb::HealthResponse {
            status: "ok".into(),
            detail: format!("fixture {}", self.id),
            active_tools: vec![],
            active_routes: vec![],
        }))
    }
    async fn call_tool(
        &self,
        _: tonic::Request<pb::ToolCallRequest>,
    ) -> Result<tonic::Response<pb::ToolCallResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("fixture has no tools"))
    }
    async fn handle_route(
        &self,
        _: tonic::Request<pb::RouteRequest>,
    ) -> Result<tonic::Response<pb::RouteResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("fixture has no routes"))
    }
    async fn schedule_tick(
        &self,
        request: tonic::Request<pb::ScheduleTickRequest>,
    ) -> Result<tonic::Response<pb::ScheduleTickResponse>, tonic::Status> {
        // Record every fire, one line each, so a test can count them.
        let job = request.into_inner().job_id;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open("ticks.log")
            .map_err(|e| tonic::Status::internal(e.to_string()))?;
        writeln!(f, "{job}").map_err(|e| tonic::Status::internal(e.to_string()))?;
        Ok(tonic::Response::new(pb::ScheduleTickResponse { status: "ok".into(), error: String::new() }))
    }
    async fn on_event(
        &self,
        _: tonic::Request<pb::EventDelivery>,
    ) -> Result<tonic::Response<pb::EventAck>, tonic::Status> {
        Err(tonic::Status::unimplemented("fixture has no events"))
    }
    async fn render_view(
        &self,
        _: tonic::Request<pb::ViewRequest>,
    ) -> Result<tonic::Response<pb::ViewResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("fixture has no views"))
    }
    async fn briefing_query(
        &self,
        _: tonic::Request<pb::BriefingQueryRequest>,
    ) -> Result<tonic::Response<pb::BriefingReport>, tonic::Status> {
        Err(tonic::Status::unimplemented("fixture has no briefing"))
    }
    async fn status_query(
        &self,
        _: tonic::Request<pb::StatusQueryRequest>,
    ) -> Result<tonic::Response<pb::StatusReport>, tonic::Status> {
        Err(tonic::Status::unimplemented("fixture has no status"))
    }
}

fn read_text(name: &str) -> Option<String> {
    std::fs::read_to_string(name).ok().map(|s| s.trim().to_string())
}

#[tokio::main]
async fn main() {
    let id = std::env::var("T3RNEL_PLUGIN_ID").unwrap_or_default();
    let mode = read_text("mode").unwrap_or_else(|| "ok".into());
    if mode == "crash" {
        eprintln!("fixture: crashing on purpose");
        std::process::exit(3);
    }
    let (Some(host_fd), Some(cb_fd)) = (fd_from_env(0), fd_from_env(1)) else {
        eprintln!("fixture: not started by the supervisor (no T3RNEL_HOST_STREAMS)");
        std::process::exit(2);
    };
    if mode == "hang" {
        // Holds its streams open and never serves: the supervisor must give up.
        let _keep = (stream_on(host_fd), stream_on(cb_fd));
        std::thread::sleep(std::time::Duration::from_secs(3600));
        return;
    }

    // `slow`: a real plugin boots before it serves (opens storage, registers
    // jobs), so the core's first call is already waiting when serving starts.
    if mode == "slow" {
        std::thread::sleep(std::time::Duration::from_millis(700));
    }
    // Serve PluginCallbacks on the callback stream.
    let cb_stream = stream_on(cb_fd);
    let server_id = id.clone();
    tokio::spawn(async move {
        let incoming = tokio_stream::iter([Ok::<_, std::io::Error>(cb_stream)]);
        let r = tonic::transport::Server::builder()
            .add_service(pb::plugin_callbacks_server::PluginCallbacksServer::new(
                Callbacks { id: server_id },
            ))
            .serve_with_incoming(incoming)
            .await;
        eprintln!("fixture: callbacks server ended: {r:?}");
    });

    // Host services client on the host stream.
    let slot = std::sync::Arc::new(std::sync::Mutex::new(Some(stream_on(host_fd))));
    let channel = Endpoint::try_from("http://host.invalid")
        .expect("endpoint")
        .connect_with_connector(tower::service_fn(move |_: Uri| {
            let slot = slot.clone();
            async move {
                let s = slot.lock().unwrap().take().ok_or_else(|| std::io::Error::other("used"))?;
                Ok::<_, std::io::Error>(TokioIo::new(s))
            }
        }))
        .await
        .expect("connect to the host stream");
    let me = pb::PluginIdentity { id: id.clone(), ..Default::default() };

    // ---- probes -------------------------------------------------------------------------------
    let mut probe = serde_json::Map::new();
    let mut put = |k: &str, v: serde_json::Value| {
        probe.insert(k.to_string(), v);
    };

    // 1. A raw connection must be impossible.
    let raw = std::net::TcpStream::connect(("127.0.0.1", 9));
    put("raw_socket_error", serde_json::json!(raw.err().map(|e| e.to_string())));
    let udp = std::net::UdpSocket::bind("127.0.0.1:0");
    put("udp_socket_error", serde_json::json!(udp.err().map(|e| e.to_string())));

    // 2. Files: outside its folder, and its own installed files.
    put("read_outside_error", serde_json::json!(std::fs::read("/etc/passwd").err().map(|e| e.to_string())));
    let manifest = std::path::Path::new("..").join("manifest.json");
    put("read_own_manifest_ok", serde_json::json!(std::fs::read(&manifest).is_ok()));
    put(
        "write_own_manifest_error",
        serde_json::json!(std::fs::OpenOptions::new().write(true).open(&manifest).err().map(|e| e.to_string())),
    );
    put(
        "write_own_binary_dir_error",
        serde_json::json!(std::fs::write("../evil", b"x").err().map(|e| e.to_string())),
    );
    put("write_data_ok", serde_json::json!(std::fs::write("scratch.txt", b"fine").is_ok()));

    // 3. Environment: only the scrubbed set plus the supervisor's own variables.
    let mut names: Vec<String> = std::env::vars().map(|(k, _)| k).collect();
    names.sort();
    put("env_names", serde_json::json!(names));

    // 4. Core dumps are off.
    let mut rl = libc::rlimit { rlim_cur: 1, rlim_max: 1 };
    // SAFETY: getrlimit writes into a valid struct.
    unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut rl) };
    put("core_limit", serde_json::json!(rl.rlim_cur));

    // 5. The host proxy: a request to the URL in ./http_url.
    if let Some(url) = read_text("http_url") {
        let mut http = pb::http_client::HttpClient::new(channel.clone());
        let r = http
            .request(pb::HttpRequest {
                plugin: Some(me.clone()),
                url,
                method: "GET".into(),
                return_body: true,
                ..Default::default()
            })
            .await;
        match r {
            Ok(resp) => {
                let resp = resp.into_inner();
                let body = resp.body.map(|b| String::from_utf8_lossy(&b.data).to_string());
                put("http", serde_json::json!({"status": resp.status, "body": body}));
            }
            Err(s) => put("http", serde_json::json!({"error": format!("{:?}: {}", s.code(), s.message())})),
        }
    }
    // And one to a host the manifest does not declare.
    {
        let mut http = pb::http_client::HttpClient::new(channel.clone());
        let r = http
            .request(pb::HttpRequest {
                plugin: Some(me.clone()),
                url: "http://undeclared.example/x".into(),
                method: "GET".into(),
                ..Default::default()
            })
            .await;
        put("http_undeclared", serde_json::json!(r.err().map(|s| format!("{:?}: {}", s.code(), s.message()))));
    }

    // 5b. A one-shot schedule job, due now: the core must fire it exactly once.
    {
        let mut schedule = pb::schedule_client::ScheduleClient::new(channel.clone());
        let due = prost_types::Timestamp { seconds: 1, nanos: 0 };
        let r = schedule
            .add(pb::ScheduleAddRequest {
                plugin: Some(me.clone()),
                jobs: vec![pb::ScheduleJob {
                    job_id: "probe-tick".into(),
                    spec: Some(pb::ScheduleSpec { kind: Some(pb::schedule_spec::Kind::RunAt(due)) }),
                    description: "fixture".into(),
                    missed_run_policy: "run_once".into(),
                }],
            })
            .await;
        put("schedule_add", serde_json::json!(r.map(|x| x.into_inner().added).map_err(|s| s.message().to_string())));
    }

    // 5c. Conversations: only a plugin whose signed manifest requires the service may send.
    {
        let mut conv = pb::conversations_client::ConversationsClient::new(channel.clone());
        let r = conv
            .send(pb::ConversationSendRequest {
                plugin: Some(me.clone()),
                channel: "local:web".into(),
                account: "web".into(),
                thread_key: "t1".into(),
                text: "hello from the fixture".into(),
            })
            .await;
        put(
            "conversations_send",
            serde_json::json!(match r {
                Ok(x) => format!("ok:{}", x.into_inner().receipt),
                Err(s) => format!("{:?}", s.code()),
            }),
        );
    }

    // 6. Its own storage works; pretending to be another plugin does not.
    let mut storage = pb::storage_client::StorageClient::new(channel.clone());
    let value = pb::Payload { data: b"hello".to_vec(), ..Default::default() };
    let own = storage
        .kv_put(pb::KvPutRequest { plugin: Some(me.clone()), namespace: "default".into(), key: "k".into(), value: Some(value.clone()) })
        .await;
    put("storage_own_ok", serde_json::json!(own.is_ok()));
    put("storage_own_error", serde_json::json!(own.as_ref().err().map(|s| format!("{:?}: {}", s.code(), s.message()))));
    let other = pb::PluginIdentity { id: "org.someone.else".into(), ..Default::default() };
    let forged = storage
        .kv_put(pb::KvPutRequest { plugin: Some(other), namespace: "default".into(), key: "k".into(), value: Some(value) })
        .await;
    put("storage_as_other_plugin", serde_json::json!(forged.err().map(|s| format!("{:?}", s.code()))));

    let text = serde_json::to_string_pretty(&serde_json::Value::Object(probe)).unwrap();
    let mut f = std::fs::File::create("probe.json.tmp").expect("write probe");
    f.write_all(text.as_bytes()).unwrap();
    std::fs::rename("probe.json.tmp", "probe.json").unwrap();

    // Stay up until the supervisor stops us.
    std::thread::sleep(std::time::Duration::from_secs(3600));
}
