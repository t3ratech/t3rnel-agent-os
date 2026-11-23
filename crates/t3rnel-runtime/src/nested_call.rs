//! Inter-agent calls (`agent_send`): depth limit and stack isolation.
//!
//! `agent_send` hands a message to another agent and waits for that agent's whole
//! LLM loop to finish. Two things must hold for that to be safe:
//!
//! 1. **Bounded depth.** A -> B -> A -> ... must stop. The limit
//!    ([`MAX_AGENT_CALL_DEPTH`]) and the counter ([`AGENT_CALL_DEPTH`]) were declared
//!    but never scoped or checked, so nothing stopped a ping-pong between two agents.
//! 2. **No stack nesting.** Awaiting the callee inline puts every hop's agent loop on
//!    the caller's stack. One loop's futures are huge (a debug build spends several
//!    hundred KB per hop), so three nested hops overflowed the 2MB tokio worker stack
//!    and aborted the whole daemon. Running the callee as its own task means the
//!    caller is parked while the callee is polled from the scheduler, so stack use
//!    stays flat however deep the chain goes.

use std::future::Future;
use std::time::Duration;
use tracing::Instrument;

/// Maximum inter-agent call depth to prevent infinite recursion (A->B->C->...).
pub const MAX_AGENT_CALL_DEPTH: u32 = 5;

tokio::task_local! {
    /// Tracks the current inter-agent call depth within a task.
    pub static AGENT_CALL_DEPTH: std::cell::Cell<u32>;
}

/// Get the current inter-agent call depth from the task-local context.
/// Returns 0 if called outside an agent task.
pub fn current_agent_depth() -> u32 {
    AGENT_CALL_DEPTH.try_with(|d| d.get()).unwrap_or(0)
}

/// Aborts the callee task when the caller is done with it, whether that is a
/// timeout, a normal return, or the caller itself being cancelled. Without it a
/// timed-out `agent_send` would leave the callee's loop running detached.
struct AbortOnDrop(tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Run `call` (the callee agent's turn) as its own task one level deeper than the
/// current call, and wait for it for at most `timeout`.
///
/// Refuses, without running `call`, once [`MAX_AGENT_CALL_DEPTH`] is reached. A panic
/// in the callee comes back as an error instead of unwinding through the caller.
pub async fn run_nested_agent_call<F>(
    agent_id: &str,
    timeout: Duration,
    call: F,
) -> Result<String, String>
where
    F: Future<Output = Result<String, String>> + Send + 'static,
{
    let depth = current_agent_depth();
    if depth >= MAX_AGENT_CALL_DEPTH {
        return Err(format!(
            "agent_send refused: inter-agent call depth limit ({MAX_AGENT_CALL_DEPTH}) reached \
             while contacting '{agent_id}'. The message was not delivered. Answer with what you \
             already have instead of delegating further."
        ));
    }

    let scoped = AGENT_CALL_DEPTH.scope(std::cell::Cell::new(depth + 1), call);
    let handle = tokio::spawn(scoped.instrument(tracing::Span::current()));
    let _abort_on_drop = AbortOnDrop(handle.abort_handle());

    match tokio::time::timeout(timeout, handle).await {
        Ok(Ok(result)) => result,
        Ok(Err(join_error)) => Err(format!(
            "agent_send to '{agent_id}' failed: the agent's task {}.",
            if join_error.is_panic() {
                "panicked"
            } else {
                "was cancelled"
            }
        )),
        Err(_) => Err(format!(
            "agent_send timed out after {}s waiting for agent '{agent_id}'. Check the target agent state and LLM provider configuration.",
            timeout.as_secs()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    const LONG: Duration = Duration::from_secs(30);

    /// An agent that, like orchestrator <-> project-manager, answers by calling
    /// another agent, which does the same, forever.
    fn ping_pong(hops: Arc<AtomicU32>) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send>> {
        Box::pin(async move {
            hops.fetch_add(1, Ordering::SeqCst);
            run_nested_agent_call("peer", LONG, ping_pong(hops)).await
        })
    }

    #[tokio::test]
    async fn ping_pong_between_agents_stops_at_the_depth_limit() {
        let hops = Arc::new(AtomicU32::new(0));

        let result = run_nested_agent_call("peer", LONG, ping_pong(hops.clone())).await;

        let error = result.expect_err("an unbounded chain must end in a refusal");
        assert!(error.contains("depth limit"), "unexpected error: {error}");
        assert_eq!(
            hops.load(Ordering::SeqCst),
            MAX_AGENT_CALL_DEPTH,
            "exactly MAX_AGENT_CALL_DEPTH callee turns may run"
        );
    }

    #[tokio::test]
    async fn refused_call_never_starts_the_callee() {
        let started = Arc::new(AtomicU32::new(0));
        let started_in_call = started.clone();

        let result = AGENT_CALL_DEPTH
            .scope(std::cell::Cell::new(MAX_AGENT_CALL_DEPTH), async move {
                run_nested_agent_call("peer", LONG, async move {
                    started_in_call.fetch_add(1, Ordering::SeqCst);
                    Ok("ran".to_string())
                })
                .await
            })
            .await;

        assert!(result.is_err());
        assert_eq!(started.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn callee_sees_one_level_deeper_than_its_caller() {
        let before = current_agent_depth();

        let inside = run_nested_agent_call("peer", LONG, async {
            Ok(current_agent_depth().to_string())
        })
        .await
        .unwrap();

        assert_eq!(inside, (before + 1).to_string());
        assert_eq!(current_agent_depth(), before, "the caller's depth is untouched");
    }

    /// The overflow came from the callee being polled on top of the caller's stack.
    /// A separate task is polled from the scheduler, so the ids must differ.
    #[tokio::test]
    async fn callee_runs_as_its_own_task_not_on_the_callers_stack() {
        // The caller is itself a task, as an agent loop is in the daemon.
        let (caller, callee) = tokio::spawn(async {
            let caller = tokio::task::id().to_string();
            let callee = run_nested_agent_call("peer", LONG, async {
                Ok(tokio::task::id().to_string())
            })
            .await
            .unwrap();
            (caller, callee)
        })
        .await
        .unwrap();

        assert_ne!(callee, caller);
    }

    struct SetOnDrop(Arc<AtomicU32>);

    impl Drop for SetOnDrop {
        fn drop(&mut self) {
            self.0.store(1, Ordering::SeqCst);
        }
    }

    async fn wait_until_set(flag: &AtomicU32) -> bool {
        for _ in 0..100 {
            if flag.load(Ordering::SeqCst) == 1 {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        false
    }

    #[tokio::test]
    async fn timed_out_callee_is_aborted_not_left_running() {
        let dropped = Arc::new(AtomicU32::new(0));
        let guard = SetOnDrop(dropped.clone());

        let result = run_nested_agent_call("slow-peer", Duration::from_millis(50), async move {
            let _guard = guard;
            std::future::pending::<Result<String, String>>().await
        })
        .await;

        let error = result.expect_err("must time out");
        assert!(error.contains("timed out"), "unexpected error: {error}");
        assert!(wait_until_set(&dropped).await, "callee kept running after the timeout");
    }

    #[tokio::test]
    async fn cancelling_the_caller_aborts_the_callee() {
        let dropped = Arc::new(AtomicU32::new(0));
        let guard = SetOnDrop(dropped.clone());

        let outer = tokio::time::timeout(
            Duration::from_millis(50),
            run_nested_agent_call("slow-peer", LONG, async move {
                let _guard = guard;
                std::future::pending::<Result<String, String>>().await
            }),
        )
        .await;

        assert!(outer.is_err(), "outer timeout should have fired");
        assert!(wait_until_set(&dropped).await, "callee outlived its cancelled caller");
    }

    #[tokio::test]
    async fn callee_panic_is_reported_as_an_error() {
        let result = run_nested_agent_call("buggy-peer", LONG, async {
            panic!("callee blew up");
            #[allow(unreachable_code)]
            Ok(String::new())
        })
        .await;

        let error = result.expect_err("a panicking callee is an error, not a crash");
        assert!(error.contains("panicked"), "unexpected error: {error}");
    }

    #[tokio::test]
    async fn callee_result_is_returned_unchanged() {
        let ok = run_nested_agent_call("peer", LONG, async { Ok("hello".to_string()) }).await;
        assert_eq!(ok.unwrap(), "hello");

        let err = run_nested_agent_call("peer", LONG, async { Err("no such agent".to_string()) }).await;
        assert_eq!(err.unwrap_err(), "no such agent");
    }
}
