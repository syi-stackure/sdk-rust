//! Deleting what the app stores for closed organizations.

use std::fmt::Display;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, PoisonError, RwLock};

use crate::client::take_events;

const MAX_EVENTS: u32 = 100;

type Deleting = Pin<Box<dyn Future<Output = Result<(), String>> + Send>>;
type OrgClosed = Arc<dyn Fn(String) -> Deleting + Send + Sync>;

static ORG_CLOSED: RwLock<Option<OrgClosed>> = RwLock::new(None);
static DRAINING: AtomicBool = AtomicBool::new(false);
static UNHANDLED: AtomicBool = AtomicBool::new(false);

/// Register the function that deletes what the app stores for a closed
/// organization and for the organizations under it.
///
/// It's called with the closed organization's ID, the same value as
/// [`User::account_id`](crate::User::account_id), once for each closed
/// organization, in the background. Stackure is told each one is done when
/// it returns `Ok`. When it returns an error or panics, the SDK prints it to
/// standard error and tries that organization again on a later session
/// check, at least 5 minutes later. The same organization can arrive again,
/// so it must also succeed when there is nothing left to delete.
///
/// Registering replaces any earlier function. Called inside a tokio runtime,
/// it also checks for closed organizations right away; otherwise the next
/// session check does.
///
/// # Example
///
/// ```no_run
/// # async fn delete_org(account_id: &str) -> Result<(), std::io::Error> { Ok(()) }
/// stackure::on_org_closed(|account_id| async move { delete_org(&account_id).await });
/// ```
pub fn on_org_closed<F, Fut, E>(f: F)
where
    F: Fn(String) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<(), E>> + Send + 'static,
    E: Display,
{
    let f: OrgClosed = Arc::new(move |account_id| -> Deleting {
        let deleting = f(account_id);
        Box::pin(async move { deleting.await.map_err(|e| e.to_string()) })
    });
    *ORG_CLOSED.write().unwrap_or_else(PoisonError::into_inner) = Some(f);
    drain_events();
}

fn org_closed() -> Option<OrgClosed> {
    ORG_CLOSED
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

/// Act on the `events_waiting` count from a session check.
pub(crate) fn note_events(waiting: u64) {
    if waiting == 0 {
        return;
    }
    if org_closed().is_none() {
        if !UNHANDLED.swap(true, Ordering::Relaxed) {
            eprintln!(
                "stackure: {} waiting for this app to delete their data. Register stackure::on_org_closed to delete it.",
                closed_orgs(waiting)
            );
        }
        return;
    }
    drain_events();
}

fn closed_orgs(n: u64) -> String {
    if n == 1 {
        "1 closed organization is".into()
    } else {
        format!("{n} closed organizations are")
    }
}

struct Draining;

impl Drop for Draining {
    fn drop(&mut self) {
        DRAINING.store(false, Ordering::Release);
    }
}

fn drain_events() {
    let (Some(f), Ok(rt)) = (org_closed(), tokio::runtime::Handle::try_current()) else {
        return;
    };
    if DRAINING.swap(true, Ordering::AcqRel) {
        return;
    }
    let draining = Draining;
    rt.spawn(async move {
        let _draining = draining;
        if let Err(e) = process_events(&f).await {
            eprintln!("stackure: closed organizations not deleted yet: {e}");
        }
    });
}

async fn process_events(f: &OrgClosed) -> Result<(), String> {
    let mut ack = Vec::new();
    loop {
        let res = take_events(&ack, MAX_EVENTS)
            .await
            .map_err(|e| e.to_string())?;
        ack.clear();
        let mut result = Ok(());
        for e in res.events {
            if e.kind != "org.closed" {
                continue;
            }
            result = run_org_closed(f, e.data.account_id).await;
            if result.is_err() {
                break;
            }
            ack.push(e.id);
        }
        if result.is_ok() && res.more {
            continue;
        }
        if !ack.is_empty() {
            let acked = take_events(&ack, 0).await.map_err(|e| e.to_string());
            result = result.and(acked.map(drop));
        }
        return result;
    }
}

async fn run_org_closed(f: &OrgClosed, account_id: String) -> Result<(), String> {
    let (f, id) = (Arc::clone(f), account_id.clone());
    match tokio::spawn(async move { f(id).await }).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(format!("deleting organization {account_id}: {e}")),
        Err(e) if e.is_panic() => {
            let p = e.into_panic();
            let msg = p
                .downcast_ref::<&str>()
                .map(|m| (*m).to_string())
                .or_else(|| p.downcast_ref::<String>().cloned())
                .unwrap_or_default();
            Err(format!(
                "deleting organization {account_id} panicked: {msg}"
            ))
        }
        Err(e) => Err(format!("deleting organization {account_id}: {e}")),
    }
}
