//! `webhooks`: a repository webhook without a shared secret lets anyone who
//! learns its URL forge the event that drives a deploy or CI receiver — a
//! supply-chain path with no commit in it. OpenSSF Scorecard registers a
//! Webhooks check for exactly this, gated behind an experimental flag no
//! default install sets, so it has never run for anyone. This control reads
//! each hook's secret and TLS setting through `gh api`, with whatever token
//! the lane holds.
//!
//! Who can read `/hooks`: any token carrying `read:repo_hook` (the `repo`
//! scope a maintainer's `gh auth login` grants includes it) — so the local
//! lane sees it by default. A workflow's `GITHUB_TOKEN` cannot, and GitHub
//! answers 404, not 403; that is `Degraded(no-access)`, never a guess.

use crate::config::Config;
use crate::context::Ctx;
use crate::controls::{Outcome, VerifyResult};
use crate::exec;

/// The scope names a maintainer needs, spelled the way the message says them.
const READ_SCOPE: &str = "read:repo_hook (included in the `repo` scope) plus repository admin";

/// `verify webhooks`.
pub fn verify_webhooks(ctx: &Ctx, cfg: &Config) -> VerifyResult {
    let id = "webhooks";
    if crate::exec::find_in_path("gh").is_none() {
        return VerifyResult::degraded(
            id,
            "tool-missing",
            vec![crate::tools::degrade_message("gh", ctx.platform)],
        );
    }
    let Some(slug) = cfg.github_repo().or_else(|| ctx.origin_slug()) else {
        return VerifyResult::degraded(
            id,
            "no-remote",
            vec![
                "no GitHub repo configured (general.github_repo) and no origin remote — cannot \
                 read webhooks"
                    .into(),
            ],
        );
    };
    let api = format!("repos/{slug}/hooks");
    let out = match exec::run("gh", &["api", &api], Some(&ctx.root)) {
        Ok(o) => o,
        Err(err) => {
            return VerifyResult::degraded(id, "scan-error", vec![format!("gh failed: {err:#}")])
        }
    };
    if !out.success() {
        let first = out.stderr.lines().next().unwrap_or("error").to_string();
        return VerifyResult::degraded(
            id,
            "no-access",
            vec![format!(
                "GitHub answered `{first}` for `{api}` — reading hooks needs {READ_SCOPE}; a \
                 workflow's GITHUB_TOKEN cannot read them at all, and 404 is how GitHub says so. \
                 Unverified, not confirmed"
            )],
        );
    }
    let hooks: Vec<serde_json::Value> = match serde_json::from_str(&out.stdout) {
        Ok(h) => h,
        Err(err) => {
            return VerifyResult::degraded(
                id,
                "scan-error",
                vec![format!("`{api}` did not return a hook list: {err}")],
            )
        }
    };
    if hooks.is_empty() {
        return VerifyResult::new(
            id,
            Outcome::Pass,
            vec![format!("{slug}: no webhooks configured")],
        );
    }
    let mut messages = Vec::new();
    let mut gaps = Vec::new();
    for hook in &hooks {
        let label = hook_label(hook);
        let active = hook["active"].as_bool().unwrap_or(true);
        // GitHub masks a configured secret as `********`; an unset secret is
        // absent from `config`. Presence is the signal, never the value.
        let has_secret = hook["config"].get("secret").is_some_and(|s| !s.is_null());
        let insecure_tls = hook["config"]["insecure_ssl"]
            .as_str()
            .map(|v| v == "1")
            .or_else(|| hook["config"]["insecure_ssl"].as_u64().map(|v| v == 1))
            .unwrap_or(false);
        if !active {
            messages.push(format!("{label}: inactive — not delivered, not scored"));
            continue;
        }
        match (has_secret, insecure_tls) {
            (true, false) => messages.push(format!("{label}: secret set, TLS verified ✓")),
            (false, _) => gaps.push(format!(
                "{label}: no secret — anyone who learns the URL can forge its events; set a \
                 secret and verify the X-Hub-Signature-256 header in the receiver"
            )),
            (true, true) => gaps.push(format!(
                "{label}: `insecure_ssl` is on — deliveries skip TLS verification and can be \
                 intercepted; turn it off"
            )),
        }
    }
    if gaps.is_empty() {
        VerifyResult::new(id, Outcome::Pass, messages)
    } else {
        messages.extend(gaps);
        VerifyResult::new(id, Outcome::Fail, messages)
    }
}

/// `web hook #123 → https://host/path` — the URL's query string is dropped, since
/// some receivers put a token there.
fn hook_label(hook: &serde_json::Value) -> String {
    let name = hook["name"].as_str().unwrap_or("hook");
    let id = hook["id"]
        .as_u64()
        .map(|i| format!("#{i}"))
        .unwrap_or_default();
    let url = hook["config"]["url"].as_str().unwrap_or("<no url>");
    let url = url.split('?').next().unwrap_or(url);
    format!("{name} {id} → {url}").replace("  ", " ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::env_lock;

    fn ctx_with_repo() -> (tempfile::TempDir, Ctx) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        exec::git(&["init", "-b", "main"], root).unwrap();
        exec::git(&["config", "user.name", "SSCSB Test"], root).unwrap();
        exec::git(&["config", "user.email", "sscsb-test@example.com"], root).unwrap();
        crate::init::bootstrap(root).expect("bootstrap");
        let ctx = Ctx::discover(root).unwrap();
        let text = std::fs::read_to_string(ctx.config_path()).unwrap().replace(
            "# github_repo = \"owner/repo\"  # set to enable GitHub API checks",
            "github_repo = \"acme/demo\"",
        );
        std::fs::write(ctx.config_path(), text).unwrap();
        let ctx = Ctx::discover(root).unwrap();
        (dir, ctx)
    }

    fn gh_answering(stdout: &str, exit: i32) -> String {
        format!("#!/bin/sh\ncase \"$1\" in --version) echo 'gh version 2.80.0'; exit 0 ;; esac\ncat <<'JSON'\n{stdout}\nJSON\nexit {exit}\n")
    }

    /// ISC-36: secret set → pass; no secret → fail naming the URL; insecure
    /// TLS → fail; an empty list → pass; an inactive hook is reported, not scored.
    #[test]
    fn hooks_with_a_secret_pass_and_without_one_fail_naming_the_url() {
        let lock = env_lock();
        lock.fake_tool(
            "gh",
            &gh_answering(
                r#"[{"id":1,"name":"web","active":true,"config":{"url":"https://deploy.example.com/hook?token=abc","secret":"********","insecure_ssl":"0"}},
                    {"id":2,"name":"web","active":true,"config":{"url":"https://ci.example.com/hook","insecure_ssl":"0"}},
                    {"id":3,"name":"web","active":true,"config":{"url":"https://old.example.com/hook","secret":"********","insecure_ssl":"1"}},
                    {"id":4,"name":"web","active":false,"config":{"url":"https://dead.example.com/hook","insecure_ssl":"0"}}]"#,
                0,
            ),
        );
        let (_d, ctx) = ctx_with_repo();
        let cfg = ctx.require_config().unwrap();
        let r = verify_webhooks(&ctx, cfg);
        assert_eq!(r.outcome, Outcome::Fail, "{:?}", r.messages);
        let joined = r.messages.join("\n");
        assert!(
            joined.contains("web #1 → https://deploy.example.com/hook: secret set, TLS verified ✓"),
            "{joined}"
        );
        assert!(
            !joined.contains("token=abc"),
            "query strings are never echoed: {joined}"
        );
        assert!(
            joined.contains("web #2 → https://ci.example.com/hook: no secret"),
            "{joined}"
        );
        assert!(
            joined.contains("web #3 → https://old.example.com/hook: `insecure_ssl` is on"),
            "{joined}"
        );
        assert!(
            joined.contains("web #4 → https://dead.example.com/hook: inactive"),
            "{joined}"
        );

        lock.fake_tool("gh", &gh_answering("[]", 0));
        let r = verify_webhooks(&ctx, cfg);
        assert_eq!(r.outcome, Outcome::Pass, "{:?}", r.messages);
        assert!(r.messages[0].contains("no webhooks configured"));

        lock.fake_tool(
            "gh",
            &gh_answering(
                r#"[{"id":9,"name":"web","active":true,"config":{"url":"https://ok.example.com/h","secret":"********","insecure_ssl":"0"}}]"#,
                0,
            ),
        );
        let r = verify_webhooks(&ctx, cfg);
        assert_eq!(r.outcome, Outcome::Pass, "{:?}", r.messages);
        assert_eq!(r.degraded_reason, None);
    }

    /// ISC-37: a 404 — what GitHub answers a token without `read:repo_hook`,
    /// including every workflow's GITHUB_TOKEN — is Degraded with the scope
    /// and the token named; never Fail, never Pass.
    #[test]
    fn a_404_is_no_access_naming_the_scope_and_the_token() {
        let lock = env_lock();
        lock.fake_tool(
            "gh",
            "#!/bin/sh\ncase \"$1\" in --version) echo 'gh version 2.80.0'; exit 0 ;; esac\necho 'gh: Not Found (HTTP 404)' 1>&2\nexit 1\n",
        );
        let (_d, ctx) = ctx_with_repo();
        let cfg = ctx.require_config().unwrap();
        let r = verify_webhooks(&ctx, cfg);
        assert_eq!(r.outcome, Outcome::Degraded, "{:?}", r.messages);
        assert_eq!(r.degraded_reason, Some("no-access"));
        assert!(r.messages[0].contains("HTTP 404"));
        assert!(r.messages[0].contains("read:repo_hook"));
        assert!(r.messages[0].contains("GITHUB_TOKEN cannot read them"));
    }

    #[test]
    fn no_gh_no_remote_and_a_non_list_answer_each_say_why() {
        let lock = env_lock();
        lock.hide_from_path(&["gh"]);
        let (_d, ctx) = ctx_with_repo();
        let cfg = ctx.require_config().unwrap();
        let r = verify_webhooks(&ctx, cfg);
        assert_eq!(r.degraded_reason, Some("tool-missing"));

        lock.fake_tool("gh", &gh_answering(r#"{"message":"weird"}"#, 0));
        let r = verify_webhooks(&ctx, cfg);
        assert_eq!(r.outcome, Outcome::Degraded);
        assert_eq!(r.degraded_reason, Some("scan-error"));

        // No repo configured and no origin: no remote to ask.
        let dir = tempfile::tempdir().unwrap();
        exec::git(&["init", "-b", "main"], dir.path()).unwrap();
        crate::init::bootstrap(dir.path()).unwrap();
        let ctx2 = Ctx::discover(dir.path()).unwrap();
        let cfg2 = ctx2.require_config().unwrap();
        let r = verify_webhooks(&ctx2, cfg2);
        assert_eq!(r.degraded_reason, Some("no-remote"), "{:?}", r.messages);
    }
}
