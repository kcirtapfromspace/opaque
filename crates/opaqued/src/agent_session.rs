//! RPC handlers for the `agent_session_*` method family: minting, ending,
//! and listing the session tokens that wrap an agent's operations under a
//! human's or service's authority.
//!
//! Extracted verbatim out of `main.rs`'s `handle_request` dispatch (pure
//! structural move, no behavior change) because `agent_session_start` alone
//! was ~400 lines of inline delegation-minting logic — by far the thickest
//! arm in the RPC match block. It stays in `opaqued` (not a crate boundary
//! move): these handlers are tightly coupled to `DaemonState`'s private
//! `agent_sessions` registry and the `AgentSession`/`SessionDelegation`
//! types defined in `main.rs`, which stay there (composition-root state).
use std::time::SystemTime;

use opaque_core::audit::{AuditEvent, AuditEventKind, ClientSummary};
use opaque_core::identity::{
    AccessMode, DelegationClaims, PrincipalContext, PrincipalId, now_unix, sign_delegation_token,
};
use opaque_core::operation::{ClientIdentity, ClientType};
use opaque_core::proto::{Request, Response};
use tracing::warn;
use uuid::Uuid;

use crate::{
    AgentSession, DaemonState, SessionDelegation, derive_agent_tool_name, emit_daemon_method_audit,
    generate_daemon_token, identity, revoke_delegations, session_approval_reason,
    system_time_to_unix_ms,
};

/// `agent_session_start`: mint a new session token (a signed delegation when
/// `[identity]` is configured, else a legacy opaque hex token), gated on a
/// fresh out-of-band human approval.
pub async fn handle_start(
    state: &DaemonState,
    req: Request,
    identity: &ClientIdentity,
    client_type: ClientType,
) -> Response {
    let default_ttl = state.config.agent_session_ttl_secs.unwrap_or(3600);
    let ttl_secs = req
        .params
        .get("ttl_secs")
        .and_then(|v| v.as_u64())
        .unwrap_or(default_ttl)
        .clamp(60, 86_400);
    let label = req
        .params
        .get("label")
        .and_then(|v| v.as_str())
        .map(|s| s.to_owned());
    let label_for_audit = label.clone();

    // --- Identity: resolve the delegation subject BEFORE burning a
    // human approval, so malformed requests fail early and the
    // approval prompt can name who the session would act for.
    let mut delegation_plan: Option<(AccessMode, opaque_core::identity::Principal)> = None;
    if let Some(rt) = state.identity.as_ref() {
        let mode_s = req
            .params
            .get("mode")
            .and_then(|v| v.as_str())
            .unwrap_or("delegated");
        let mode = match mode_s.parse::<AccessMode>() {
            Ok(m) => m,
            Err(_) => {
                return Response::err(
                    Some(req.id),
                    "invalid_params",
                    "mode must be one of: delegated, autonomous, break_glass",
                );
            }
        };
        let sub = match mode {
            AccessMode::BreakGlass => {
                emit_daemon_method_audit(
                    state,
                    AuditEventKind::OperationFailed,
                    "agent_session_start",
                    identity,
                    client_type,
                    "break_glass_unavailable",
                    Some("break-glass session requested; no distinct-approver factor".into()),
                );
                return Response::err(
                    Some(req.id),
                    "break_glass_unavailable",
                    "break-glass access requires a distinct-approver factor \
                     (paired second device), which is not configured",
                );
            }
            AccessMode::Delegated => {
                let session = match rt.store.current_human_session() {
                    Ok(Some(s)) => s,
                    Ok(None) => {
                        emit_daemon_method_audit(
                            state,
                            AuditEventKind::OperationFailed,
                            "agent_session_start",
                            identity,
                            client_type,
                            "login_required",
                            Some("delegated session requested with no active login".into()),
                        );
                        return Response::err(
                            Some(req.id),
                            "login_required",
                            "delegated agent sessions require an active human login — \
                             run `opaque login` first",
                        );
                    }
                    Err(e) => {
                        warn!("identity store error during session mint: {e}");
                        return Response::err(
                            Some(req.id),
                            "internal",
                            "identity store unavailable",
                        );
                    }
                };
                match rt.store.get_principal(&session.principal_id) {
                    Ok(Some(p))
                        if rt.principal_permitted(&p) && session.idp_issuer == rt.config.issuer =>
                    {
                        p
                    }
                    Ok(_) => {
                        return Response::err(
                            Some(req.id),
                            "login_required",
                            "the logged-in principal is missing or disabled",
                        );
                    }
                    Err(e) => {
                        warn!("identity store error during session mint: {e}");
                        return Response::err(
                            Some(req.id),
                            "internal",
                            "identity store unavailable",
                        );
                    }
                }
            }
            AccessMode::Autonomous => {
                let Some(service) = req.params.get("service").and_then(|v| v.as_str()) else {
                    return Response::err(
                        Some(req.id),
                        "invalid_params",
                        "autonomous mode requires a 'service' principal name",
                    );
                };
                match rt.store.get_service_by_name(service) {
                    Ok(Some(p)) if rt.principal_permitted(&p) => p,
                    Ok(_) => {
                        emit_daemon_method_audit(
                            state,
                            AuditEventKind::OperationFailed,
                            "agent_session_start",
                            identity,
                            client_type,
                            "unknown_service_principal",
                            Some(format!(
                                "autonomous session requested for unknown service '{}'",
                                service.chars().take(64).collect::<String>()
                            )),
                        );
                        return Response::err(
                            Some(req.id),
                            "unknown_service_principal",
                            "no such service principal — declare it under \
                             [[identity.service_principals]] in the daemon config",
                        );
                    }
                    Err(e) => {
                        warn!("identity store error during session mint: {e}");
                        return Response::err(
                            Some(req.id),
                            "internal",
                            "identity store unavailable",
                        );
                    }
                }
            }
        };
        delegation_plan = Some((mode, sub));
    }

    // SECURITY (C1/software-first): minting a session token grants a wrapped
    // agent scoped access, so it must be authorized by a fresh out-of-band
    // human approval — not by client classification, which an agent can wear.
    // The agent cannot satisfy the approval, so it cannot mint its own session.
    let reason = session_approval_reason(
        state.tenant.as_ref().map(|boundary| boundary.binding()),
        identity.uid,
        ttl_secs,
        delegation_plan.as_ref(),
        label.as_deref(),
    );
    let session_approver = match state
        .enclave
        .request_control_approval(
            identity,
            client_type,
            "agent_session_start",
            "Create an agent session token",
            &reason,
        )
        .await
    {
        Ok(approver) => approver,
        Err(e) => {
            emit_daemon_method_audit(
                state,
                AuditEventKind::OperationFailed,
                "agent_session_start",
                identity,
                client_type,
                "permission_denied",
                Some(format!("session creation not approved: {e}")),
            );
            return Response::err(
                Some(req.id),
                "permission_denied",
                "creating an agent session requires out-of-band approval",
            );
        }
    };

    let session_id = Uuid::new_v4().to_string();
    let expires_at = SystemTime::now()
        .checked_add(std::time::Duration::from_secs(ttl_secs))
        .unwrap_or(SystemTime::now());

    // Mint the credential: a signed delegation token when identity is
    // configured, the legacy opaque hex token otherwise.
    let (session_token, delegation, mut extra) = match (state.identity.as_ref(), delegation_plan) {
        (Some(rt), Some((mode, sub))) => {
            // Membership or principal state may have changed while
            // the independent approver reviewed session creation.
            let sub = match rt.store.get_principal(&sub.id) {
                Ok(Some(current)) if rt.principal_permitted(&current) => current,
                _ => {
                    return Response::err(
                        Some(req.id),
                        "identity_not_permitted",
                        "the delegating principal is no longer permitted by identity policy",
                    );
                }
            };
            // Re-check the login session didn't expire while the
            // human was approving (delegated mode only).
            let human_session_id = if mode == AccessMode::Delegated {
                match rt.store.current_human_session() {
                    Ok(Some(s)) if s.principal_id == sub.id && s.idp_issuer == rt.config.issuer => {
                        Some(s.id)
                    }
                    _ => {
                        return Response::err(
                            Some(req.id),
                            "login_required",
                            "the human login session ended before the delegation \
                             could be issued — run `opaque login` again",
                        );
                    }
                }
            } else {
                None
            };

            let tool = derive_agent_tool_name(label.as_deref(), identity);
            let act = match rt.store.upsert_agent(&tool) {
                Ok(p) => p,
                Err(e) => {
                    warn!("failed to upsert agent principal: {e}");
                    return Response::err(Some(req.id), "internal", "identity store unavailable");
                }
            };

            let now = now_unix();
            let claims = DelegationClaims {
                jti: session_id.clone(),
                sub: sub.id.clone(),
                act: act.id.clone(),
                mode,
                iat: now,
                exp: now + ttl_secs as i64,
            };
            let token = match sign_delegation_token(&claims, &rt.signing) {
                Ok(t) => t,
                Err(e) => {
                    warn!("failed to sign delegation token: {e}");
                    return Response::err(
                        Some(req.id),
                        "internal",
                        "could not mint a delegation token",
                    );
                }
            };
            let record = identity::store::DelegationRecord {
                jti: session_id.clone(),
                sub_principal: sub.id.clone(),
                act_principal: act.id.clone(),
                mode,
                human_session_id: human_session_id.clone(),
                // Attribute the delegation to the principal who
                // approved its minting, when the gate named one.
                approved_by: session_approver
                    .as_ref()
                    .and_then(|a| PrincipalId::parse(&a.principal_id).ok()),
                created_at: now,
                expires_at: now + ttl_secs as i64,
                revoked_at: None,
            };
            if let Err(e) = rt.store.record_delegation(&record) {
                warn!("failed to record delegation: {e}");
                return Response::err(Some(req.id), "internal", "could not record the delegation");
            }

            let extra = serde_json::json!({
                "mode": mode.as_str(),
                "on_behalf_of": sub.id.as_str(),
                "on_behalf_of_label": sub.display_label(),
            });
            (
                token,
                Some(SessionDelegation {
                    jti: session_id.clone(),
                    sub: sub.id.clone(),
                    act: act.id.clone(),
                    mode,
                    human_session_id,
                }),
                extra,
            )
        }
        _ => (generate_daemon_token(), None, serde_json::json!({})),
    };

    let delegation_for_audit = delegation
        .as_ref()
        .map(|d| format!(" mode={} sub={}", d.mode, d.sub))
        .unwrap_or_default();

    let session = AgentSession {
        session_id: session_id.clone(),
        token: session_token.clone(),
        created_by_uid: identity.uid,
        expires_at,
        label,
        delegation: delegation.clone(),
    };
    state
        .agent_sessions
        .write()
        .await
        .insert(session_id.clone(), session);

    let detail = format!(
        "session_id={} ttl_secs={} label={}{}",
        session_id,
        ttl_secs,
        label_for_audit.as_deref().unwrap_or(""),
        delegation_for_audit
    );
    // A delegated/autonomous mint is a DelegationIssued event carrying
    // the principal context; a legacy hex-token mint stays a plain
    // session-start operation event.
    match &delegation {
        Some(d) => {
            let sub_label = state
                .identity
                .as_ref()
                .and_then(|rt| rt.store.get_principal(&d.sub).ok().flatten())
                .map(|p| p.display_label())
                .unwrap_or_default();
            let ctx = PrincipalContext {
                sub: d.sub.clone(),
                sub_teams: state.federation.teams_of(&sub_label),
                sub_label,
                sub_roles: Default::default(),
                act: d.act.clone(),
                act_label: String::new(),
                mode: d.mode,
                jti: d.jti.clone(),
                human_session_id: d.human_session_id.clone(),
            };
            state.audit.emit({
                let mut ev = AuditEvent::new(AuditEventKind::DelegationIssued)
                    .with_operation("agent_session_start")
                    .with_client(ClientSummary::from((identity, client_type)).with_principal(&ctx))
                    .with_outcome("issued")
                    .with_detail(detail);
                if let Some(ref approver) = session_approver {
                    ev = ev.with_approver(approver.clone());
                }
                ev
            });
        }
        None => emit_daemon_method_audit(
            state,
            AuditEventKind::OperationSucceeded,
            "agent_session_start",
            identity,
            client_type,
            "started",
            Some(detail),
        ),
    }

    let mut payload = serde_json::json!({
        "session_id": session_id,
        "session_token": session_token,
        "expires_at_utc_ms": system_time_to_unix_ms(expires_at),
        "ttl_secs": ttl_secs,
    });
    if let (Some(obj), Some(extra_obj)) = (payload.as_object_mut(), extra.as_object_mut()) {
        obj.append(extra_obj);
    }
    Response::ok(req.id, payload)
}

/// `agent_session_end`: revoke one session (or, with `all: true`, every
/// session minted by the caller's uid), releasing its delegation record.
pub async fn handle_end(
    state: &DaemonState,
    req: Request,
    identity: &ClientIdentity,
    client_type: ClientType,
) -> Response {
    let end_all = req
        .params
        .get("all")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let session_id_param = req.params.get("session_id").and_then(|v| v.as_str());

    if end_all && session_id_param.is_some() {
        emit_daemon_method_audit(
            state,
            AuditEventKind::OperationFailed,
            "agent_session_end",
            identity,
            client_type,
            "bad_request",
            Some("cannot combine all=true with session_id".into()),
        );
        return Response::err(
            Some(req.id),
            "bad_request",
            "cannot combine 'all' with 'session_id'",
        );
    }

    if end_all {
        let mut sessions = state.agent_sessions.write().await;
        let before = sessions.len();
        let ended_delegations: Vec<SessionDelegation> = sessions
            .values()
            .filter(|s| s.created_by_uid == identity.uid)
            .filter_map(|s| s.delegation.clone())
            .collect();
        sessions.retain(|_, s| s.created_by_uid != identity.uid);
        let ended_count = before.saturating_sub(sessions.len());
        drop(sessions);
        revoke_delegations(state, identity, client_type, &ended_delegations);
        emit_daemon_method_audit(
            state,
            AuditEventKind::OperationSucceeded,
            "agent_session_end",
            identity,
            client_type,
            "ended_all",
            Some(format!("ended_count={ended_count}")),
        );
        return Response::ok(
            req.id,
            serde_json::json!({
                "status": "ended",
                "all": true,
                "ended_count": ended_count,
            }),
        );
    }

    let Some(session_id) = session_id_param else {
        emit_daemon_method_audit(
            state,
            AuditEventKind::OperationFailed,
            "agent_session_end",
            identity,
            client_type,
            "bad_request",
            Some("missing session_id".into()),
        );
        return Response::err(Some(req.id), "bad_request", "missing 'session_id' field");
    };

    let mut sessions = state.agent_sessions.write().await;
    let can_delete = if let Some(existing) = sessions.get(session_id) {
        client_type == ClientType::Human || existing.created_by_uid == identity.uid
    } else {
        true
    };
    if !can_delete {
        emit_daemon_method_audit(
            state,
            AuditEventKind::OperationFailed,
            "agent_session_end",
            identity,
            client_type,
            "permission_denied",
            Some(format!("session_id={session_id}")),
        );
        return Response::err(
            Some(req.id),
            "permission_denied",
            "session belongs to a different uid",
        );
    }

    let removed = sessions.remove(session_id);
    drop(sessions);
    if let Some(d) = removed.as_ref().and_then(|s| s.delegation.clone()) {
        revoke_delegations(state, identity, client_type, &[d]);
    }
    let label = removed.as_ref().and_then(|s| s.label.clone());
    let status = if removed.is_some() {
        "ended"
    } else {
        "not_found"
    };
    emit_daemon_method_audit(
        state,
        AuditEventKind::OperationSucceeded,
        "agent_session_end",
        identity,
        client_type,
        status,
        Some(format!("session_id={session_id}")),
    );

    Response::ok(
        req.id,
        serde_json::json!({
            "status": status,
            "session_id": session_id,
            "label": label,
        }),
    )
}

/// `agent_session_list`: list the caller's own live sessions (opportunistic
/// expiry sweep included), sorted by session id. Never gated on client
/// classification — see the inline NOTE.
pub async fn handle_list(
    state: &DaemonState,
    req: Request,
    identity: &ClientIdentity,
    client_type: ClientType,
) -> Response {
    // NOTE (software-first): no longer gated on client classification, which
    // is audit-only at a shared uid. The listing is already scoped to the
    // caller's own uid and hides tokens; restricting it from a co-resident
    // agent soundly requires the separate-uid split (Lever B).
    let now = SystemTime::now();
    let mut sessions = state.agent_sessions.write().await;
    // Expire old sessions opportunistically.
    sessions.retain(|_, s| s.expires_at > now);

    let mut visible_sessions: Vec<serde_json::Value> = sessions
        .values()
        .filter(|s| s.created_by_uid == identity.uid)
        .map(|s| {
            let ttl_remaining_secs = s
                .expires_at
                .duration_since(now)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            serde_json::json!({
                "session_id": s.session_id,
                "label": s.label,
                "expires_at_utc_ms": system_time_to_unix_ms(s.expires_at),
                "ttl_remaining_secs": ttl_remaining_secs,
            })
        })
        .collect();

    visible_sessions.sort_by(|a, b| {
        let a_id = a.get("session_id").and_then(|v| v.as_str()).unwrap_or("");
        let b_id = b.get("session_id").and_then(|v| v.as_str()).unwrap_or("");
        a_id.cmp(b_id)
    });

    emit_daemon_method_audit(
        state,
        AuditEventKind::OperationSucceeded,
        "agent_session_list",
        identity,
        client_type,
        "listed",
        Some(format!("count={}", visible_sessions.len())),
    );

    Response::ok(
        req.id,
        serde_json::json!({
            "count": visible_sessions.len(),
            "sessions": visible_sessions,
        }),
    )
}
