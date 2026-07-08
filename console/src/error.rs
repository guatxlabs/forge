// SPDX-License-Identifier: AGPL-3.0-only
//! Compact typed API error shared by the flag-gated enterprise modules (rbac / compliance / sso /
//! tenancy / scim). Deliberately SMALL by construction (`&'static str` code + `String` why, no boxing)
//! so `Result<T, ApiError>` never trips `clippy::result_large_err`. `IntoResponse` produces EXACTLY the
//! byte-identical `(status, Json({"error": code, "why": why}))` envelope the modules emitted before, so
//! routing each module's private `err(...)` helper through this changes nothing on the wire.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Json, Response},
};
use serde_json::json;

/// Typed API error — the shared substrate of every enterprise module's `err(...)` helper.
#[derive(Debug)]
pub(crate) struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub why: String,
}

impl ApiError {
    /// Generic constructor (mirrors the historical `err(status, code, why)` signature).
    pub(crate) fn new(status: StatusCode, code: &'static str, why: impl Into<String>) -> Self {
        Self { status, code, why: why.into() }
    }

    /// 400 Bad Request.
    #[allow(dead_code)]
    pub(crate) fn bad(code: &'static str, why: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, why)
    }

    /// 403 Forbidden.
    #[allow(dead_code)]
    pub(crate) fn forbidden(code: &'static str, why: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, code, why)
    }

    /// 404 Not Found.
    #[allow(dead_code)]
    pub(crate) fn not_found(code: &'static str, why: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, code, why)
    }

    /// Décompose en la paire `(StatusCode, Json<Value>)` — enveloppe STRICTEMENT identique à
    /// `into_response` — pour les handlers `impl IntoResponse` dont le type concret de retour est
    /// déjà ce tuple (on ne peut y injecter un `Response` sans casser l'unicité du type concret).
    pub(crate) fn into_parts(self) -> (StatusCode, Json<serde_json::Value>) {
        (self.status, Json(json!({ "error": self.code, "why": self.why })))
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.code, "why": self.why }))).into_response()
    }
}

/// Handler-result alias for the upcoming ApiResult migration (Wave 2 — handlers not yet migrated).
#[allow(dead_code)]
pub(crate) type ApiResult<T> = Result<T, ApiError>;
