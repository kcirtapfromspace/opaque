//! Only compile-time, public brand assets are available while the UI is locked.

use axum::extract::Path;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};

#[path = "../../../../assets/brand/embedded.rs"]
pub(crate) mod assets;

pub async fn get_asset(Path(path): Path<String>) -> Response {
    match assets::get(&path) {
        Some(asset) => ([(header::CONTENT_TYPE, asset.content_type)], asset.bytes).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
