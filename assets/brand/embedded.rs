//! Compile-time public brand allowlist shared by local web surfaces.
//!
//! This module intentionally has no dependencies. Never replace the allowlist
//! with directory serving: this folder also contains build metadata and source.

pub struct BrandAsset {
    pub path: &'static str,
    pub content_type: &'static str,
    pub bytes: &'static [u8],
}

pub static ASSETS: &[BrandAsset] = &[
    BrandAsset {
        path: "fonts/archivo-variable.ttf",
        content_type: "font/ttf",
        bytes: include_bytes!("fonts/archivo-variable.ttf"),
    },
    BrandAsset {
        path: "fonts/archivo-variable-italic.ttf",
        content_type: "font/ttf",
        bytes: include_bytes!("fonts/archivo-variable-italic.ttf"),
    },
    BrandAsset {
        path: "fonts/ibm-plex-mono-regular.ttf",
        content_type: "font/ttf",
        bytes: include_bytes!("fonts/ibm-plex-mono-regular.ttf"),
    },
    BrandAsset {
        path: "fonts/ibm-plex-mono-italic.ttf",
        content_type: "font/ttf",
        bytes: include_bytes!("fonts/ibm-plex-mono-italic.ttf"),
    },
    BrandAsset {
        path: "fonts/ibm-plex-mono-bold.ttf",
        content_type: "font/ttf",
        bytes: include_bytes!("fonts/ibm-plex-mono-bold.ttf"),
    },
    BrandAsset {
        path: "fonts/ibm-plex-mono-bold-italic.ttf",
        content_type: "font/ttf",
        bytes: include_bytes!("fonts/ibm-plex-mono-bold-italic.ttf"),
    },
    BrandAsset {
        path: "licenses/archivo-OFL.txt",
        content_type: "text/plain; charset=utf-8",
        bytes: include_bytes!("licenses/archivo-OFL.txt"),
    },
    BrandAsset {
        path: "licenses/ibm-plex-mono-OFL.txt",
        content_type: "text/plain; charset=utf-8",
        bytes: include_bytes!("licenses/ibm-plex-mono-OFL.txt"),
    },
    BrandAsset {
        path: "opaque.css",
        content_type: "text/css; charset=utf-8",
        bytes: include_bytes!("opaque.css"),
    },
    BrandAsset {
        path: "opaque-mark.svg",
        content_type: "image/svg+xml",
        bytes: include_bytes!("opaque-mark.svg"),
    },
];

pub fn get(path: &str) -> Option<&'static BrandAsset> {
    ASSETS.iter().find(|asset| asset.path == path)
}
