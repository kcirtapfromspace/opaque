# Shared Opaque brand assets

`opaque.css` is the canonical warm charcoal / paper palette, typography, and
radius foundation for the documentation, dashboard, and showcase. It preserves
the website's existing color values. Components and interaction styles stay in
their respective applications. Dark is the default; `data-op-color-scheme`
accepts `dark` / `light`, and the existing Material `data-md-color-scheme`
`slate` / `default` selectors remain supported.

`opaque-mark.svg` preserves the existing three-bar redaction glyph. Local Rust
servers include only the explicit `embedded.rs` allowlist under `/brand/`.
The MkDocs hook copies the same manifest entries to `brand/`; it never publishes
this folder wholesale or uses a symlink. Source files and the manifest are not
browser assets.

The six font files are unmodified TrueType files from the official
[Google Fonts repository](https://github.com/google/fonts), pinned to commit
`8e44913e4ff26fc997e6856c1ec40ff4791c98c5`. Archivo includes variable normal and
italic faces; IBM Plex Mono includes regular and bold in both styles. Both
families use the SIL Open Font License; their original license files are
included and served alongside the fonts. `manifest.json` records exact upstream
URLs and SHA-256 hashes. Browser font requests use only the serving origin.

When changing an asset, update its hash in `manifest.json`; when adding an
asset, also add it to `embedded.rs`. `scripts/test_brand_assets.py` checks that
the Rust and documentation publication lists agree and all font CSS resources
are local and licensed. The generated site must still pass the existing privacy
gate before any publication.
