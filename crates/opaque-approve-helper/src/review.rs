//! Trusted full-text review UI. This is only an intent confirmation; the
//! daemon still requires the configured biometric/authentication factor.

/// Checks capability only: creates no window, solicits no decision and cannot
/// establish that a human will see a subsequent review.
#[cfg(target_os = "macos")]
pub fn check_ui() -> Result<(), &'static str> {
    use objc2::MainThreadMarker;
    use objc2_app_kit::NSScreen;
    use std::os::unix::fs::MetadataExt;

    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    let console_uid = std::fs::metadata("/dev/console")
        .map_err(|_| "cannot inspect the active macOS console session")?
        .uid();
    // SAFETY: geteuid has no preconditions and returns the calling account.
    if console_uid == 0 || console_uid != unsafe { geteuid() } {
        return Err("run the reviewer as the signed-in macOS console user");
    }
    let mtm = MainThreadMarker::new().ok_or("native review requires the main thread")?;
    if NSScreen::mainScreen(mtm).is_none() {
        return Err("no macOS screen is available; use an interactive desktop session");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn check_ui() -> Result<(), &'static str> {
    use std::process::{Command, Stdio};
    if !["DISPLAY", "WAYLAND_DISPLAY"]
        .iter()
        .any(|name| std::env::var_os(name).is_some_and(|value| !value.is_empty()))
    {
        return Err("no Linux display is configured; use an interactive desktop session");
    }
    let mut command = Command::new("zenity");
    crate::process::bind_to_parent(&mut command);
    let status = command
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| "zenity is required for full-document native review")?;
    if !status.success() {
        return Err("zenity is unavailable in this desktop session");
    }
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn check_ui() -> Result<(), &'static str> {
    Err("native review is unsupported on this platform")
}

fn stage(name: &str) {
    use std::io::Write;
    // Fixed stage names only; never send the reviewed document to logs.
    println!("opaque-review-stage: {name}");
    let _ = std::io::stdout().flush();
}

#[cfg(target_os = "macos")]
pub fn show(reason: &str) -> Result<bool, &'static str> {
    use objc2::{MainThreadMarker, MainThreadOnly};
    use objc2_app_kit::{
        NSAlert, NSAlertFirstButtonReturn, NSApplication, NSApplicationActivationPolicy,
        NSAutoresizingMaskOptions, NSFont, NSScrollView, NSTextView,
    };
    use objc2_foundation::{NSPoint, NSRect, NSSize, NSString};

    check_ui()?;
    stage("ui-ready");
    let mtm = MainThreadMarker::new().ok_or("native review requires the main thread")?;
    let application = NSApplication::sharedApplication(mtm);
    if application.activationPolicy() == NSApplicationActivationPolicy::Prohibited
        && !application.setActivationPolicy(NSApplicationActivationPolicy::Accessory)
    {
        return Err("macOS refused the native review activation policy");
    }
    // A standalone helper never calls NSApplication.run(), which normally
    // completes this launch sequence before servicing windows.
    application.finishLaunching();
    let alert = NSAlert::new(mtm);
    alert.setMessageText(&NSString::from_str("Review Opaque task"));
    alert.setInformativeText(&NSString::from_str(
        "Review every destination, source version, credential reference, and limit below. Confirm review to continue to authentication. This review alone does not authorize a write."
    ));
    let confirm = alert.addButtonWithTitle(&NSString::from_str("Confirm review"));
    // Do not let an accidental Return key approve a long document.
    confirm.setKeyEquivalent(&NSString::from_str(""));
    let cancel = alert.addButtonWithTitle(&NSString::from_str("Cancel"));
    cancel.setKeyEquivalent(&NSString::from_str("\u{1b}"));

    let frame = NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(720.0, 420.0));
    let scroll = NSScrollView::initWithFrame(NSScrollView::alloc(mtm), frame);
    scroll.setHasVerticalScroller(true);
    scroll.setHasHorizontalScroller(false);
    let text = NSTextView::initWithFrame(NSTextView::alloc(mtm), frame);
    text.setEditable(false);
    text.setSelectable(true);
    text.setRichText(false);
    text.setMinSize(NSSize::new(0.0, 420.0));
    text.setMaxSize(NSSize::new(f64::MAX, f64::MAX));
    text.setVerticallyResizable(true);
    text.setHorizontallyResizable(false);
    text.setAutoresizingMask(NSAutoresizingMaskOptions::ViewWidthSizable);
    text.setTextContainerInset(NSSize::new(12.0, 12.0));
    // SAFETY: this fresh text view owns its layout container, and all access
    // stays on the AppKit main thread for the lifetime of the modal review.
    if let Some(container) = unsafe { text.textContainer() } {
        container.setContainerSize(NSSize::new(696.0, f64::MAX));
        container.setWidthTracksTextView(true);
    }
    text.setFont(NSFont::userFixedPitchFontOfSize(12.0).as_deref());
    text.setString(&NSString::from_str(reason));
    scroll.setDocumentView(Some(&text));
    alert.setAccessoryView(Some(&scroll));
    alert.layout();
    let window = alert.window();
    window.center();
    application.activate();
    // activate() is best effort. Order the review explicitly so a helper
    // launched from a background broker does not rely on focus transfer alone.
    window.makeKeyAndOrderFront(None);
    window.orderFrontRegardless();
    if !window.isVisible() {
        return Err("macOS did not order the review window; inspect the desktop session");
    }
    // This is AppKit window state, not proof a human observed the document.
    stage("window-ordered");
    let approved = alert.runModal() == NSAlertFirstButtonReturn;
    stage(if approved {
        "review-confirmed"
    } else {
        "review-cancelled"
    });
    Ok(approved)
}

#[cfg(target_os = "linux")]
pub fn show(reason: &str) -> Result<bool, &'static str> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    check_ui()?;
    stage("ui-ready");
    // Text-info supplies a scrollable plain-text document. The checkbox must
    // be selected before zenity enables OK; never fall back to a short dialog.
    let mut command = Command::new("zenity");
    crate::process::bind_to_parent(&mut command);
    let mut child = command
        .args([
            "--text-info",
            "--title=Review Opaque task",
            "--width=820",
            "--height=640",
            "--checkbox=I reviewed every action and limit",
            "--ok-label=Confirm review",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "could not start the native review window")?;
    child
        .stdin
        .take()
        .ok_or("could not send the full document to the native review window")?
        .write_all(reason.as_bytes())
        .map_err(|_| "could not send the full document to the native review window")?;
    stage("dialog-started");
    match child
        .wait()
        .map_err(|_| "native review process failed")?
        .code()
    {
        Some(0) => {
            stage("review-confirmed");
            Ok(true)
        }
        Some(1) => {
            stage("review-cancelled");
            Ok(false)
        }
        _ => Err("native review window failed; inspect the desktop session"),
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn show(_reason: &str) -> Result<bool, &'static str> {
    Err("native review is unsupported on this platform")
}
