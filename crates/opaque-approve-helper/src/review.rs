//! Trusted full-text review UI. This is only an intent confirmation; the
//! daemon still requires the configured biometric/authentication factor.

#[cfg(target_os = "macos")]
pub fn show(reason: &str) -> Result<bool, ()> {
    use objc2::{MainThreadMarker, MainThreadOnly};
    use objc2_app_kit::{
        NSAlert, NSAlertFirstButtonReturn, NSApplication, NSApplicationActivationPolicy,
        NSAutoresizingMaskOptions, NSFont, NSScrollView, NSTextView,
    };
    use objc2_foundation::{NSPoint, NSRect, NSSize, NSString};

    let mtm = MainThreadMarker::new().ok_or(())?;
    let application = NSApplication::sharedApplication(mtm);
    if application.activationPolicy() == NSApplicationActivationPolicy::Prohibited
        && !application.setActivationPolicy(NSApplicationActivationPolicy::Accessory)
    {
        return Err(());
    }
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
    application.activate();
    Ok(alert.runModal() == NSAlertFirstButtonReturn)
}

#[cfg(target_os = "linux")]
pub fn show(reason: &str) -> Result<bool, ()> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    // Text-info supplies a scrollable plain-text document. The checkbox must
    // be selected before zenity enables OK; never fall back to a short dialog.
    let mut child = Command::new("zenity")
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
        .map_err(|_| ())?;
    child
        .stdin
        .take()
        .ok_or(())?
        .write_all(reason.as_bytes())
        .map_err(|_| ())?;
    match child.wait().map_err(|_| ())?.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err(()),
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn show(_reason: &str) -> Result<bool, ()> {
    Err(())
}
