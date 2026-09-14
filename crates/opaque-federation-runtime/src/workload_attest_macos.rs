//! Native dynamic code validation. An audit token binds the guest lookup to a
//! process incarnation, avoiding PID reuse and executable-path replacement.
//! Only Apple-anchored certificate signatures can produce a trusted Team ID.

use std::ffi::{c_char, c_void};
use std::ptr;

type CfRef = *const c_void;

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecGuestAttributeAudit: CfRef;
    static kSecCodeInfoTeamIdentifier: CfRef;
    fn SecCodeCopyGuestWithAttributes(
        host: CfRef,
        attributes: CfRef,
        flags: u32,
        guest: *mut CfRef,
    ) -> i32;
    fn SecRequirementCreateWithString(text: CfRef, flags: u32, requirement: *mut CfRef) -> i32;
    fn SecCodeCheckValidity(code: CfRef, flags: u32, requirement: CfRef) -> i32;
    fn SecCodeCopySigningInformation(code: CfRef, flags: u32, information: *mut CfRef) -> i32;
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFRelease(value: CfRef);
    fn CFDataCreate(allocator: CfRef, bytes: *const u8, length: isize) -> CfRef;
    fn CFDictionaryCreate(
        allocator: CfRef,
        keys: *const CfRef,
        values: *const CfRef,
        count: isize,
        key_callbacks: CfRef,
        value_callbacks: CfRef,
    ) -> CfRef;
    fn CFDictionaryGetValue(dictionary: CfRef, key: CfRef) -> CfRef;
    fn CFStringCreateWithCString(allocator: CfRef, text: *const c_char, encoding: u32) -> CfRef;
    fn CFStringGetCString(string: CfRef, buffer: *mut c_char, size: isize, encoding: u32) -> bool;
    fn CFGetTypeID(value: CfRef) -> usize;
    fn CFStringGetTypeID() -> usize;
}

struct OwnedCf(CfRef);

impl OwnedCf {
    fn new(value: CfRef) -> Option<Self> {
        (!value.is_null()).then_some(Self(value))
    }
}

impl Drop for OwnedCf {
    fn drop(&mut self) {
        // SAFETY: every OwnedCf wraps one retained create/copy result.
        unsafe { CFRelease(self.0) };
    }
}

pub(super) fn validated_team_id(audit_token: &[u32; 8]) -> Option<String> {
    // SAFETY: native APIs receive valid CF objects retained for each call's
    // duration. Copy/create results are released once; dictionary values are
    // borrowed only while their owning dictionary is alive. No pointer escapes.
    unsafe {
        let token = OwnedCf::new(CFDataCreate(
            ptr::null(),
            audit_token.as_ptr().cast(),
            std::mem::size_of_val(audit_token) as isize,
        ))?;
        let attribute_key = kSecGuestAttributeAudit;
        let attributes = OwnedCf::new(CFDictionaryCreate(
            ptr::null(),
            &attribute_key,
            &token.0,
            1,
            ptr::null(),
            ptr::null(),
        ))?;
        let mut guest = ptr::null();
        if SecCodeCopyGuestWithAttributes(ptr::null(), attributes.0, 0, &mut guest) != 0 {
            return None;
        }
        let guest = OwnedCf::new(guest)?;
        const UTF8: u32 = 0x0800_0100;
        let text = OwnedCf::new(CFStringCreateWithCString(
            ptr::null(),
            c"anchor apple generic".as_ptr(),
            UTF8,
        ))?;
        let mut requirement = ptr::null();
        if SecRequirementCreateWithString(text.0, 0, &mut requirement) != 0 {
            return None;
        }
        let requirement = OwnedCf::new(requirement)?;
        if SecCodeCheckValidity(guest.0, 0, requirement.0) != 0 {
            return None;
        }
        let mut information = ptr::null();
        const SIGNING_INFORMATION: u32 = 1 << 1;
        if SecCodeCopySigningInformation(guest.0, SIGNING_INFORMATION, &mut information) != 0 {
            return None;
        }
        let information = OwnedCf::new(information)?;
        let team = CFDictionaryGetValue(information.0, kSecCodeInfoTeamIdentifier);
        if team.is_null() || CFGetTypeID(team) != CFStringGetTypeID() {
            return None;
        }
        let mut bytes = [0u8; 65];
        if !CFStringGetCString(team, bytes.as_mut_ptr().cast(), bytes.len() as isize, UTF8) {
            return None;
        }
        let length = bytes.iter().position(|byte| *byte == 0)?;
        let value = std::str::from_utf8(&bytes[..length]).ok()?;
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
            return None;
        }
        Some(value.into())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn missing_or_fabricated_process_incarnation_never_produces_a_team() {
        assert!(validated_team_id(&[0; 8]).is_none());
        let mut token = [0; 8];
        token[5] = std::process::id();
        token[7] = u32::MAX;
        assert!(validated_team_id(&token).is_none());
    }
}
