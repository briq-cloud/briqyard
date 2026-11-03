//! The CPU template every x86_64 guest boots with: no virtualization extensions (ADR 0087).

use serde_json::{json, Value};

/// The SVM feature identification leaf (AMD).
const SVM_LEAF: u32 = 0x8000_000A;

/// A Firecracker bitmap, most significant bit first: `x` keeps a bit, `0` clears it.
fn clear(bit: u32) -> String {
    let bits: String = (0..32)
        .rev()
        .map(|i| if i == bit { '0' } else { 'x' })
        .collect();
    format!("0b{bits}")
}

fn registers(leaf: u32, registers: &[(&str, String)]) -> Value {
    json!({
        "leaf": format!("{leaf:#x}"),
        "subleaf": "0x0",
        "flags": 0,
        "modifiers": registers
            .iter()
            .map(|(register, bitmap)| json!({"register": register, "bitmap": bitmap}))
            .collect::<Vec<_>>(),
    })
}

/// VMX (leaf 1, ECX bit 5) and SVM (leaf 0x80000001, ECX bit 2) cleared; the SVM feature
/// leaf zeroed when the host has it. Firecracker refuses a modifier for a leaf that KVM does
/// not list, and KVM lists an extended leaf only up to the host's own limit, so a host
/// without leaf 0x8000000A (every Intel CPU) gets no modifier for it.
pub fn template(host_max_extended_leaf: u32) -> Value {
    let mut leaves = vec![
        registers(0x1, &[("ecx", clear(5))]),
        registers(0x8000_0001, &[("ecx", clear(2))]),
    ];
    if host_max_extended_leaf >= SVM_LEAF {
        let zero = format!("0b{}", "0".repeat(32));
        leaves.push(registers(
            SVM_LEAF,
            &["eax", "ebx", "ecx", "edx"].map(|r| (r, zero.clone())),
        ));
    }
    json!({"cpuid_modifiers": leaves})
}

/// What this host's guests boot with; none where Firecracker gives a guest no EL2.
#[cfg(target_arch = "x86_64")]
pub fn host_template() -> Option<Value> {
    // `__cpuid` is unsafe up to Rust 1.86 (the crate's minimum is 1.85) and safe after.
    // SAFETY: CPUID is available on every x86_64 CPU.
    #[allow(unused_unsafe)]
    let max = unsafe { std::arch::x86_64::__cpuid(0x8000_0000) }.eax;
    Some(template(max))
}

#[cfg(not(target_arch = "x86_64"))]
pub fn host_template() -> Option<Value> {
    None
}

/// The identity of a template: the SHA-256 of the JSON as sent, `none` without one.
pub fn digest(template: Option<&Value>) -> String {
    use sha2::{Digest, Sha256};
    match template {
        Some(t) => hex::encode(Sha256::digest(t.to_string().as_bytes())),
        None => "none".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(t: &Value) -> Vec<(String, Vec<(String, String)>)> {
        t["cpuid_modifiers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| {
                (
                    l["leaf"].as_str().unwrap().to_string(),
                    l["modifiers"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|m| {
                            (
                                m["register"].as_str().unwrap().to_string(),
                                m["bitmap"].as_str().unwrap().to_string(),
                            )
                        })
                        .collect(),
                )
            })
            .collect()
    }

    #[test]
    fn clears_vmx_and_svm_and_nothing_else() {
        let l = leaves(&template(0x8000_0008));
        assert_eq!(l.len(), 2);
        assert_eq!(l[0].0, "0x1");
        // Bit 5 of 32, counted from the most significant: position 26.
        assert_eq!(
            l[0].1,
            [("ecx".into(), "0bxxxxxxxxxxxxxxxxxxxxxxxxxx0xxxxx".into())]
        );
        assert_eq!(l[1].0, "0x80000001");
        assert_eq!(
            l[1].1,
            [("ecx".into(), "0bxxxxxxxxxxxxxxxxxxxxxxxxxxxxx0xx".into())]
        );
        for (_, regs) in &l {
            for (_, bitmap) in regs {
                assert_eq!(bitmap.len(), 2 + 32);
                assert_eq!(bitmap.matches('0').count(), 1 + 1);
            }
        }
    }

    #[test]
    fn svm_leaf_only_where_the_host_has_it() {
        for max in [0x8000_0008, 0x8000_0009] {
            assert_eq!(leaves(&template(max)).len(), 2, "{max:#x}");
        }
        for max in [0x8000_000A, 0x8000_0021, 0x8000_0026] {
            let l = leaves(&template(max));
            assert_eq!(l.len(), 3, "{max:#x}");
            assert_eq!(l[2].0, "0x8000000a");
            let registers: Vec<_> = l[2].1.iter().map(|(r, _)| r.as_str()).collect();
            assert_eq!(registers, ["eax", "ebx", "ecx", "edx"]);
            assert!(l[2]
                .1
                .iter()
                .all(|(_, b)| b == &format!("0b{}", "0".repeat(32))));
        }
    }

    #[test]
    fn digest_follows_the_template() {
        let a = template(0x8000_0008);
        let b = template(0x8000_000A);
        assert_eq!(digest(None), "none");
        assert_eq!(digest(Some(&a)), digest(Some(&template(0x8000_0008))));
        assert_ne!(digest(Some(&a)), digest(Some(&b)));
        assert_eq!(digest(Some(&a)).len(), 64);
    }
}
