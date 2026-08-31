//! This duplicates `kerbridge_core::secret::Secret` because the isolated client
//! workspace does not depend on `kerbridge-core`. See
//! `crates/kerbridge-core/GLOSSARY.md`.

use std::fmt;

use zeroize::Zeroizing;

const REDACTED: &str = "<redacted>";

/// A credential in memory.
///
/// `Debug` prints `<redacted>`, and `Secret` has no `Display`, so accidental
/// formatting fails to compile. [`expose`](Secret::expose) returns the plaintext.
/// Each clone zeroizes its allocation on drop.
#[derive(Clone)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    /// The plaintext, named so that every use of it is one grep away.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_and_only_the_accessor_does_not() {
        let secret = Secret::new("Kb1-hunter2");
        assert_eq!(format!("{secret:?}"), REDACTED);
        assert_eq!(secret.expose(), "Kb1-hunter2");

        #[derive(Debug)]
        struct Holder {
            password: Secret,
        }
        let holder = Holder { password: Secret::new("Kb1-hunter2") };
        let held = format!("{holder:?}");
        assert!(!held.contains("hunter2"), "{held}");
        assert!(held.contains(REDACTED), "{held}");
        assert_eq!(holder.password.expose(), "Kb1-hunter2");
    }
}
