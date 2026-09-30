//! Pure delivery state for tray icon and tooltip updates.
//!
//! The Windows adapter supplies the shell calls. Keeping their schedule here lets
//! host-native tests cover resume failures without Win32 or Explorer.

const FIRST_RECOVERY_FAILURES: u32 = 2;
const RECOVERY_BACKOFF_FIRST: u32 = 30;
const RECOVERY_BACKOFF_MAX: u32 = 10 * 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ShellCall<P> {
    Modify(P),
    Add,
    Delete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IconDisposition {
    Delivered,
    ReAdded,
    Unused,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Diagnostic {
    None,
    ModifyFailed,
    ReAdded,
    ReAddFailed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Attempt {
    pub(crate) icon: IconDisposition,
    pub(crate) diagnostic: Diagnostic,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DeliveryState<C> {
    rendered: Option<C>,
    pending_target: Option<C>,
    failures_since_recovery: u32,
    recovery_after: u32,
    readded: bool,
    failure_logged: bool,
}

impl<C: Copy + Eq> DeliveryState<C> {
    pub(crate) const fn new() -> Self {
        Self {
            rendered: None,
            pending_target: None,
            failures_since_recovery: 0,
            recovery_after: FIRST_RECOVERY_FAILURES,
            readded: false,
            failure_logged: false,
        }
    }

    #[cfg(test)]
    fn shown(condition: C) -> Self {
        Self { rendered: Some(condition), ..Self::new() }
    }

    pub(crate) fn needs_update(self, target: C) -> bool {
        self.pending_target.is_some() || self.rendered != Some(target)
    }

    pub(crate) fn invalidate(&mut self) {
        *self = Self::new();
    }

    pub(crate) fn attempt<P: Copy>(
        &mut self,
        target: C,
        content: P,
        mut shell: impl FnMut(ShellCall<P>) -> bool,
    ) -> Attempt {
        if shell(ShellCall::Modify(content)) {
            self.rendered = Some(target);
            self.pending_target = None;
            self.failures_since_recovery = 0;
            self.recovery_after = FIRST_RECOVERY_FAILURES;
            self.readded = false;
            self.failure_logged = false;
            return Attempt { icon: IconDisposition::Delivered, diagnostic: Diagnostic::None };
        }

        if self.pending_target != Some(target) {
            self.pending_target = Some(target);
            self.failures_since_recovery = 0;
            self.recovery_after = FIRST_RECOVERY_FAILURES;
            self.readded = false;
            self.failure_logged = false;
        }
        self.failures_since_recovery = self.failures_since_recovery.saturating_add(1);

        if !self.readded && self.failures_since_recovery >= self.recovery_after {
            let added = shell(ShellCall::Add) || {
                let _ = shell(ShellCall::Delete);
                shell(ShellCall::Add)
            };
            self.failures_since_recovery = 0;
            if added {
                self.readded = true;
                return Attempt { icon: IconDisposition::ReAdded, diagnostic: Diagnostic::ReAdded };
            }
            self.recovery_after = if self.recovery_after == FIRST_RECOVERY_FAILURES {
                RECOVERY_BACKOFF_FIRST
            } else {
                self.recovery_after.saturating_mul(2).min(RECOVERY_BACKOFF_MAX)
            };
            return Attempt { icon: IconDisposition::Unused, diagnostic: Diagnostic::ReAddFailed };
        }

        let diagnostic = if self.failure_logged {
            Diagnostic::None
        } else {
            self.failure_logged = true;
            Diagnostic::ModifyFailed
        };
        Attempt { icon: IconDisposition::Unused, diagnostic }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Condition {
        Working,
        Stopped,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Content {
        icon: &'static str,
        tooltip: &'static str,
    }

    #[test]
    fn first_failed_modify_retries_once_on_the_next_heartbeat() {
        let mut state = DeliveryState::shown(Condition::Working);
        let mut calls = Vec::new();

        let first = state.attempt(Condition::Stopped, (), |call| {
            calls.push(call);
            false
        });
        assert_eq!(first.icon, IconDisposition::Unused);
        assert_eq!(first.diagnostic, Diagnostic::ModifyFailed);
        assert!(state.needs_update(Condition::Stopped));

        let second = state.attempt(Condition::Stopped, (), |call| {
            calls.push(call);
            matches!(call, ShellCall::Modify(()))
        });
        assert_eq!(second.icon, IconDisposition::Delivered);
        assert_eq!(calls, [ShellCall::Modify(()), ShellCall::Modify(())]);
        assert!(!state.needs_update(Condition::Stopped));
    }

    #[test]
    fn long_failure_streak_bounds_and_backs_off_readd_and_logs() {
        let mut state = DeliveryState::shown(Condition::Working);
        let mut calls = Vec::new();
        let mut diagnostics = Vec::new();

        for _ in 0..2_000 {
            let attempt = state.attempt(Condition::Stopped, (), |call| {
                calls.push(call);
                false
            });
            if attempt.diagnostic != Diagnostic::None {
                diagnostics.push(attempt.diagnostic);
            }
        }

        assert_eq!(
            calls.iter().filter(|call| matches!(call, ShellCall::Modify(()))).count(),
            2_000
        );
        assert_eq!(calls.iter().filter(|call| matches!(call, ShellCall::Delete)).count(), 7);
        assert_eq!(calls.iter().filter(|call| matches!(call, ShellCall::Add)).count(), 14);
        assert_eq!(diagnostics.len(), 8);

        let first_new_target = state.attempt(Condition::Working, (), |_| false);
        assert_eq!(first_new_target.diagnostic, Diagnostic::ModifyFailed);
        let mut reset_calls = Vec::new();
        let second_new_target = state.attempt(Condition::Working, (), |call| {
            reset_calls.push(call);
            false
        });
        assert_eq!(second_new_target.diagnostic, Diagnostic::ReAddFailed);
        assert_eq!(
            reset_calls,
            [ShellCall::Modify(()), ShellCall::Add, ShellCall::Delete, ShellCall::Add]
        );
    }

    #[test]
    fn successful_modify_delivers_one_icon_and_tooltip_snapshot() {
        let content = Content { icon: "stopped", tooltip: "NAS Access — No access" };
        let mut state = DeliveryState::shown(Condition::Working);
        let mut delivered = Vec::new();

        let attempt = state.attempt(Condition::Stopped, content, |call| {
            if let ShellCall::Modify(delivered_content) = call {
                delivered.push(delivered_content);
                true
            } else {
                false
            }
        });

        assert_eq!(attempt.icon, IconDisposition::Delivered);
        assert_eq!(delivered, [content]);
    }

    #[test]
    fn successful_readd_stays_pending_until_the_next_modify_lands() {
        let mut state = DeliveryState::shown(Condition::Working);
        let _ = state.attempt(Condition::Stopped, (), |_| false);
        let mut calls = Vec::new();

        let recovered = state.attempt(Condition::Stopped, (), |call| {
            calls.push(call);
            call == ShellCall::Add
        });
        assert_eq!(recovered.icon, IconDisposition::ReAdded);
        assert_eq!(recovered.diagnostic, Diagnostic::ReAdded);
        assert_eq!(calls, [ShellCall::Modify(()), ShellCall::Add]);
        assert!(state.needs_update(Condition::Stopped));

        let delivered = state.attempt(Condition::Stopped, (), |call| call == ShellCall::Modify(()));
        assert_eq!(delivered.icon, IconDisposition::Delivered);
        assert!(!state.needs_update(Condition::Stopped));

        state.invalidate();
        assert!(state.needs_update(Condition::Stopped));
    }

    #[test]
    fn retries_only_request_status_delivery_and_never_a_balloon() {
        let mut state = DeliveryState::shown(Condition::Working);
        let mut calls = Vec::new();

        for _ in 0..3 {
            let _ = state.attempt(Condition::Stopped, (), |call| {
                calls.push(call);
                false
            });
        }

        assert_eq!(
            calls,
            [
                ShellCall::Modify(()),
                ShellCall::Modify(()),
                ShellCall::Add,
                ShellCall::Delete,
                ShellCall::Add,
                ShellCall::Modify(()),
            ]
        );
    }
}
