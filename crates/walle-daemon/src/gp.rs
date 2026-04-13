use std::net::IpAddr;

use tracing::{debug, info, warn};
use walle_policy::{GpPolicy, GpStrategyKind, GpTriggerMode};

use crate::detector::{SshBanDecision, SshFailureEvent, SshFailureReason};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GpAdapterKind {
    Ssh,
}

impl GpAdapterKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ssh => "ssh",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GpTriggerKind {
    SignalObserved,
    DecisionEmitted,
}

impl GpTriggerKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SignalObserved => "signal_observed",
            Self::DecisionEmitted => "decision_emitted",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GpExecutionStatus {
    Disabled,
    TriggerFiltered,
    Observed,
    FailedOpen,
}

impl GpExecutionStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::TriggerFiltered => "trigger_filtered",
            Self::Observed => "observed",
            Self::FailedOpen => "failed_open",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GpExecutionError {
    StrategyUnavailable { strategy: GpStrategyKind },
}

impl GpExecutionError {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::StrategyUnavailable { .. } => "strategy_unavailable",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GpExecutionOutcome {
    pub adapter: GpAdapterKind,
    pub trigger: GpTriggerKind,
    pub strategy: GpStrategyKind,
    pub status: GpExecutionStatus,
    pub source_ip: IpAddr,
    pub error: Option<GpExecutionError>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GpAdapterRequest {
    Ssh(SshGpRequest),
}

impl GpAdapterRequest {
    #[must_use]
    pub const fn adapter_kind(&self) -> GpAdapterKind {
        match self {
            Self::Ssh(_) => GpAdapterKind::Ssh,
        }
    }

    #[must_use]
    pub const fn trigger_kind(&self) -> GpTriggerKind {
        match self {
            Self::Ssh(request) => request.trigger_kind,
        }
    }

    #[must_use]
    pub const fn source_ip(&self) -> IpAddr {
        match self {
            Self::Ssh(request) => request.source_ip,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshGpRequest {
    pub trigger_kind: GpTriggerKind,
    pub observed_at_secs: u64,
    pub source_ip: IpAddr,
    pub username: Option<String>,
    pub failure_reason: Option<SshFailureReason>,
    pub matched_failures: Option<usize>,
    pub expires_at_secs: Option<u64>,
}

impl SshGpRequest {
    #[must_use]
    pub fn from_failure_event(event: &SshFailureEvent, observed_at_secs: u64) -> Self {
        Self {
            trigger_kind: GpTriggerKind::SignalObserved,
            observed_at_secs,
            source_ip: event.ip,
            username: None,
            failure_reason: Some(event.reason),
            matched_failures: None,
            expires_at_secs: None,
        }
    }

    #[must_use]
    pub fn from_ban_decision(decision: &SshBanDecision) -> Self {
        Self {
            trigger_kind: GpTriggerKind::DecisionEmitted,
            observed_at_secs: decision.observed_at_secs,
            source_ip: decision.ip,
            username: None,
            failure_reason: None,
            matched_failures: Some(decision.matched_failures),
            expires_at_secs: Some(decision.expires_at_secs),
        }
    }
}

#[derive(Clone, Debug)]
pub struct GpExecutor {
    policy: GpPolicy,
}

impl GpExecutor {
    #[must_use]
    pub fn new(policy: GpPolicy) -> Self {
        Self { policy }
    }

    #[must_use]
    pub const fn policy(&self) -> &GpPolicy {
        &self.policy
    }

    #[must_use]
    pub fn describe(&self) -> String {
        format!(
            "gp: enabled={}, strategy={}, trigger_mode={}",
            self.policy.enabled,
            self.policy.strategy.as_str(),
            self.policy.trigger_mode.as_str()
        )
    }

    pub fn log_startup(&self) {
        info!(
            component = "gp",
            event = "policy_loaded",
            enabled = self.policy.enabled,
            strategy = self.policy.strategy.as_str(),
            trigger_mode = self.policy.trigger_mode.as_str(),
            "prepared GP execution policy"
        );
    }

    #[must_use]
    pub fn execute(&self, request: GpAdapterRequest) -> GpExecutionOutcome {
        let outcome = if !self.policy.enabled {
            self.build_outcome(&request, GpExecutionStatus::Disabled, None)
        } else if !trigger_mode_matches(self.policy.trigger_mode, request.trigger_kind()) {
            self.build_outcome(&request, GpExecutionStatus::TriggerFiltered, None)
        } else {
            match self.policy.strategy {
                GpStrategyKind::Observe => {
                    self.build_outcome(&request, GpExecutionStatus::Observed, None)
                }
                GpStrategyKind::Degrade | GpStrategyKind::Contain => self.build_outcome(
                    &request,
                    GpExecutionStatus::FailedOpen,
                    Some(GpExecutionError::StrategyUnavailable {
                        strategy: self.policy.strategy,
                    }),
                ),
            }
        };

        self.log_outcome(&request, &outcome);
        outcome
    }

    #[must_use]
    fn build_outcome(
        &self,
        request: &GpAdapterRequest,
        status: GpExecutionStatus,
        error: Option<GpExecutionError>,
    ) -> GpExecutionOutcome {
        GpExecutionOutcome {
            adapter: request.adapter_kind(),
            trigger: request.trigger_kind(),
            strategy: self.policy.strategy,
            status,
            source_ip: request.source_ip(),
            error,
        }
    }

    fn log_outcome(&self, request: &GpAdapterRequest, outcome: &GpExecutionOutcome) {
        match request {
            GpAdapterRequest::Ssh(ssh) => {
                if matches!(outcome.status, GpExecutionStatus::FailedOpen) {
                    warn!(
                        component = "gp",
                        event = "execution_result",
                        adapter = outcome.adapter.as_str(),
                        trigger = outcome.trigger.as_str(),
                        strategy = outcome.strategy.as_str(),
                        result = outcome.status.as_str(),
                        ip = %outcome.source_ip,
                        observed_at_secs = ssh.observed_at_secs,
                        failure_reason = ?ssh.failure_reason,
                        matched_failures = ?ssh.matched_failures,
                        expires_at_secs = ?ssh.expires_at_secs,
                        error = outcome
                            .error
                            .as_ref()
                            .map(GpExecutionError::as_str)
                            .unwrap_or("none"),
                        "GP execution failed open; baseline enforcement continues"
                    );
                } else {
                    debug!(
                        component = "gp",
                        event = "execution_result",
                        adapter = outcome.adapter.as_str(),
                        trigger = outcome.trigger.as_str(),
                        strategy = outcome.strategy.as_str(),
                        result = outcome.status.as_str(),
                        ip = %outcome.source_ip,
                        observed_at_secs = ssh.observed_at_secs,
                        failure_reason = ?ssh.failure_reason,
                        matched_failures = ?ssh.matched_failures,
                        expires_at_secs = ?ssh.expires_at_secs,
                        error = outcome
                            .error
                            .as_ref()
                            .map(GpExecutionError::as_str)
                            .unwrap_or("none"),
                        "GP execution outcome recorded"
                    );
                }
            }
        }
    }
}

const fn trigger_mode_matches(mode: GpTriggerMode, trigger: GpTriggerKind) -> bool {
    match trigger {
        GpTriggerKind::SignalObserved => mode.matches_signal_observed(),
        GpTriggerKind::DecisionEmitted => mode.matches_decision_emitted(),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::{
        GpAdapterRequest, GpExecutionError, GpExecutionStatus, GpExecutor, GpTriggerKind,
        SshGpRequest,
    };
    use crate::detector::SshFailureReason;
    use walle_policy::{GpPolicy, GpStrategyKind, GpTriggerMode};

    fn ssh_request(trigger_kind: GpTriggerKind) -> GpAdapterRequest {
        GpAdapterRequest::Ssh(SshGpRequest {
            trigger_kind,
            observed_at_secs: 42,
            source_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42)),
            username: None,
            failure_reason: Some(SshFailureReason::FailedPassword),
            matched_failures: None,
            expires_at_secs: None,
        })
    }

    #[test]
    fn disabled_policy_returns_disabled_outcome() {
        let executor = GpExecutor::new(GpPolicy::default());
        let outcome = executor.execute(ssh_request(GpTriggerKind::SignalObserved));

        assert_eq!(outcome.status, GpExecutionStatus::Disabled);
        assert_eq!(outcome.strategy, GpStrategyKind::Observe);
        assert!(outcome.error.is_none());
    }

    #[test]
    fn trigger_mode_filters_non_matching_events() {
        let executor = GpExecutor::new(GpPolicy {
            enabled: true,
            strategy: GpStrategyKind::Observe,
            trigger_mode: GpTriggerMode::DecisionEmitted,
        });
        let outcome = executor.execute(ssh_request(GpTriggerKind::SignalObserved));

        assert_eq!(outcome.status, GpExecutionStatus::TriggerFiltered);
        assert!(outcome.error.is_none());
    }

    #[test]
    fn observe_strategy_records_observed_outcome() {
        let executor = GpExecutor::new(GpPolicy {
            enabled: true,
            strategy: GpStrategyKind::Observe,
            trigger_mode: GpTriggerMode::All,
        });
        let outcome = executor.execute(ssh_request(GpTriggerKind::DecisionEmitted));

        assert_eq!(outcome.status, GpExecutionStatus::Observed);
        assert!(outcome.error.is_none());
    }

    #[test]
    fn unavailable_strategies_fail_open() {
        let executor = GpExecutor::new(GpPolicy {
            enabled: true,
            strategy: GpStrategyKind::Contain,
            trigger_mode: GpTriggerMode::All,
        });
        let outcome = executor.execute(ssh_request(GpTriggerKind::DecisionEmitted));

        assert_eq!(outcome.status, GpExecutionStatus::FailedOpen);
        assert_eq!(
            outcome.error,
            Some(GpExecutionError::StrategyUnavailable {
                strategy: GpStrategyKind::Contain,
            })
        );
    }
}
