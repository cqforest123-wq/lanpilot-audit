//! Summary statistics for a run of echo probes.
//!
//! Jitter is the mean absolute difference between consecutive round trips
//! (RFC 3550's idea, without the smoothing filter). For video and voice it
//! predicts trouble far better than the average does: a link that averages
//! 20 ms but swings 40 ms between packets drops frames, while a steady 80 ms
//! link looks worse on paper and works fine.

use serde::Serialize;

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeStats {
    pub sent: u32,
    pub received: u32,
    pub loss_pct: f64,
    pub min_ms: Option<f64>,
    pub avg_ms: Option<f64>,
    pub max_ms: Option<f64>,
    /// Mean absolute change between consecutive samples.
    pub jitter_ms: Option<f64>,
}

/// Summarize round trips. `sent` counts probes issued, including lost ones.
pub fn summarize(sent: u32, samples: &[f64]) -> ProbeStats {
    let received = samples.len() as u32;
    let loss_pct = if sent == 0 {
        0.0
    } else {
        ((sent - received.min(sent)) as f64 / sent as f64) * 100.0
    };

    if samples.is_empty() {
        return ProbeStats { sent, received, loss_pct, ..Default::default() };
    }

    let min = samples.iter().cloned().fold(f64::INFINITY, f64::min);
    let max = samples.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let avg = samples.iter().sum::<f64>() / samples.len() as f64;

    // Needs two samples before a change between samples exists.
    let jitter = if samples.len() < 2 {
        None
    } else {
        let total: f64 = samples.windows(2).map(|pair| (pair[1] - pair[0]).abs()).sum();
        Some(total / (samples.len() - 1) as f64)
    };

    ProbeStats {
        sent,
        received,
        loss_pct,
        min_ms: Some(round2(min)),
        avg_ms: Some(round2(avg)),
        max_ms: Some(round2(max)),
        jitter_ms: jitter.map(round2),
    }
}

fn round2(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarizes_a_clean_run() {
        let stats = summarize(4, &[10.0, 12.0, 11.0, 13.0]);
        assert_eq!(stats.sent, 4);
        assert_eq!(stats.received, 4);
        assert_eq!(stats.loss_pct, 0.0);
        assert_eq!(stats.min_ms, Some(10.0));
        assert_eq!(stats.max_ms, Some(13.0));
        assert_eq!(stats.avg_ms, Some(11.5));
        // |2| + |-1| + |2| = 5, over 3 gaps.
        assert_eq!(stats.jitter_ms, Some(1.67));
    }

    #[test]
    fn counts_loss() {
        let stats = summarize(4, &[10.0, 12.0]);
        assert_eq!(stats.loss_pct, 50.0);
        assert_eq!(stats.received, 2);
    }

    #[test]
    fn reports_total_loss_without_panicking() {
        let stats = summarize(4, &[]);
        assert_eq!(stats.loss_pct, 100.0);
        assert_eq!(stats.avg_ms, None);
        assert_eq!(stats.jitter_ms, None);
    }

    #[test]
    fn needs_two_samples_for_jitter() {
        assert_eq!(summarize(1, &[10.0]).jitter_ms, None);
        assert_eq!(summarize(2, &[10.0, 14.0]).jitter_ms, Some(4.0));
    }

    #[test]
    fn distinguishes_steady_slow_from_erratic_fast() {
        // The case that matters for cameras: same average, very different link.
        let steady = summarize(4, &[80.0, 80.0, 80.0, 80.0]);
        let erratic = summarize(4, &[40.0, 120.0, 40.0, 120.0]);
        assert_eq!(steady.avg_ms, erratic.avg_ms);
        assert_eq!(steady.jitter_ms, Some(0.0));
        assert_eq!(erratic.jitter_ms, Some(80.0));
    }

    #[test]
    fn handles_zero_probes() {
        let stats = summarize(0, &[]);
        assert_eq!(stats.loss_pct, 0.0);
        assert_eq!(stats.sent, 0);
    }
}
