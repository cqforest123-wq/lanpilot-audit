//! Long-running reachability watch with an outage log.
//!
//! A one-shot check answers "is it up right now". This answers the harder
//! question behind most camera and VoIP complaints: "it drops sometimes — when,
//! how often, and for how long?" A single averaged number hides exactly that,
//! so every gap is recorded with a timestamp and a duration.

use serde::Serialize;

/// One probe result, reduced to what the outage tracker needs.
#[derive(Debug, Clone, Copy)]
pub struct Tick {
    /// Milliseconds since the watch started.
    pub at_ms: u64,
    pub rtt_ms: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Outage {
    pub started_at_ms: u64,
    /// `None` while the outage is still ongoing.
    pub ended_at_ms: Option<u64>,
    pub duration_ms: Option<u64>,
    pub missed_probes: u32,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WatchSummary {
    pub total_probes: u32,
    pub replies: u32,
    pub loss_pct: f64,
    pub outages: Vec<Outage>,
    pub longest_outage_ms: Option<u64>,
    pub worst_rtt_ms: Option<f64>,
}

/// Fold a series of ticks into an outage log.
///
/// A single lost packet already counts as an outage: for a camera stream that
/// is a visible glitch, and hiding it behind an average is the whole failure
/// mode this feature exists to prevent.
pub fn summarize(ticks: &[Tick]) -> WatchSummary {
    let mut summary = WatchSummary { total_probes: ticks.len() as u32, ..Default::default() };
    let mut current: Option<Outage> = None;

    for tick in ticks {
        match tick.rtt_ms {
            Some(rtt) => {
                summary.replies += 1;
                summary.worst_rtt_ms =
                    Some(summary.worst_rtt_ms.map_or(rtt, |worst: f64| worst.max(rtt)));

                // A reply closes any gap that was open.
                if let Some(mut outage) = current.take() {
                    outage.ended_at_ms = Some(tick.at_ms);
                    outage.duration_ms = Some(tick.at_ms.saturating_sub(outage.started_at_ms));
                    summary.outages.push(outage);
                }
            }
            None => match current.as_mut() {
                Some(outage) => outage.missed_probes += 1,
                None => {
                    current = Some(Outage {
                        started_at_ms: tick.at_ms,
                        ended_at_ms: None,
                        duration_ms: None,
                        missed_probes: 1,
                    });
                }
            },
        }
    }

    // An outage still open when the watch stops is reported as ongoing rather
    // than silently dropped.
    if let Some(outage) = current {
        summary.outages.push(outage);
    }

    summary.loss_pct = if summary.total_probes == 0 {
        0.0
    } else {
        let lost = summary.total_probes - summary.replies;
        ((lost as f64 / summary.total_probes as f64) * 1000.0).round() / 10.0
    };

    summary.longest_outage_ms = summary.outages.iter().filter_map(|entry| entry.duration_ms).max();

    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tick(at_ms: u64, rtt_ms: Option<f64>) -> Tick {
        Tick { at_ms, rtt_ms }
    }

    #[test]
    fn a_clean_watch_logs_no_outage() {
        let summary =
            summarize(&[tick(0, Some(10.0)), tick(1000, Some(11.0)), tick(2000, Some(9.0))]);
        assert_eq!(summary.loss_pct, 0.0);
        assert!(summary.outages.is_empty());
        assert_eq!(summary.worst_rtt_ms, Some(11.0));
    }

    #[test]
    fn records_a_single_dropped_packet() {
        // The glitch that an average would erase.
        let summary =
            summarize(&[tick(0, Some(10.0)), tick(1000, None), tick(2000, Some(10.0))]);
        assert_eq!(summary.outages.len(), 1);
        assert_eq!(summary.outages[0].started_at_ms, 1000);
        assert_eq!(summary.outages[0].duration_ms, Some(1000));
        assert_eq!(summary.outages[0].missed_probes, 1);
    }

    #[test]
    fn merges_consecutive_losses_into_one_outage() {
        let summary = summarize(&[
            tick(0, Some(10.0)),
            tick(1000, None),
            tick(2000, None),
            tick(3000, None),
            tick(4000, Some(12.0)),
        ]);
        assert_eq!(summary.outages.len(), 1);
        assert_eq!(summary.outages[0].missed_probes, 3);
        assert_eq!(summary.outages[0].duration_ms, Some(3000));
        assert_eq!(summary.longest_outage_ms, Some(3000));
    }

    #[test]
    fn separates_two_distinct_outages() {
        let summary = summarize(&[
            tick(0, Some(10.0)),
            tick(1000, None),
            tick(2000, Some(10.0)),
            tick(3000, None),
            tick(4000, None),
            tick(5000, Some(10.0)),
        ]);
        assert_eq!(summary.outages.len(), 2);
        assert_eq!(summary.outages[0].duration_ms, Some(1000));
        assert_eq!(summary.outages[1].duration_ms, Some(2000));
        assert_eq!(summary.longest_outage_ms, Some(2000));
    }

    #[test]
    fn reports_an_outage_still_open_at_the_end() {
        let summary = summarize(&[tick(0, Some(10.0)), tick(1000, None), tick(2000, None)]);
        assert_eq!(summary.outages.len(), 1);
        assert_eq!(summary.outages[0].ended_at_ms, None, "still ongoing");
        assert_eq!(summary.outages[0].duration_ms, None);
        assert_eq!(summary.longest_outage_ms, None);
    }

    #[test]
    fn handles_a_watch_that_never_got_a_reply() {
        let summary = summarize(&[tick(0, None), tick(1000, None)]);
        assert_eq!(summary.loss_pct, 100.0);
        assert_eq!(summary.replies, 0);
        assert_eq!(summary.outages.len(), 1);
        assert_eq!(summary.outages[0].started_at_ms, 0);
    }

    #[test]
    fn computes_loss_to_one_decimal() {
        let ticks: Vec<Tick> = (0..8)
            .map(|index| tick(index * 1000, (index % 4 != 0).then_some(10.0)))
            .collect();
        assert_eq!(summarize(&ticks).loss_pct, 25.0);
    }

    #[test]
    fn an_empty_watch_is_not_a_division_by_zero() {
        let summary = summarize(&[]);
        assert_eq!(summary.loss_pct, 0.0);
        assert_eq!(summary.total_probes, 0);
    }
}
