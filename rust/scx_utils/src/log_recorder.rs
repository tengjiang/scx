// Copyright (c) Netflix, Inc.
// Author: Jose Fernandez

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::collections::HashMap;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use anyhow::Result;
use log::info;
use metrics::Counter;
use metrics::Gauge;
use metrics::Histogram;
use metrics::Key;
use metrics::KeyName;
use metrics::Metadata;
use metrics::Recorder;
use metrics::SharedString;
use metrics::Unit;
use metrics_util::registry::AtomicStorage;
use metrics_util::registry::Registry;

/// A builder for creating a new instance of `LogRecorder` and installing it as
/// the global recorder.
///
/// Example:
///
/// ```rust
/// LogRecorderBuilder::new()
///     .with_reporting_interval(Duration::from_secs(3))
///     .install()?;
/// ```
pub struct LogRecorderBuilder {
    reporting_interval: Duration,
    metric_formatter: Box<dyn MetricFormatter + Send + Sync>,
}

impl LogRecorderBuilder {
    pub fn new() -> LogRecorderBuilder {
        Self {
            reporting_interval: Duration::from_secs(3),
            metric_formatter: Box::new(DefaultMetricFormatter),
        }
    }

    /// Sets the interval at which the recorder will log the metrics.
    pub fn with_reporting_interval(mut self, interval: Duration) -> Self {
        self.reporting_interval = interval;
        self
    }

    /// Sets the formatter to use for logging the metrics.
    pub fn with_metric_formatter(
        mut self,
        formatter: Box<dyn MetricFormatter + Send + Sync>,
    ) -> Self {
        self.metric_formatter = formatter;
        self
    }

    /// Installs the log recorder as the global recorder.
    pub fn install(self) -> Result<()> {
        let recorder = LogRecorder {
            registry: Arc::new(Registry::<Key, AtomicStorage>::atomic()),
        };
        recorder.start(self.metric_formatter, self.reporting_interval);
        metrics::set_global_recorder(recorder)?;
        Ok(())
    }
}

/// A metrics recorder that logs metrics to the terminal.
///
/// `LogRecorder` implements the `Recorder` trait from the metrics-rs framework.
/// It maintains an in-memory registry of metrics and uses a background thread
/// to report all metrics at regular intervals.
///
/// Use the `LogRecorderBuilder` to create a new instance of `LogRecorder` and
/// install it as the global recorder.
struct LogRecorder {
    registry: Arc<Registry<Key, AtomicStorage>>,
}

impl Recorder for LogRecorder {
    fn describe_counter(&self, _: KeyName, _: Option<Unit>, _: SharedString) {
        unimplemented!()
    }

    fn describe_gauge(&self, _: KeyName, _: Option<Unit>, _: SharedString) {
        unimplemented!()
    }

    fn describe_histogram(&self, _: KeyName, _: Option<Unit>, _: SharedString) {
        unimplemented!()
    }

    fn register_counter(&self, key: &Key, _: &Metadata<'_>) -> Counter {
        self.registry
            .get_or_create_counter(key, |c| c.clone().into())
    }

    fn register_gauge(&self, key: &Key, _: &Metadata<'_>) -> Gauge {
        self.registry.get_or_create_gauge(key, |g| g.clone().into())
    }

    fn register_histogram(&self, key: &Key, _: &Metadata<'_>) -> Histogram {
        self.registry
            .get_or_create_histogram(key, |h: &Arc<metrics_util::AtomicBucket<f64>>| {
                h.clone().into()
            })
    }
}

impl LogRecorder {
    // Starts a background thread that logs the metrics at an interval defined
    // by the `reporting_interval` parameter.
    fn start(
        &self,
        metric_formatter: Box<dyn MetricFormatter + Send + Sync>,
        reporting_interval: Duration,
    ) {
        let registry_clone = self.registry.clone();

        thread::spawn(move || {
            let mut prev_counter_values: HashMap<Key, u64> = HashMap::new();
            let mut prev_instant = Instant::now();

            loop {
                let now = Instant::now();
                let period_secs = prev_instant.elapsed().as_secs_f64();
                prev_instant = now;

                log_counter_info(
                    &metric_formatter,
                    &registry_clone,
                    &mut prev_counter_values,
                    period_secs,
                );
                log_gauge_info(&metric_formatter, &registry_clone);
                log_histogram_info(&metric_formatter, &registry_clone);
                info!("---");

                // Sleep for the remainder of the period
                thread::sleep(reporting_interval - prev_instant.elapsed());
            }
        });
    }
}

/// A trait for formatting metrics for logging.
/// Implementations of this trait can be used to customize the format of the
/// metrics when they are logged.
pub trait MetricFormatter {
    /// Formats a counter metric for logging.
    /// The `rate_per_sec` parameter is the rate of change of the counter value.
    /// The `percentage` parameter is the percentage of the counter value
    /// relative to the total in a group. if not provided it means the counter
    /// is the only one in the group.
    fn format_counter(
        &self,
        key: &Key,
        value: u64,
        rate_per_sec: f64,
        percentage: Option<f64>,
    ) -> String {
        match percentage {
            Some(percentage) => {
                // Assuming only one label for now
                let name = match key.labels().next() {
                    Some(label) => label.value(),
                    None => "Unknown",
                };

                format!(
                    "    {}: {} ({:.1}%) [{:.1}/s]",
                    name, value, percentage, rate_per_sec
                )
            }
            None => {
                format!("  {}: {} [{:.1}/s]", key.name(), value, rate_per_sec)
            }
        }
    }

    /// Formats a gauge metric for logging.
    fn format_gauge(&self, key: &Key, value: f64) -> String {
        format!("  {}: {:.2}", key.name(), value)
    }

    /// Formats a histogram metric for logging.
    /// The `values` parameter is a list of all the values in the histogram.
    fn format_histogram(&self, key: &Key, values: Vec<f64>) -> String {
        let mut sum = 0.0;
        let mut count = 0;
        let mut min = 0.0;
        let mut max = 0.0;

        for value in values {
            sum += value;
            count += 1;

            if min == 0.0 || value < min {
                min = value;
            }

            if value >= max {
                max = value;
            }
        }

        let avg = if count > 0 { sum / count as f64 } else { 0.0 };
        let mut name = key.name().to_string();
        for label in key.labels() {
            name.push_str(&format!(" {}={}", label.key(), label.value()));
        }

        format!("  {}: avg={:.2} min={:.2} max={:.2}", name, avg, min, max)
    }
}

struct DefaultMetricFormatter;

impl MetricFormatter for DefaultMetricFormatter {}

fn group_keys_by_name(keys: Vec<Key>) -> HashMap<String, Vec<Key>> {
    let mut grouped_keys: HashMap<String, Vec<Key>> = HashMap::new();
    for key in keys {
        let key_name = key.name().to_string();
        let keys = grouped_keys.entry(key_name).or_insert_with(Vec::new);
        keys.push(key);
    }
    grouped_keys
}

fn log_counter_info(
    metric_formatter: &Box<dyn MetricFormatter + Send + Sync>,
    registry: &Registry<Key, AtomicStorage>,
    prev_counter_values: &mut HashMap<Key, u64>,
    period_secs: f64,
) {
    let handles = registry.get_counter_handles();
    let grouped_keys = group_keys_by_name(handles.keys().cloned().collect());

    // Collect the totals for sorting
    let mut total_values: Vec<(String, u64, Vec<(Key, u64)>)> = grouped_keys
        .into_iter()
        .map(|(key_name, keys)| {
            // Collect all counter values first
            let key_values: Vec<(Key, u64)> = keys
                .iter()
                .map(|key| {
                    let value = registry.get_counter(key).unwrap().load(Relaxed);
                    (key.clone(), value)
                })
                .collect();

            // Calculate the total
            let total: u64 = key_values.iter().map(|(_, value)| *value).sum();

            (key_name, total, key_values)
        })
        .collect();

    // Sort by total value in descending order, then by key name in ascending order
    total_values.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    if handles.len() > 0 {
        info!("Counters:");
    }
    for (_, total, mut key_values) in total_values {
        let mut total_rate_per_second = 0.0;

        for (key, value) in &key_values {
            let prev_value = prev_counter_values.get(key).cloned().unwrap_or(0);
            let rate_per_second = (value - prev_value) as f64 / period_secs;
            total_rate_per_second += rate_per_second;
        }

        let key = &key_values[0].0;
        info!(
            "{}",
            metric_formatter.format_counter(key, total, total_rate_per_second, None)
        );

        if key_values.len() > 1 {
            // Sort the key_values by the counter value in descending order
            key_values.sort_by(|a, b| b.1.cmp(&a.1));

            // Log individual totals, their percentages, and rates
            for (key, value) in key_values {
                let prev_value = prev_counter_values.get(&key).cloned().unwrap_or(0);
                let rate_per_second = (value - prev_value) as f64 / period_secs;
                let percentage = if total == 0 {
                    0.0
                } else {
                    (value as f64 / total as f64) * 100.0
                };
                info!(
                    "{}",
                    metric_formatter.format_counter(&key, value, rate_per_second, Some(percentage))
                );
                prev_counter_values.insert(key.clone(), value);
            }
        } else {
            let (key, value) = &key_values[0];
            prev_counter_values.insert(key.clone(), *value);
        }
    }
}

fn log_gauge_info(
    metric_formatter: &Box<dyn MetricFormatter + Send + Sync>,
    registry: &Registry<Key, AtomicStorage>,
) {
    let handles = registry.get_gauge_handles();
    let mut keys: Vec<Key> = handles.keys().cloned().collect();
    keys.sort();
    if keys.len() > 0 {
        info!("Gauges:");
    }
    for key in keys {
        match registry.get_gauge(&key) {
            None => continue,
            Some(gauge) => {
                // Gauge values are stored as bits, so we need to convert them to f64
                let value = f64::from_bits(gauge.load(Relaxed));
                info!("{}", metric_formatter.format_gauge(&key, value));
            }
        }
    }
}

fn log_histogram_info(
    metric_formatter: &Box<dyn MetricFormatter + Send + Sync>,
    registry: &Registry<Key, AtomicStorage>,
) {
    let handles = registry.get_histogram_handles();
    let mut keys: Vec<Key> = handles.keys().cloned().collect();

    keys.sort();
    if keys.len() > 0 {
        info!("Histograms:");
    }

    for key in keys {
        match registry.get_histogram(&key) {
            None => continue,
            Some(histogram) => {
                let mut values = vec![];

                // Iterate over all elements in the histogram and clear it.
                // This prevents the histogram from growing indefinitely.
                histogram.clear_with(|elements| {
                    for element in elements.iter() {
                        values.push(element.clone());
                    }
                });

                info!("{}", metric_formatter.format_histogram(&key, values));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use metrics::Label;

    use super::*;

    #[test]
    fn test_default_format_counter() {
        let formatter = DefaultMetricFormatter;
        let key = Key::from_name("test_counter");
        let value = 100;
        let rate_per_sec = 10.5;
        let percentage = None;

        let result = formatter.format_counter(&key, value, rate_per_sec, percentage);

        assert_eq!(result, "  test_counter: 100 [10.5/s]");
    }

    #[test]
    fn test_default_format_counter_for_group() {
        let formatter = DefaultMetricFormatter;
        let label = Label::new("test_label", "value");
        let key = Key::from_parts("test_counter", vec![label]);
        let value = 100;
        let rate_per_sec = 10.5;
        let percentage = Some(0.75);

        let result = formatter.format_counter(&key, value, rate_per_sec, percentage);

        assert_eq!(result, "    test_label: 100 (0.8%) [10.5/s]");
    }

    #[test]
    fn test_default_format_gauge() {
        let formatter = DefaultMetricFormatter;
        let key = Key::from_name("test_gauge");
        let value = 3.14;
        let result = formatter.format_gauge(&key, value);
        assert_eq!(result, "  test_gauge: 3.14");
    }

    #[test]
    fn test_default_format_histogram() {
        let formatter = DefaultMetricFormatter;
        let key = Key::from_name("test_histogram");
        let values = vec![1.0, 2.0, 3.0];
        let result = formatter.format_histogram(&key, values);
        assert_eq!(result, "  test_histogram: avg=2.00 min=1.00 max=3.00");
    }
}
