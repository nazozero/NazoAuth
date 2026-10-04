use super::*;

#[test]
fn otel_config_is_disabled_by_default() {
    let config = ConfigSource::from_pairs_for_test([]);

    assert!(OtelConfig::from_config(&config).unwrap().is_none());
}

#[test]
fn otel_config_explicit_false_overrides_inherited_endpoint() {
    let config = ConfigSource::from_pairs_for_test([
        ("OTEL_ENABLED", "false"),
        ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4318"),
    ]);

    assert!(OtelConfig::from_config(&config).unwrap().is_none());
}

#[test]
fn otel_config_accepts_explicit_endpoint_and_timeout() {
    let config = ConfigSource::from_pairs_for_test([
        ("OTEL_ENABLED", "true"),
        ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4318"),
        ("OTEL_EXPORTER_OTLP_TIMEOUT", "2500"),
    ]);

    let otel = OtelConfig::from_config(&config).unwrap().unwrap();

    assert_eq!(otel.endpoint, "http://collector:4318");
    assert_eq!(otel.timeout, Some(Duration::from_millis(2_500)));
    assert_eq!(
        otel.signal_endpoint("/v1/traces"),
        "http://collector:4318/v1/traces"
    );
}

#[test]
fn otel_config_rejects_unsupported_protocol_and_bad_endpoint() {
    let protocol = ConfigSource::from_pairs_for_test([
        ("OTEL_ENABLED", "true"),
        ("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc"),
    ]);
    assert!(OtelConfig::from_config(&protocol).is_err());

    let endpoint = ConfigSource::from_pairs_for_test([
        ("OTEL_ENABLED", "true"),
        ("OTEL_EXPORTER_OTLP_ENDPOINT", "collector:4318"),
    ]);
    assert!(OtelConfig::from_config(&endpoint).is_err());
}

#[test]
fn otel_http_exporters_build_with_the_selected_reqwest_client() {
    let config = OtelConfig {
        endpoint: "http://collector:4318".to_owned(),
        timeout: Some(Duration::from_secs(1)),
    };

    otel_http_span_exporter(&config).expect("span exporter should build");
    otel_http_metric_exporter(&config).expect("metric exporter should build");
    otel_http_log_exporter(&config).expect("log exporter should build");
}


#[test]
fn otel_http_exporters_do_not_retry_transient_responses() {
    use opentelemetry::{logs::{LogRecord as _, Logger as _, LoggerProvider as _}, metrics::MeterProvider as _, trace::{Tracer as _, Span as _}};
    use std::{
        collections::BTreeMap,
        io::{Read, Write},
        net::TcpListener,
        sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}},
        thread,
        time::Instant,
    };

    for (status, delay) in [(200, 0), (429, 0), (503, 0), (200, 200)] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let done = Arc::new(AtomicBool::new(false));
        let counts = Arc::new(Mutex::new(BTreeMap::<String, usize>::new()));
        let stop = done.clone();
        let received = counts.clone();
        let server = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            while !stop.load(Ordering::SeqCst) && Instant::now() < deadline {
                let (mut socket, _) = match listener.accept() {
                    Ok(value) => value,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(error) => panic!("collector accept: {error}"),
                };
                socket.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    if socket.read_exact(&mut byte).is_err() { break; }
                    head.push(byte[0]);
                    assert!(head.len() < 16_384);
                }
                if !head.ends_with(b"\r\n\r\n") { continue; }
                let head = String::from_utf8(head).unwrap();
                let path = head.lines().next().unwrap().split_whitespace().nth(1).unwrap().to_owned();
                let length = head.lines().find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length").then(|| value.trim().parse::<usize>().unwrap())
                }).unwrap_or(0);
                assert!(length < 1_048_576);
                if socket.read_exact(&mut vec![0; length]).is_err() { continue; }
                *received.lock().unwrap().entry(path).or_default() += 1;
                thread::sleep(Duration::from_millis(delay));
                let _ = write!(socket, "HTTP/1.1 {status} Test\r\nContent-Length: 0\r\nRetry-After: 0\r\nConnection: close\r\n\r\n");
            }
        });
        let config = OtelConfig { endpoint, timeout: Some(Duration::from_millis(100)) };
        let trace = SdkTracerProvider::builder().with_simple_exporter(otel_http_span_exporter(&config).unwrap()).build();
        trace.tracer("retry-boundary").start("single-export").end();
        let logs = SdkLoggerProvider::builder().with_simple_exporter(otel_http_log_exporter(&config).unwrap()).build();
        let logger = logs.logger("retry-boundary");
        let mut record = logger.create_log_record();
        record.set_body("single-export".into());
        logger.emit(record);
        let metrics = SdkMeterProvider::builder().with_periodic_exporter(otel_http_metric_exporter(&config).unwrap()).build();
        metrics.meter("retry-boundary").u64_counter("single-export").build().add(1, &[]);
        let _ = metrics.force_flush();
        // Observe a single explicit export, before shutdown may export another
        // metric collection. No retry of that invocation is allowed.
        let deadline = Instant::now() + Duration::from_secs(1);
        while counts.lock().unwrap().len() < 3 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(2));
        }
        let observed = counts.lock().unwrap().clone();
        let _ = metrics.shutdown();
        let _ = logs.shutdown();
        let _ = trace.shutdown();
        done.store(true, Ordering::SeqCst);
        server.join().unwrap();
        for path in ["/v1/traces", "/v1/logs", "/v1/metrics"] {
            assert_eq!(observed.get(path), Some(&1), "status={status}, delay={delay}, path={path}");
        }
    }
}
