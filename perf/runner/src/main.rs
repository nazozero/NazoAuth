use goose::config::GooseConfiguration;
use goose::goose::{GooseRequest, GooseUser};
use reqwest::{Client, Method, Url, redirect, retry};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::task::JoinSet;
use tokio::time::{Instant, sleep_until};

const SEND_DEADLINE: Duration = Duration::from_millis(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

type Error = Box<dyn std::error::Error>;

#[derive(Deserialize)]
struct Request {
    method: String,
    url: String,
    #[serde(default)]
    headers: Vec<(String, String)>,
    #[serde(default)]
    body: String,
    operation: String,
    authorize: Option<Authorization>,
    previous_refresh: Option<String>,
    refresh_form: Option<Vec<(String, String)>>,
    userinfo_subject: Option<String>,
}

#[derive(Deserialize)]
struct Authorization {
    peer: String,
    redirect: String,
    state: String,
    token_url: String,
    token_fields: Vec<(String, String)>,
    csrf: String,
    #[serde(default)]
    keycloak_consent: bool,
}

struct Observation {
    slot: u64,
    due_ns: u64,
    sent_ns: Option<u64>,
    completed_ns: Option<u64>,
    status: u16,
    outcome: &'static str,
    operation: String,
    http_requests: usize,
}

impl Observation {
    fn write(&self, out: &mut impl Write) -> std::io::Result<()> {
        writeln!(
            out,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.slot,
            self.due_ns,
            self.sent_ns.map_or_else(String::new, |n| n.to_string()),
            self.completed_ns
                .map_or_else(String::new, |n| n.to_string()),
            self.status,
            self.outcome,
            self.operation,
            self.http_requests
        )
    }
}

fn nanos(d: Duration) -> u64 {
    d.as_nanos()
        .try_into()
        .expect("measurement exceeds u64 nanoseconds")
}

fn due(slot: u64, rate: u64) -> u64 {
    (u128::from(slot) * 1_000_000_000 / u128::from(rate)) as u64
}

struct ArrivalPhase {
    start_ns: u64,
    first_slot: u64,
    end_slot: u64,
    rate: u64,
}

fn arrival_phases(
    schedule: Option<&str>,
    rate: u64,
    warm: u64,
    seconds: u64,
) -> Result<Vec<ArrivalPhase>, Error> {
    let phases = if let Some(schedule) = schedule {
        let intervals = schedule
            .split(',')
            .map(|segment| {
                let (duration, rate) = segment.split_once('@').ok_or("expected duration@rate")?;
                Ok((duration.parse::<u64>()?, rate.parse::<u64>()?))
            })
            .collect::<Result<Vec<_>, Error>>()?;
        if intervals.len() != 4
            || intervals[0] != (warm, rate)
            || intervals[1].1 != rate
            || intervals[3].1 != rate
            || intervals.iter().map(|(duration, _)| duration).sum::<u64>() != warm + seconds
        {
            return Err("arrival phases must match the warm-up and measurement arguments".into());
        }
        intervals
    } else {
        vec![(warm + seconds, rate)]
    };
    let mut start_ns = 0;
    let mut first_slot = 0u64;
    let mut result = Vec::new();
    for (duration, rate) in phases {
        if duration == 0 || rate == 0 {
            return Err("arrival phases need positive duration and rate".into());
        }
        let count = duration.checked_mul(rate).ok_or("slot count overflow")?;
        let end_slot = first_slot.checked_add(count).ok_or("slot count overflow")?;
        result.push(ArrivalPhase {
            start_ns,
            first_slot,
            end_slot,
            rate,
        });
        start_ns += duration * 1_000_000_000;
        first_slot = end_slot;
    }
    Ok(result)
}

fn scheduled_time(phases: &[ArrivalPhase], slot: u64) -> u64 {
    let phase = &phases[phases.partition_point(|phase| phase.end_slot <= slot)];
    phase.start_ns + due(slot - phase.first_slot, phase.rate)
}

async fn send(
    user: &mut GooseUser,
    builder: reqwest::RequestBuilder,
) -> Result<reqwest::Response, &'static str> {
    let request = GooseRequest::builder().set_request_builder(builder).build();
    user.request(request)
        .await
        .map_err(|_| "client_error")?
        .response
        .map_err(|e| {
            if e.is_timeout() {
                "timeout"
            } else {
                "transport_error"
            }
        })
}

fn location(response: &reqwest::Response, base: &Url) -> Result<Url, &'static str> {
    let value = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .ok_or("protocol_error")?;
    base.join(value).map_err(|_| "protocol_error")
}

fn form_builder(
    user: &GooseUser,
    url: &str,
    fields: &[(String, String)],
    keep_headers: &[(String, String)],
) -> reqwest::RequestBuilder {
    let mut builder = user.client.post(url).form(fields);
    for (name, value) in keep_headers {
        builder = builder.header(name, value);
    }
    builder
}

fn consent_form(html: &str) -> Option<(String, String, String)> {
    let dom = tl::parse(html, tl::ParserOptions::default()).ok()?;
    let mut action = None;
    let mut code = None;
    let mut accept = None;
    for tag in dom.nodes().iter().filter_map(tl::Node::as_tag) {
        let attr = |key| tag.attributes().get(key).flatten().map(|s| s.as_utf8_str());
        match tag.name().as_bytes() {
            b"form" if attr("method")?.eq_ignore_ascii_case("post") => {
                if let Some(target) = attr("action") {
                    action = Some(target.replace("&amp;", "&"));
                }
            }
            b"input" | b"button" => match attr("name").as_deref() {
                Some("code") => code = attr("value").map(|s| s.into_owned()),
                Some("accept") => accept = Some(attr("value").unwrap_or_default().into_owned()),
                _ => {}
            },
            _ => {}
        }
    }
    Some((action?, code?, accept?))
}

async fn keycloak_consent(
    user: &mut GooseUser,
    fixture: &Request,
    mut response: reqwest::Response,
    calls: &mut usize,
) -> Result<reqwest::Response, &'static str> {
    let service = Url::parse(&fixture.url).map_err(|_| "client_error")?;
    let host = fixture
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
        .ok_or("client_error")?
        .1
        .as_str();
    let issuer =
        Url::parse(&format!("{}://{host}", service.scheme())).map_err(|_| "client_error")?;
    let mut cookies = std::collections::BTreeMap::<String, String>::new();
    let update = |values: &mut std::collections::BTreeMap<String, String>, pair: &str| {
        if let Some((key, value)) = pair.trim().split_once('=') {
            if value.is_empty() {
                values.remove(key);
            } else {
                values.insert(key.into(), value.into());
            }
        }
    };
    if let Some((_, value)) = fixture
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("cookie"))
    {
        for cookie in value.split(';') {
            update(&mut cookies, cookie);
        }
    }
    for _ in 0..5 {
        for value in response.headers().get_all("set-cookie") {
            if let Ok(field) = value.to_str() {
                update(&mut cookies, field.split(';').next().unwrap_or(""));
            }
        }
        let (action, code) = if response.status().is_redirection() {
            let location = location(&response, &issuer)?;
            response.bytes().await.map_err(|_| "transport_error")?;
            (location, None)
        } else if response.status().as_u16() == 200 {
            let body = response.text().await.map_err(|_| "transport_error")?;
            let (action, code, accept) = consent_form(&body).ok_or("protocol_error")?;
            (
                issuer.join(&action).map_err(|_| "protocol_error")?,
                Some((code, accept)),
            )
        } else {
            return Err("protocol_error");
        };
        if action.origin() != issuer.origin() || !action.path().starts_with("/realms/api-audit/") {
            return Err("protocol_error");
        }
        let mut endpoint = service.clone();
        endpoint.set_path(action.path());
        endpoint.set_query(action.query());
        let submitted = code.is_some();
        let req = if let Some((code, accept)) = code {
            user.client
                .post(endpoint)
                .form(&[("code", code.as_str()), ("accept", accept.as_str())])
        } else {
            user.client.get(endpoint)
        };
        let cookie = cookies
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ");
        *calls += 1;
        response = send(user, req.header("Host", host).header("Cookie", cookie)).await?;
        if submitted {
            return Ok(response);
        }
    }
    Err("protocol_error")
}

async fn authorize(
    user: &mut GooseUser,
    fixture: &Request,
    flow: &Authorization,
    first: reqwest::Response,
    calls: &mut usize,
) -> Result<reqwest::Response, &'static str> {
    let origin = Url::parse(&fixture.url).map_err(|_| "client_error")?;
    let callback = Url::parse(&flow.redirect).map_err(|_| "client_error")?;
    let first = if flow.keycloak_consent {
        keycloak_consent(user, fixture, first, calls).await?
    } else {
        first
    };
    let mut redirect = location(&first, &origin)?;
    let _ = first.bytes().await;
    if flow.peer == "nazo" && redirect.origin() != callback.origin() {
        if redirect.origin() != origin.origin() && redirect.host_str() != Some("localhost") {
            return Err("protocol_error");
        }
        let id = redirect
            .query_pairs()
            .find(|(k, _)| k == "request_id")
            .ok_or("protocol_error")?
            .1
            .into_owned();
        let fields = vec![
            ("request_id".into(), id),
            ("decision".into(), "approve".into()),
            ("csrf_token".into(), flow.csrf.clone()),
        ];
        let endpoint = origin
            .join("/authorize/decision")
            .map_err(|_| "client_error")?;
        let request = form_builder(user, endpoint.as_str(), &fields, &fixture.headers);
        *calls += 1;
        let response = send(user, request).await?;
        redirect = location(&response, &origin)?;
        let _ = response.bytes().await;
    }
    if redirect.origin() != callback.origin()
        || redirect.path() != callback.path()
        || !redirect
            .query_pairs()
            .any(|(k, v)| k == "state" && v == flow.state)
    {
        return Err("protocol_error");
    }
    let code = redirect
        .query_pairs()
        .find(|(k, _)| k == "code")
        .ok_or("protocol_error")?
        .1
        .into_owned();
    let mut fields = flow.token_fields.clone();
    fields.push(("code".into(), code));
    let mut request = user.client.post(&flow.token_url).form(&fields);
    if let Some((name, value)) = fixture
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("host"))
    {
        request = request.header(name, value);
    }
    *calls += 1;
    send(user, request).await
}

async fn request(
    user: &mut GooseUser,
    fixture: &Request,
    calls: &mut usize,
    mut refresh: Option<&mut Option<String>>,
) -> (u16, &'static str) {
    let mut builder = user
        .client
        .request(fixture.method.parse::<Method>().unwrap(), &fixture.url);
    for (key, value) in &fixture.headers {
        builder = builder.header(key, value);
    }
    let old_refresh = refresh.as_deref_mut().and_then(Option::take);
    if let (Some(token), Some(fields)) = (&old_refresh, &fixture.refresh_form) {
        let mut fields = fields.clone();
        fields.push(("refresh_token".into(), token.clone()));
        builder = builder.form(&fields);
    } else if !fixture.body.is_empty() {
        builder = builder.body(fixture.body.clone());
    }
    *calls += 1;
    let mut response = match send(user, builder).await {
        Ok(response) => response,
        Err(err) => return (0, err),
    };
    if let Some(flow) = &fixture.authorize {
        response = match authorize(user, fixture, flow, response, calls).await {
            Ok(response) => response,
            Err(err) => return (0, err),
        };
    }
    let status = response.status().as_u16();
    if status != 200 {
        let _ = response.bytes().await;
        return (status, "http_error");
    }
    let body = match response.bytes().await {
        Ok(body) => body,
        Err(e) => {
            return (
                status,
                if e.is_timeout() {
                    "timeout"
                } else {
                    "transport_error"
                },
            );
        }
    };
    if fixture.operation == "control" {
        return (
            status,
            if body.as_ref() == b"ok" {
                "ok"
            } else {
                "protocol_error"
            },
        );
    }
    let Ok(doc) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return (status, "protocol_error");
    };
    let valid = match fixture.operation.as_str() {
        "machine" | "exchange" | "refresh" | "authorize" => {
            doc["access_token"].as_str().is_some_and(|s| !s.is_empty())
                && doc["token_type"]
                    .as_str()
                    .is_some_and(|s| s.eq_ignore_ascii_case("bearer"))
                && doc["expires_in"].as_u64().is_some_and(|n| n > 0)
                && (!matches!(fixture.operation.as_str(), "exchange" | "authorize")
                    || doc["id_token"].as_str().is_some_and(|s| !s.is_empty()))
                && (fixture.operation != "refresh"
                    || doc["refresh_token"]
                        .as_str()
                        .is_some_and(|s| !s.is_empty() && old_refresh.as_deref() != Some(s)))
        }
        "introspect" => doc["active"].as_bool() == Some(true),
        "userinfo" => doc["sub"]
            .as_str()
            .is_some_and(|actual| fixture.userinfo_subject.as_deref() == Some(actual)),
        _ => false,
    };
    if valid && let Some(lane) = refresh {
        *lane = doc["refresh_token"].as_str().map(str::to_owned);
    }
    (status, if valid { "ok" } else { "protocol_error" })
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args: Vec<_> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--version") {
        println!("oauth-goose {} (Goose 0.19.2)", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if args.len() != 7 {
        return Err("usage: oauth-goose RATE WARM_SECONDS MEASURE_SECONDS MAX_IN_FLIGHT FIXTURE_JSON RESULT_TSV".into());
    }
    let rate: u64 = args[1].parse()?;
    let warm: u64 = args[2].parse()?;
    let seconds: u64 = args[3].parse()?;
    let concurrency: usize = args[4].parse()?;
    if rate == 0 || seconds == 0 || concurrency == 0 {
        return Err("rate, measurement window and concurrency must be positive".into());
    }
    let schedule = std::env::var("BENCH_ARRIVAL_PHASES").ok();
    let phases = arrival_phases(schedule.as_deref(), rate, warm, seconds)?;
    let slots = phases.last().unwrap().end_slot;
    let fixtures: Vec<Request> = serde_json::from_reader(BufReader::new(File::open(&args[5])?))?;
    let mut out = BufWriter::with_capacity(
        1024 * 1024,
        File::options()
            .write(true)
            .create_new(true)
            .open(&args[6])?,
    );
    if fixtures
        .iter()
        .any(|f| matches!(f.operation.as_str(), "exchange" | "authorize"))
        && (fixtures.len() != slots as usize)
    {
        return Err("user grants require one private fixture for each planned slot".into());
    }
    let origin = Url::parse(&fixtures.first().ok_or("empty fixtures")?.url)?;
    for fixture in &fixtures {
        let _: Method = fixture.method.parse()?;
        let url = Url::parse(&fixture.url)?;
        if url.scheme() != origin.scheme()
            || url.host_str() != origin.host_str()
            || !matches!(
                fixture.operation.as_str(),
                "control"
                    | "machine"
                    | "introspect"
                    | "exchange"
                    | "refresh"
                    | "authorize"
                    | "userinfo"
            )
        {
            return Err(
                "each phase needs one service host and transport and recognized operations".into(),
            );
        }
        if fixture.operation == "refresh"
            && (fixture.previous_refresh.is_none() || fixture.refresh_form.is_none())
        {
            return Err("refresh needs a verified initial token and the grant form".into());
        }
    }
    let mut client = Client::builder()
        .http1_only()
        .timeout(REQUEST_TIMEOUT)
        .redirect(redirect::Policy::none())
        .retry(retry::never())
        .pool_max_idle_per_host(concurrency)
        .no_proxy();
    if let Ok(path) = std::env::var("BENCH_CA_PEM") {
        client =
            client.add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(path)?)?);
    }
    let client = client.build()?;
    let config = GooseConfiguration::default();
    let mut users = Vec::with_capacity(concurrency);
    for _ in 0..concurrency {
        let mut user = GooseUser::single(origin.clone(), &config)?;
        user.client = client.clone();
        users.push(user);
    }
    let users = Arc::new(Mutex::new(users));
    let refresh_pool = {
        let mut families = HashMap::new();
        Arc::new(
            fixtures
                .iter()
                .map(|f| {
                    f.previous_refresh.as_ref().map(|token| {
                        families
                            .entry(token)
                            .or_insert_with(|| {
                                Arc::new(tokio::sync::Mutex::new(Some(token.clone())))
                            })
                            .clone()
                    })
                })
                .collect::<Vec<_>>(),
        )
    };
    let fixtures = Arc::new(fixtures);
    let mut pending = JoinSet::new();
    let epoch_ns = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let start = Instant::now();
    eprintln!(
        "epoch_ns={epoch_ns} warm={warm} seconds={seconds} rate={rate} concurrency={concurrency}"
    );
    if let Some(schedule) = schedule {
        eprintln!("schedule={schedule}");
    }
    writeln!(
        out,
        "slot\tdue_ns\tsent_ns\tcompleted_ns\tstatus\toutcome\toperation\thttp_requests"
    )?;
    let wide = std::env::var("BENCH_GO_PROFILE").as_deref() == Ok("journal-wide");
    let mut direct = Some(out);
    let journal = if wide {
        let (sender, receiver) = std::sync::mpsc::channel::<Observation>();
        let mut file = direct.take().unwrap();
        let writer = std::thread::spawn(move || -> std::io::Result<u64> {
            let mut count = 0;
            for record in receiver {
                record.write(&mut file)?;
                count += 1;
            }
            file.flush()?;
            Ok(count)
        });
        Some((sender, writer))
    } else {
        None
    };
    let mut record = |sample: Observation| -> Result<(), Error> {
        if let Some(file) = direct.as_mut() {
            sample.write(file)?;
        } else if let Some((sender, _)) = &journal {
            sender.send(sample)?;
        }
        Ok(())
    };
    let end = start + Duration::from_secs(warm + seconds);
    let mut slot = 0;
    while slot < slots {
        let now = Instant::now();
        let elapsed_ns = nanos(now - start);
        if elapsed_ns < scheduled_time(&phases, slot) {
            let after_next_tick = (elapsed_ns / 1_000_000 + 1) * 1_000_000;
            sleep_until(start + Duration::from_nanos(after_next_tick)).await;
        }
        while let Some(observation) = pending.try_join_next() {
            let observation: Observation = observation?;
            record(observation)?;
        }
        let cutoff = nanos(start.elapsed());
        while slot < slots && scheduled_time(&phases, slot) <= cutoff {
            let due_ns = scheduled_time(&phases, slot);
            let scheduled = start + Duration::from_nanos(due_ns);
            let fixture_index = slot as usize % fixtures.len();
            let fixture = &fixtures[fixture_index];
            let mut sample = Observation {
                slot,
                due_ns,
                sent_ns: None,
                completed_ns: None,
                status: 0,
                outcome: "scheduler_late",
                operation: fixture.operation.clone(),
                http_requests: 0,
            };
            slot += 1;
            if Instant::now() >= (scheduled + SEND_DEADLINE).min(end) {
                record(sample)?;
                continue;
            }
            let Some(mut user) = users.lock().unwrap().pop() else {
                sample.outcome = "in_flight_limit";
                record(sample)?;
                continue;
            };
            let users = users.clone();
            let fixtures = fixtures.clone();
            let refresh_pool = refresh_pool.clone();
            let operation = async move {
                let mut refresh = if let Some(lane) = &refresh_pool[fixture_index] {
                    match lane.try_lock() {
                        Ok(guard) if guard.is_some() => Some(guard),
                        Ok(_) => {
                            sample.outcome = "refresh_lane_failed";
                            users.lock().unwrap().push(user);
                            return sample;
                        }
                        Err(_) => {
                            sample.outcome = "refresh_lane_pending";
                            users.lock().unwrap().push(user);
                            return sample;
                        }
                    }
                } else {
                    None
                };
                let sending = Instant::now();
                if sending < (scheduled + SEND_DEADLINE).min(end) {
                    sample.sent_ns = Some(nanos(sending - start));
                    (sample.status, sample.outcome) = request(
                        &mut user,
                        &fixtures[fixture_index],
                        &mut sample.http_requests,
                        refresh.as_deref_mut(),
                    )
                    .await;
                    sample.completed_ns = Some(nanos(start.elapsed()));
                }
                users.lock().unwrap().push(user);
                sample
            };
            if let Some((sender, _)) = &journal {
                let sender = sender.clone();
                tokio::spawn(async move {
                    let _ = sender.send(operation.await);
                });
            } else {
                pending.spawn(operation);
            }
        }
    }
    while let Some(observation) = pending.join_next().await {
        record(observation?)?;
    }
    if let Some(file) = direct.as_mut() {
        file.flush()?;
    }
    if let Some((sender, writer)) = journal {
        drop(sender);
        if writer.join().map_err(|_| "arrival writer panicked")?? != slots {
            return Err("arrival ledger incomplete".into());
        }
    }
    Ok(())
}
