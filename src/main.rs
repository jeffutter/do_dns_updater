use std::{
    env,
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    time::Duration,
};

use env_logger::Env;
use serde::Deserialize;
use stunclient::StunClient;
use ureq::Agent;

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct ListResponse {
    domain_records: Vec<DomainRecord>,
    links: Links,
    meta: Meta,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct UpdateResponse {
    domain_record: DomainRecord,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct DomainRecord {
    id: u32,
    #[serde(rename = "type")]
    t: String,
    name: String,
    data: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Meta {
    total: usize,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Links {
    pages: Option<Pages>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Pages {
    last: String,
    next: String,
}

fn get_ip() -> Result<IpAddr, Box<dyn std::error::Error>> {
    let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);

    UdpSocket::bind(&local_addr)
        .map_err(|x| x.into())
        .and_then(|socket| {
            StunClient::with_google_stun_server()
                .query_external_address(&socket)
                .map_err(|x| x.into())
                .map(|x| x.ip())
        })
}

fn list_do_records(
    agent: Agent,
    domain: &str,
    name: &str,
    token: &str,
) -> Result<ListResponse, Box<dyn std::error::Error>> {
    let url = format!("https://api.digitalocean.com/v2/domains/{}/records", domain);

    let body: ListResponse = agent
        .get(&url)
        .query("type", "A")
        .query("name", &format_name(domain, name))
        .set("Content-Type", "application/json")
        .set("Authorization", &format!("Bearer {}", token))
        .call()?
        .into_json()?;

    Ok(body)
}

fn update_ip(
    agent: Agent,
    domain: &str,
    id: u32,
    ip: IpAddr,
    token: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let url = format!(
        "https://api.digitalocean.com/v2/domains/{}/records/{}",
        domain, id
    );

    agent
        .patch(&url)
        .set("Content-Type", "application/json")
        .set("Authorization", &format!("Bearer {}", token))
        .send_json(ureq::json!({
              "type": "A",
              "data": ip
        }))?
        .into_json::<UpdateResponse>()?;

    Ok(())
}

fn format_name(domain: &str, name: &str) -> String {
    match name {
        "@" => domain.to_string(),
        _ => format!("{}.{}", name, domain),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let token = env::var("DO_TOKEN").expect("DO_TOKEN not set");
    let domain = env::var("DOMAIN").expect("DOMAIN not set");
    let name = env::var("NAME").expect("NAME not set");

    let agent: Agent = ureq::AgentBuilder::new()
        .timeout_read(Duration::from_secs(5))
        .timeout_write(Duration::from_secs(5))
        .build();

    let ip = get_ip()?;
    log::info!("Found Public IP: {:?}", ip);

    let records = list_do_records(agent.clone(), &domain, &name, &token)?;
    for record in records.domain_records {
        if record.data == ip.to_string() {
            log::info!(
                "Skipping {}.{} already set to {}",
                name,
                domain,
                record.data
            );
            continue;
        }

        log::info!("Updating {}.{} {} -> {:?}", name, domain, record.data, ip);

        update_ip(agent.clone(), &domain, record.id, ip, &token)?;

        log::info!("Updated {}.{} {} -> {:?}", name, domain, record.data, ip);
    }

    Ok(())
}
