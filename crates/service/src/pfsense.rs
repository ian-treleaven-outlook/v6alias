//! Source-specific native configuration compiler and pure offline CAS transactions.
//! This is not an API client, privileged executor, XML writer, or runtime reload adapter.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv6Addr},
};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use v6alias_core::Alias;

use crate::{
    Assignment, AssignmentState, Duid, ServiceConfig, ServiceError, Store, reconcile,
    shadow::validate_capture_time, validate_dns_label,
};

pub const CONTRACT: &str = "pfsense-2.8.1-isc-4.4.3P1-unbound-1.24.2-native-v1";
pub const COVERAGE: &str = "all-staticmaps-hosts-aliases-and-external-conflicts";
pub const TTL_CAPABILITY: &str = "unbound-local-data-default-3600-no-ttl-overrides";
pub const MAX_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_RECORDS: usize = 4096;
const MARKER: &str = "v6alias:";
const SCOPE: &str = "managed_dhcpv6_staticmaps_and_unbound_host_overrides";
const REQUIREMENTS: &[&str] = &[
    "live_privileged_executor_and_transport_not_installed_or_validated",
    "operator_approval_and_maintenance_window",
    "verify_installed_source_pins_and_complete_fresh_projection_on_router",
    "serialize_against_UI_writers_and_verify_full_config_revision_before_persistence",
    "harden_persistence_backup_revision_plugins_CARP_and_remote_ACB_side_effects",
    "avoid_nonreentrant_config_lock_and_write_config_deadlock",
    "DHCPv6_configure_also_configures_radvd_and_returns_void",
    "Unbound_configure_restarts_resolver_and_regenerates_hosts_and_lease_data",
    "verify_DHCPv6_RA_DNS_AAAA_PTR_TTL_health_independently_of_return_values",
    "runtime_activation_is_not_atomic_and_requires_guarded_recovery",
    "existing_clients_may_need_lease_reacquisition_no_static_ULA_changes",
];

mod digest;

type Result<T> = std::result::Result<T, ServiceError>;

fn invalid(detail: &'static str) -> ServiceError {
    ServiceError::Validation(format!("native pfSense: {detail}"))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bindings {
    pub schema_version: u32,
    pub source: String,
    pub links: BTreeMap<String, LinkBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkBinding {
    pub interface: String,
    /// Explicit operator audit/authorization; absence in a capture is NOT availability.
    pub approved_reservation_addresses: Vec<Ipv6Addr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeScope {
    pub subnet: Ipv6Addr,
    pub prefix_length: u8,
    pub router_address: Ipv6Addr,
    /// Non-DHCP static addresses from the operator's external inventory.
    pub external_static_addresses: Vec<Ipv6Addr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalDns {
    /// Absolute DNS owner, including any PTR owner and CNAME owner.
    pub name: String,
    pub addresses: Vec<IpAddr>,
}

/// `config` is a secret-free complete projection, NOT the complete config.xml.
/// Raw native maps retain opaque fields and insertion order; arrays retain order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Projection {
    pub schema_version: u32,
    pub source: String,
    pub captured_at_unix_secs: u64,
    pub source_contract: String,
    pub pfsense_version: String,
    pub dhcp_backend: String,
    pub isc_version: String,
    pub unbound_version: String,
    pub ttl_capability: String,
    pub complete: bool,
    pub coverage: String,
    /// SHA256 of the full router configuration, supplied by a future trusted helper.
    pub config_revision_sha256: String,
    /// Local simulation counter, never represented as a new router revision/hash.
    pub offline_generation: u64,
    pub scopes: BTreeMap<String, NativeScope>,
    pub external_dns: Vec<ExternalDns>,
    pub config: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum NativePath {
    #[serde(rename = "dhcpv6_staticmap")]
    StaticMap { interface: String },
    #[serde(rename = "unbound_hosts")]
    Hosts,
}

impl NativePath {
    fn display(&self) -> String {
        match self {
            Self::StaticMap { interface } => format!("dhcpdv6/{interface}/staticmap"),
            Self::Hosts => "unbound/hosts".into(),
        }
    }

    fn collection<'a>(&self, projection: &'a Projection) -> Result<&'a Vec<Value>> {
        let value = match self {
            Self::StaticMap { interface } => &projection.config["dhcpdv6"][interface]["staticmap"],
            Self::Hosts => &projection.config["unbound"]["hosts"],
        };
        value
            .as_array()
            .ok_or_else(|| invalid("missing native collection"))
    }

    fn replace(&self, projection: &mut Projection, records: Vec<Value>) {
        // Only compiler-created paths reach this function, after complete validation.
        match self {
            Self::StaticMap { interface } => {
                projection.config["dhcpdv6"][interface]["staticmap"] = Value::Array(records);
            }
            Self::Hosts => projection.config["unbound"]["hosts"] = Value::Array(records),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectionChange {
    pub path: NativePath,
    pub before: Vec<Value>,
    pub after: Vec<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema_version: u32,
    pub mode: String,
    pub mutation_scope: String,
    pub network_writes: bool,
    pub approval_required: bool,
    pub source_contract: String,
    pub expected_revision_sha256: String,
    pub baseline_projection_sha256: String,
    pub authority_sha256: String,
    pub candidate_projection_sha256: String,
    pub allowed_paths: Vec<String>,
    pub changes: Vec<CollectionChange>,
    pub activation_requirements: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackToken {
    pub request_sha256: String,
    pub baseline_projection_sha256: String,
    pub candidate_projection_sha256: String,
    pub expected_revision_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Simulation {
    pub schema_version: u32,
    pub mode: String,
    pub mutation_scope: String,
    pub network_writes: bool,
    pub approval_required: bool,
    pub request: Request,
    pub projection: Projection,
    pub rollback: RollbackToken,
}

#[derive(Debug, Clone, Serialize)]
pub struct RollbackResult {
    pub schema_version: u32,
    pub mode: &'static str,
    pub operation: &'static str,
    pub mutation_scope: &'static str,
    pub network_writes: bool,
    pub approval_required: bool,
    pub projection: Projection,
}

/// Canonical object-key sorting makes key order irrelevant to CAS/hash comparisons.
/// Array order and every opaque value remain significant. Stored objects are never sorted.
pub fn canonical_sha256(value: &impl Serialize) -> Result<String> {
    fn sorted(value: Value) -> Value {
        match value {
            Value::Object(map) => Value::Object(
                map.into_iter()
                    .collect::<BTreeMap<_, _>>()
                    .into_iter()
                    .map(|(key, value)| (key, sorted(value)))
                    .collect(),
            ),
            Value::Array(values) => Value::Array(values.into_iter().map(sorted).collect()),
            other => other,
        }
    }
    let value = serde_json::to_value(value)?;
    validate_numbers(&value)?;
    let bytes = serde_json::to_vec(&sorted(value))?;
    Ok(digest::sha256(&bytes))
}

pub fn from_json<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    if bytes.len() as u64 > MAX_BYTES {
        return Err(invalid("input exceeds 16 MiB"));
    }
    // Reject duplicate keys, including opaque objects, rather than silently dropping data.
    let value: StrictValue = serde_json::from_slice(bytes)
        .map_err(|_| invalid("invalid JSON, duplicate key, or excessive nesting"))?;
    serde_json::from_value(value.0).map_err(|_| invalid("unsupported input schema or shape"))
}

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = StrictValue;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("JSON without duplicate object keys")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut result = Map::new();
                while let Some((key, value)) = map.next_entry::<String, StrictValue>()? {
                    if result.insert(key, value.0).is_some() {
                        return Err(serde::de::Error::custom("duplicate key"));
                    }
                }
                Ok(StrictValue(Value::Object(result)))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element::<StrictValue>()? {
                    values.push(value.0);
                }
                Ok(StrictValue(Value::Array(values)))
            }
            fn visit_str<E: serde::de::Error>(
                self,
                value: &str,
            ) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(json!(value)))
            }
            fn visit_bool<E: serde::de::Error>(
                self,
                value: bool,
            ) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(json!(value)))
            }
            fn visit_i64<E: serde::de::Error>(
                self,
                value: i64,
            ) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(json!(value)))
            }
            fn visit_u64<E: serde::de::Error>(
                self,
                value: u64,
            ) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(json!(value)))
            }
            fn visit_f64<E: serde::de::Error>(
                self,
                _value: f64,
            ) -> std::result::Result<Self::Value, E> {
                Err(serde::de::Error::custom(
                    "native projections require exact 64-bit integer numbers",
                ))
            }
            fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

fn bounded(value: &impl Serialize) -> Result<()> {
    let value = serde_json::to_value(value)?;
    validate_numbers(&value)?;
    if serde_json::to_vec(&value)?.len() as u64 > MAX_BYTES {
        return Err(invalid("document exceeds 16 MiB"));
    }
    Ok(())
}

fn validate_numbers(value: &Value) -> Result<()> {
    match value {
        Value::Number(number) if number.is_f64() => {
            return Err(invalid(
                "floating-point and out-of-range integer numbers are unsupported",
            ));
        }
        Value::Array(values) => {
            for value in values {
                validate_numbers(value)?;
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                validate_numbers(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn object(value: &Value) -> Result<&Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| invalid("expected native object"))
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("missing or non-string native field"))
}

fn optional_text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    match value.get(key) {
        None => Ok(""),
        Some(Value::String(value)) => Ok(value),
        _ => Err(invalid("unsupported native optional field")),
    }
}

fn ip6(value: &str) -> Result<Ipv6Addr> {
    value.parse().map_err(|_| invalid("invalid IPv6 field"))
}

fn interface(value: &str) -> Result<()> {
    if !matches!(value, "lan" | "opt1" | "opt2") {
        return Err(invalid(
            "unsupported interface; only lan, opt1, opt2 are pinned",
        ));
    }
    Ok(())
}

fn network(address: Ipv6Addr) -> u128 {
    u128::from(address) & (!0u128 << 64)
}

fn native_duid(duid: &Duid) -> String {
    duid.as_str()
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| std::str::from_utf8(pair).expect("DUID is ASCII"))
        .collect::<Vec<_>>()
        .join(":")
}

fn dns_name(name: &str) -> Result<String> {
    let normalized = name.trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty() || normalized.len() > 253 || name.ends_with("..") {
        return Err(invalid("unsupported DNS owner"));
    }
    for label in normalized.split('.') {
        validate_dns_label(label).map_err(|_| invalid("unsupported DNS label"))?;
    }
    Ok(format!("{normalized}."))
}

fn host_name(record: &Value) -> Result<String> {
    let host = text(record, "host")?;
    let domain = text(record, "domain")?;
    if domain.is_empty() || host.contains('.') {
        return Err(invalid("unsupported host/domain shape"));
    }
    dns_name(&if host.is_empty() {
        domain.to_owned()
    } else {
        format!("{host}.{domain}")
    })
}

fn marker(record: &Value) -> Result<bool> {
    Ok(optional_text(record, "descr")?.starts_with(MARKER))
}

fn owned_records(config: &ServiceConfig, assignment: &Assignment) -> (Value, Value) {
    let hostname = assignment.fqdn.split('.').next().expect("validated FQDN");
    let description = format!("{MARKER}{}", assignment.asset_id);
    (
        json!({
            "duid": native_duid(&assignment.duid), "ipaddrv6": assignment.address.to_string(),
            "hostname": hostname, "descr": description, "earlydnsregpolicy": "disable",
            "filename": "", "rootpath": ""
        }),
        json!({
            "host": hostname, "domain": config.dns_zone, "ip": assignment.address.to_string(),
            "descr": description, "aliases": {"item": []}
        }),
    )
}

#[derive(Default)]
struct Index {
    duids: BTreeSet<Duid>,
    dhcp_addresses: BTreeSet<Ipv6Addr>,
    dhcp_names: BTreeSet<String>,
    dns_names: BTreeSet<String>,
    dns_addresses: BTreeSet<IpAddr>,
}

fn unique<T: Ord>(set: &mut BTreeSet<T>, value: T) -> Result<()> {
    if !set.insert(value) {
        return Err(invalid("duplicate native identity, address or DNS owner"));
    }
    Ok(())
}

fn inspect_static(record: &Value, index: &mut Index) -> Result<()> {
    object(record)?;
    // ISC has no IAID selector; accepting such a field would imply false isolation.
    if ["iaid", "prefix", "pdprefix", "custom_kea_config"]
        .iter()
        .any(|field| record.get(field).is_some())
    {
        return Err(invalid(
            "IAID-specific or delegated-prefix mappings are unsupported",
        ));
    }
    let raw = text(record, "duid")?;
    let duid: Duid = raw.parse().map_err(|_| invalid("invalid native DUID"))?;
    if native_duid(&duid) != raw {
        return Err(invalid(
            "native DUID must be colon-separated lowercase bytes",
        ));
    }
    unique(&mut index.duids, duid)?;
    let address = optional_text(record, "ipaddrv6")?;
    if !address.is_empty() {
        unique(&mut index.dhcp_addresses, ip6(address)?)?;
    }
    let hostname = optional_text(record, "hostname")?;
    if !hostname.is_empty() {
        unique(&mut index.dhcp_names, dns_name(hostname)?)?;
    }
    optional_text(record, "descr")?;
    Ok(())
}

fn inspect_host(record: &Value, index: &mut Index) -> Result<()> {
    object(record)?;
    unique(&mut index.dns_names, host_name(record)?)?;
    let ips = text(record, "ip")?;
    if ips.len() > 8192 {
        return Err(invalid("host address list exceeds limit"));
    }
    let addresses = ips.split(',').collect::<Vec<_>>();
    if addresses.len() > 128 {
        return Err(invalid("too many addresses in host override"));
    }
    for address in addresses {
        unique(
            &mut index.dns_addresses,
            address
                .trim()
                .parse::<IpAddr>()
                .map_err(|_| invalid("unsupported native host IP list"))?,
        )?;
    }
    if let Some(aliases) = record.get("aliases") {
        let aliases_map = object(aliases)?;
        if aliases_map.len() != 1 {
            return Err(invalid("unsupported native aliases object"));
        }
        let items = aliases
            .get("item")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("aliases/item must be an array"))?;
        if items.len() > 128 {
            return Err(invalid("too many aliases"));
        }
        for alias in items {
            if object(alias)?
                .keys()
                .any(|key| !matches!(key.as_str(), "host" | "domain" | "description"))
            {
                return Err(invalid("unsupported native alias fields"));
            }
            unique(&mut index.dns_names, host_name(alias)?)?;
        }
    }
    // No TTL/CNAME mechanism is part of this native host-override contract.
    if record.get("ttl").is_some() || record.get("cname").is_some() {
        return Err(invalid("unsupported native TTL or CNAME shape"));
    }
    optional_text(record, "descr")?;
    Ok(())
}

impl Projection {
    pub fn validate_freshness(&self, source: &str, now: u64, max_age: u64) -> Result<()> {
        validate_dns_label(source).map_err(|_| invalid("invalid source binding"))?;
        if self.source != source {
            return Err(invalid("source does not match operator binding"));
        }
        validate_capture_time("native", self.captured_at_unix_secs, now, max_age)
    }

    fn validate(
        &self,
        config: &ServiceConfig,
        bindings: &Bindings,
        now: u64,
        max_age: u64,
    ) -> Result<Index> {
        bounded(self)?;
        bounded(bindings)?;
        config.validate()?;
        self.validate_freshness(&bindings.source, now, max_age)?;
        if config.dns_ttl_seconds != 3600 {
            return Err(invalid(
                "native Unbound host overrides require explicit DNS TTL 3600",
            ));
        }
        if self.schema_version != 1
            || bindings.schema_version != 1
            || self.source_contract != CONTRACT
            || self.pfsense_version != "2.8.1-RELEASE"
            || self.dhcp_backend != "isc"
            || self.isc_version != "4.4.3P1"
            || self.unbound_version != "1.24.2"
            || self.ttl_capability != TTL_CAPABILITY
            || !self.complete
            || self.coverage != COVERAGE
        {
            return Err(invalid(
                "unsupported source, backend, version, capability or incomplete projection",
            ));
        }
        if self.config_revision_sha256.len() != 64
            || !self
                .config_revision_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(invalid("full-config revision must be lowercase SHA256"));
        }
        object(&self.config)?;
        let native_interfaces = object(&self.config["interfaces"])?;
        let dhcp = object(&self.config["dhcpdv6"])?;
        let unbound = object(&self.config["unbound"])?;
        if dhcp.is_empty()
            || dhcp.len() > 3
            || dhcp.len() != self.scopes.len()
            || bindings.links.len() != config.links.len()
        {
            return Err(invalid(
                "all native scopes and all configured link bindings are required",
            ));
        }
        // The complete projection helper must expand other effective records into
        // external_dns. Opaque fields are retained, not interpreted as instructions.
        for field in ["custom_options", "custom-options"] {
            if unbound.get(field).is_some_and(|v| v != "") {
                return Err(invalid(
                    "custom Unbound configuration is outside the pinned contract",
                ));
            }
        }
        let mut interfaces = BTreeSet::new();
        for (link_name, binding) in &bindings.links {
            interface(&binding.interface)?;
            unique(&mut interfaces, &binding.interface)?;
            let link = config
                .links
                .get(link_name)
                .ok_or_else(|| invalid("unknown link binding"))?;
            let scope = self
                .scopes
                .get(&binding.interface)
                .ok_or_else(|| invalid("missing native scope"))?;
            let resolved = config.address_config().resolve(&Alias {
                profile: link.profile.clone(),
                subnet: Some(link.subnet),
                device: 2,
            })?;
            if network(resolved) != u128::from(scope.subnet) {
                return Err(invalid("link prefix/subnet does not match native /64"));
            }
            if binding.approved_reservation_addresses.len() > MAX_RECORDS {
                return Err(invalid("too many approved reservation addresses"));
            }
            let mut approved = BTreeSet::new();
            for &address in &binding.approved_reservation_addresses {
                unique(&mut approved, address)?;
                let slot = u128::from(address) - network(address);
                if network(address) != network(resolved)
                    || slot < u128::from(link.pool.first)
                    || slot > u128::from(link.pool.last)
                    || link.reserved.contains(&(slot as u16))
                {
                    return Err(invalid("approved address outside allocatable link pool"));
                }
            }
        }
        let mut index = Index::default();
        let mut count = self.external_dns.len();
        let mut subnets = BTreeSet::new();
        for (name, value) in dhcp {
            interface(name)?;
            object(value)?;
            let scope = self
                .scopes
                .get(name)
                .ok_or_else(|| invalid("missing native scope"))?;
            let native_interface = native_interfaces
                .get(name)
                .ok_or_else(|| invalid("missing native interface address configuration"))?;
            let fields = object(native_interface)?;
            if fields.keys().any(|key| key.starts_with("track6"))
                || text(native_interface, "subnetv6")? != "64"
                || ip6(text(native_interface, "ipaddrv6")?)? != scope.router_address
            {
                return Err(invalid(
                    "native interface must have the fixed /64 router address; tracked scopes are unsupported",
                ));
            }
            unique(&mut subnets, scope.subnet)?;
            if value.get("pool").is_some_and(|v| v != &json!([]))
                || value.get("prefixrange").is_some()
                || value.get("custom_kea_config").is_some()
                || value.get("ipaddrv6").is_some_and(|v| v == "track6")
            {
                return Err(invalid(
                    "additional pools, prefix delegation, tracked scopes or custom backends are unsupported",
                ));
            }
            if scope.prefix_length != 64
                || network(scope.subnet) != u128::from(scope.subnet)
                || network(scope.router_address) != u128::from(scope.subnet)
                || scope.router_address == scope.subnet
            {
                return Err(invalid("invalid fixed native /64 or router address"));
            }
            let range = &value["range"];
            if object(range)?.len() != 2 {
                return Err(invalid("unsupported native range shape"));
            }
            let from = ip6(text(range, "from")?)?;
            let to = ip6(text(range, "to")?)?;
            if u128::from(from) != u128::from(scope.subnet) + 0x1000
                || u128::from(to) != u128::from(scope.subnet) + 0xffff
            {
                return Err(invalid(
                    "native bootstrap range must be /64::1000 through ::ffff",
                ));
            }
            let mut external = BTreeSet::new();
            if scope.external_static_addresses.len() > MAX_RECORDS {
                return Err(invalid("external address inventory exceeds limit"));
            }
            for &address in &scope.external_static_addresses {
                if network(address) != u128::from(scope.subnet) {
                    return Err(invalid("external static address outside native scope"));
                }
                unique(&mut external, address)?;
            }
            let records = NativePath::StaticMap {
                interface: name.clone(),
            }
            .collection(self)?;
            count += records.len();
            for record in records {
                inspect_static(record, &mut index)?;
                let address = optional_text(record, "ipaddrv6")?;
                if !address.is_empty() && network(ip6(address)?) != u128::from(scope.subnet) {
                    return Err(invalid("native static mapping is outside its scope"));
                }
            }
        }
        let hosts = NativePath::Hosts.collection(self)?;
        count += hosts.len();
        if count > MAX_RECORDS {
            return Err(invalid("native record count exceeds 4096"));
        }
        for host in hosts {
            inspect_host(host, &mut index)?;
        }
        for external in &self.external_dns {
            if !external.name.ends_with('.') {
                return Err(invalid("external DNS owner must be absolute"));
            }
            if external.addresses.len() > 128 {
                return Err(invalid("external DNS address list exceeds limit"));
            }
            unique(&mut index.dns_names, dns_name(&external.name)?)?;
            for &address in &external.addresses {
                // External A/AAAA and PTR records legitimately share an address.
                index.dns_addresses.insert(address);
            }
        }
        Ok(index)
    }
}

/// Reads the complete retained assignment history from an existing authoritative Store.
pub fn compile(
    store: &Store,
    config: &ServiceConfig,
    bindings: &Bindings,
    baseline: &Projection,
    now: u64,
    max_age: u64,
) -> Result<Request> {
    let history = store.assignments(config)?;
    compile_history(config, &history, bindings, baseline, now, max_age)
}

fn compile_history(
    config: &ServiceConfig,
    history: &[Assignment],
    bindings: &Bindings,
    baseline: &Projection,
    now: u64,
    max_age: u64,
) -> Result<Request> {
    if history.len() > MAX_RECORDS {
        return Err(invalid("assignment history exceeds 4096"));
    }
    reconcile::plan(config, history, None)?;
    baseline.validate(config, bindings, now, max_age)?;
    let mut known: Vec<(NativePath, Value, bool)> = Vec::new();
    for assignment in history {
        let binding = &bindings.links[&assignment.link];
        let scope = &baseline.scopes[&binding.interface];
        if !binding
            .approved_reservation_addresses
            .contains(&assignment.address)
            || assignment.address == scope.router_address
            || scope
                .external_static_addresses
                .contains(&assignment.address)
        {
            return Err(invalid(
                "assignment lacks operator address approval or conflicts with router/external static IP",
            ));
        }
        let (reservation, host) = owned_records(config, assignment);
        let active = assignment.state == AssignmentState::Active;
        known.push((
            NativePath::StaticMap {
                interface: binding.interface.clone(),
            },
            reservation,
            active,
        ));
        known.push((NativePath::Hosts, host, active));
    }
    let mut paths: Vec<_> = bindings
        .links
        .values()
        .map(|binding| NativePath::StaticMap {
            interface: binding.interface.clone(),
        })
        .collect();
    paths.sort_by_key(NativePath::display);
    paths.push(NativePath::Hosts);
    let mut foreign = Index::default();
    // Inspect every interface, including unbound/unmanaged ones, before removing anything.
    for name in baseline.scopes.keys() {
        let path = NativePath::StaticMap {
            interface: name.clone(),
        };
        for record in path.collection(baseline)? {
            let exact = known.iter().any(|(p, v, _)| p == &path && v == record);
            if marker(record)? && !exact {
                return Err(invalid(
                    "ownership marker is unknown or native owned mapping drifted",
                ));
            }
            if !exact {
                inspect_static(record, &mut foreign)?;
            }
        }
    }
    for record in NativePath::Hosts.collection(baseline)? {
        let exact = known
            .iter()
            .any(|(p, v, _)| *p == NativePath::Hosts && v == record);
        if marker(record)? && !exact {
            return Err(invalid(
                "ownership marker is unknown or native owned host drifted",
            ));
        }
        if !exact {
            inspect_host(record, &mut foreign)?;
        }
    }
    for external in &baseline.external_dns {
        foreign.dns_names.insert(dns_name(&external.name)?);
        foreign.dns_addresses.extend(&external.addresses);
    }
    // Tombstones protect keys too: do not adopt foreign records into retained history.
    for assignment in history {
        let label = assignment.fqdn.split('.').next().expect("validated FQDN");
        if foreign.duids.contains(&assignment.duid)
            || foreign.dhcp_addresses.contains(&assignment.address)
            || foreign.dhcp_names.contains(&format!("{label}."))
            || foreign.dhcp_names.contains(&assignment.fqdn)
            || foreign.dns_names.contains(&assignment.fqdn)
            || foreign
                .dns_names
                .contains(&reconcile::reverse_name(assignment.address))
            || foreign
                .dns_addresses
                .contains(&IpAddr::V6(assignment.address))
        {
            return Err(invalid(
                "unmanaged DUID, address, FQDN, alias or PTR owner conflicts with history",
            ));
        }
    }
    let mut changes = Vec::new();
    for path in &paths {
        let before = path.collection(baseline)?.clone();
        let mut after = before
            .iter()
            .filter(|record| {
                !known
                    .iter()
                    .any(|(p, v, active)| p == path && v == *record && !active)
            })
            .cloned()
            .collect::<Vec<_>>();
        let mut additions = known
            .iter()
            .filter(|(p, value, active)| p == path && *active && !before.contains(value))
            .map(|(_, value, _)| value.clone())
            .collect::<Vec<_>>();
        additions.sort_by_key(|value| value["descr"].as_str().unwrap_or_default().to_owned());
        after.extend(additions);
        if after != before {
            changes.push(CollectionChange {
                path: path.clone(),
                before,
                after,
            });
        }
    }
    let candidate = transform(baseline, &changes, false)?;
    // Revalidate total candidate counts and global uniqueness after appending.
    candidate.validate(config, bindings, now, max_age)?;
    let request = Request {
        schema_version: 1,
        mode: "native_plan".into(),
        mutation_scope: SCOPE.into(),
        network_writes: false,
        approval_required: true,
        source_contract: CONTRACT.into(),
        expected_revision_sha256: baseline.config_revision_sha256.clone(),
        baseline_projection_sha256: canonical_sha256(baseline)?,
        authority_sha256: canonical_sha256(&(config.identity()?, history, bindings))?,
        candidate_projection_sha256: canonical_sha256(&candidate)?,
        allowed_paths: paths.iter().map(NativePath::display).collect(),
        changes,
        activation_requirements: REQUIREMENTS.iter().map(|s| (*s).into()).collect(),
    };
    bounded(&request)?;
    Ok(request)
}

fn transform(
    baseline: &Projection,
    changes: &[CollectionChange],
    reverse: bool,
) -> Result<Projection> {
    let mut candidate = baseline.clone();
    for change in changes {
        let (expected, replacement) = if reverse {
            (&change.after, &change.before)
        } else {
            (&change.before, &change.after)
        };
        if change.path.collection(&candidate)? != expected {
            return Err(invalid("native collection precondition failed"));
        }
        change.path.replace(&mut candidate, replacement.clone());
    }
    if !changes.is_empty() {
        candidate.offline_generation = candidate
            .offline_generation
            .checked_add(1)
            .ok_or_else(|| invalid("offline generation exhausted"))?;
    }
    Ok(candidate)
}

/// Actual pure configuration transformation, with whole-input CAS and authority recompilation.
/// No request-supplied paths or desired values are executed without matching the compiler.
pub fn simulate(
    store: &Store,
    config: &ServiceConfig,
    bindings: &Bindings,
    baseline: &Projection,
    request: &Request,
    now: u64,
    max_age: u64,
) -> Result<Simulation> {
    let compiled = compile(store, config, bindings, baseline, now, max_age)?;
    if canonical_sha256(request)? != canonical_sha256(&compiled)? {
        return Err(invalid(
            "request differs from current authoritative compilation",
        ));
    }
    let projection = transform(baseline, &compiled.changes, false)?;
    let rollback = RollbackToken {
        request_sha256: canonical_sha256(&compiled)?,
        baseline_projection_sha256: compiled.baseline_projection_sha256.clone(),
        candidate_projection_sha256: compiled.candidate_projection_sha256.clone(),
        expected_revision_sha256: compiled.expected_revision_sha256.clone(),
    };
    let result = Simulation {
        schema_version: 1,
        mode: "offline_simulation".into(),
        mutation_scope: SCOPE.into(),
        network_writes: false,
        approval_required: true,
        request: compiled,
        projection,
        rollback,
    };
    bounded(&result)?;
    Ok(result)
}

/// Roll back only exact compiled paths, and only against the exact simulated poststate.
/// An unrelated edit anywhere in the projection or a full-config revision change refuses.
pub fn rollback(
    store: &Store,
    config: &ServiceConfig,
    bindings: &Bindings,
    baseline: &Projection,
    poststate: (&Projection, &Simulation),
    now: u64,
    max_age: u64,
) -> Result<RollbackResult> {
    let (current, simulation) = poststate;
    let verified = simulate(
        store,
        config,
        bindings,
        baseline,
        &simulation.request,
        now,
        max_age,
    )?;
    if canonical_sha256(&verified)? != canonical_sha256(simulation)?
        || canonical_sha256(current)? != verified.rollback.candidate_projection_sha256
        || current.config_revision_sha256 != verified.rollback.expected_revision_sha256
    {
        return Err(invalid(
            "rollback token or exact poststate/revision precondition failed",
        ));
    }
    let projection = transform(current, &verified.request.changes, true)?;
    let result = RollbackResult {
        schema_version: 1,
        mode: "offline_simulation",
        operation: "rollback",
        mutation_scope: SCOPE,
        network_writes: false,
        approval_required: true,
        projection,
    };
    bounded(&result)?;
    Ok(result)
}

#[cfg(test)]
mod tests;
