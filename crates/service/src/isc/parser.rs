use std::{collections::BTreeMap, net::Ipv6Addr};

use super::{
    Counts, Duid, MAX_ADDRESSES, MAX_ASSOCIATIONS, MAX_RECORD_BYTES, MAX_TOKEN_BYTES, MAX_TOKENS,
    Result, invalid,
};

#[derive(Debug, PartialEq)]
enum Token {
    Word(String),
    Bytes(Vec<u8>),
    Punct(u8),
}

struct Lexer<'a> {
    bytes: &'a [u8],
    pos: usize,
    tokens: usize,
    limits: Limits,
    record_start: Option<usize>,
}

#[derive(Clone, Copy)]
struct Limits {
    token_bytes: usize,
    tokens: usize,
    record_bytes: usize,
    associations: usize,
    addresses: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            token_bytes: MAX_TOKEN_BYTES,
            tokens: MAX_TOKENS,
            record_bytes: MAX_RECORD_BYTES,
            associations: MAX_ASSOCIATIONS,
            addresses: MAX_ADDRESSES,
        }
    }
}

impl Lexer<'_> {
    fn error(&self, message: &str) -> crate::ServiceError {
        invalid(format!("ISC byte {}: {message}", self.pos))
    }

    fn advance(&mut self) -> Result<u8> {
        let value = *self
            .bytes
            .get(self.pos)
            .ok_or_else(|| self.error("unexpected end of file"))?;
        self.pos += 1;
        if self
            .record_start
            .is_some_and(|start| self.pos - start > self.limits.record_bytes)
        {
            return Err(self.error("association record byte limit exceeded"));
        }
        Ok(value)
    }

    fn next(&mut self) -> Result<Option<Token>> {
        while let Some(&b) = self.bytes.get(self.pos) {
            if b.is_ascii_whitespace() {
                self.advance()?;
            } else if b == b'#' {
                while self.bytes.get(self.pos).is_some_and(|b| *b != b'\n') {
                    self.advance()?;
                }
            } else {
                break;
            }
        }
        let Some(&first) = self.bytes.get(self.pos) else {
            return Ok(None);
        };
        self.tokens += 1;
        if self.tokens > self.limits.tokens {
            return Err(self.error("token count limit exceeded"));
        }
        if b"{};=".contains(&first) {
            self.advance()?;
            return Ok(Some(Token::Punct(first)));
        }
        let start = self.pos;
        if first == b'"' {
            self.advance()?;
            let mut bytes = Vec::new();
            loop {
                let b = self.advance()?;
                if self.pos - start > self.limits.token_bytes {
                    return Err(self.error("token byte limit exceeded"));
                }
                match b {
                    b'"' => return Ok(Some(Token::Bytes(bytes))),
                    b'\\' => {
                        let escaped = self.advance()?;
                        let decoded = match escaped {
                            b'"' | b'\\' => escaped,
                            b'0'..=b'3' => {
                                let second = self.advance()?;
                                let third = self.advance()?;
                                if !(b'0'..=b'7').contains(&second)
                                    || !(b'0'..=b'7').contains(&third)
                                {
                                    return Err(self.error("expected exactly three octal digits"));
                                }
                                (escaped - b'0') * 64 + (second - b'0') * 8 + (third - b'0')
                            }
                            _ => return Err(self.error("unsupported quoted-byte escape")),
                        };
                        bytes.push(decoded);
                    }
                    0x20..=0x7e => bytes.push(b),
                    _ => return Err(self.error("raw quoted bytes must be printable ASCII")),
                }
            }
        }
        while let Some(&b) = self.bytes.get(self.pos) {
            if b.is_ascii_whitespace() || b"{};=#\"".contains(&b) {
                break;
            }
            if !(0x21..=0x7e).contains(&b) || b == b'\\' {
                return Err(self.error("invalid unquoted byte"));
            }
            self.advance()?;
            if self.pos - start > self.limits.token_bytes {
                return Err(self.error("token byte limit exceeded"));
            }
        }
        let word = std::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| self.error("non-ASCII token"))?;
        Ok(Some(Token::Word(word.to_owned())))
    }

    fn required(&mut self) -> Result<Token> {
        self.next()?
            .ok_or_else(|| self.error("unexpected end of file"))
    }

    fn word(&mut self) -> Result<String> {
        match self.required()? {
            Token::Word(word) => Ok(word),
            _ => Err(self.error("expected unquoted token")),
        }
    }

    fn expect(&mut self, expected: Token) -> Result<()> {
        if self.required()? != expected {
            return Err(self.error("unexpected token"));
        }
        Ok(())
    }

    fn punct(&mut self, expected: u8) -> Result<()> {
        self.expect(Token::Punct(expected))
    }

    fn keyword(&mut self, expected: &str) -> Result<()> {
        self.expect(Token::Word(expected.into()))
    }

    fn identifier(&mut self, server: bool) -> Result<Vec<u8>> {
        let (bytes, quoted) = match self.required()? {
            Token::Bytes(bytes) => (bytes, true),
            Token::Word(word) => {
                let mut bytes = Vec::new();
                for part in word.split(':') {
                    if part.len() != 2 || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
                        return Err(
                            self.error("identifier requires colon-separated hex byte pairs")
                        );
                    }
                    bytes
                        .push(u8::from_str_radix(part, 16).map_err(|_| self.error("invalid hex"))?);
                }
                (bytes, false)
            }
            _ => return Err(self.error("expected quoted or hexadecimal identifier")),
        };
        // ISC's quoted reader reserves one byte for NUL. Never silently truncate.
        let (min, max) = match (server, quoted) {
            (true, true) => (3, 127),
            (true, false) => (3, 128),
            (false, true) => (6, 131),
            (false, false) => (6, 132),
        };
        if !(min..=max).contains(&bytes.len()) {
            return Err(self.error("identifier byte length outside supported ISC reader bounds"));
        }
        Ok(bytes)
    }

    fn number(&mut self) -> Result<u32> {
        let word = self.word()?;
        unsigned(&word).ok_or_else(|| self.error("expected decimal u32"))
    }

    fn date(&mut self, allow_never: bool) -> Result<End> {
        let first = self.word()?;
        let end = match first.as_str() {
            "never" if allow_never => End::Never,
            "epoch" => {
                let epoch = self.number()?;
                if epoch >= 2_147_483_647 {
                    return Err(self.error("finite epoch must be 0..2147483646"));
                }
                End::Finite(epoch.into())
            }
            _ => {
                let weekday = unsigned(&first)
                    .filter(|d| *d <= 6 && first.len() == 1)
                    .ok_or_else(|| self.error("expected finite date (or ends never)"))?;
                let date = self.word()?;
                let time = self.word()?;
                let epoch = calendar_epoch(weekday, &date, &time)
                    .ok_or_else(|| self.error("invalid UTC date; supported years 1970..2037"))?;
                End::Finite(epoch)
            }
        };
        // No numeric timezone suffix or guessed local time.
        self.punct(b';')?;
        Ok(end)
    }
}

fn unsigned(word: &str) -> Option<u32> {
    if word.is_empty() || !word.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    word.parse().ok()
}

fn calendar_epoch(weekday: u32, date: &str, time: &str) -> Option<u64> {
    if date.len() != 10
        || time.len() != 8
        || date.as_bytes()[4] != b'/'
        || date.as_bytes()[7] != b'/'
        || time.as_bytes()[2] != b':'
        || time.as_bytes()[5] != b':'
    {
        return None;
    }
    let year = unsigned(&date[..4])?;
    let month = unsigned(&date[5..7])?;
    let day = unsigned(&date[8..])?;
    let hour = unsigned(&time[..2])?;
    let minute = unsigned(&time[3..5])?;
    let second = unsigned(&time[6..])?;
    if !(1970..=2037).contains(&year)
        || !(1..=12).contains(&month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let leap = |y: u32| y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400));
    let month_days = [
        31,
        if leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if day == 0 || day > month_days[month as usize - 1] {
        return None;
    }
    let days: u64 = (1970..year)
        .map(|y| if leap(y) { 366 } else { 365 })
        .sum::<u64>()
        + month_days[..month as usize - 1]
            .iter()
            .map(|d| u64::from(*d))
            .sum::<u64>()
        + u64::from(day - 1);
    if (days + 4) % 7 != u64::from(weekday) {
        return None;
    }
    Some(days * 86400 + u64::from(hour * 3600 + minute * 60 + second))
}

#[derive(Debug)]
pub(super) enum End {
    Never,
    Finite(u64),
}

impl End {
    pub(super) fn live_at(&self, now: u64) -> bool {
        match self {
            Self::Never => true,
            Self::Finite(end) => *end > now,
        }
    }
}

#[derive(Debug)]
pub(super) struct Address {
    pub address: Ipv6Addr,
    pub active: bool,
    pub ends: End,
}

type Associations = BTreeMap<(Duid, u32), Vec<Address>>;

pub(super) fn parse(bytes: &[u8]) -> Result<(Associations, Counts)> {
    parse_with_limits(bytes, Limits::default())
}

fn parse_with_limits(bytes: &[u8], limits: Limits) -> Result<(Associations, Counts)> {
    let mut lex = Lexer {
        bytes,
        pos: 0,
        tokens: 0,
        limits,
        record_start: None,
    };
    let mut records = BTreeMap::new();
    let mut counts = Counts::default();
    let mut order = None;
    let mut server_duid = None;
    while let Some(token) = lex.next()? {
        match token {
            Token::Word(word) if word == "authoring-byte-order" => {
                if order.is_some() || counts.association_records != 0 {
                    return Err(lex.error("duplicate or late authoring-byte-order header"));
                }
                let little = match lex.word()?.as_str() {
                    "little-endian" => true,
                    "big-endian" => false,
                    _ => return Err(lex.error("unknown authoring-byte-order")),
                };
                lex.punct(b';')?;
                order = Some(little);
                counts.authoring_byte_order = Some(if little {
                    "little-endian"
                } else {
                    "big-endian"
                });
            }
            Token::Word(word) if word == "server-duid" => {
                if counts.association_records != 0 {
                    return Err(lex.error("late server-duid header"));
                }
                let identity = lex.identifier(true)?;
                lex.punct(b';')?;
                // ISC can repeat the same server identity in a header-only file.
                if server_duid
                    .as_ref()
                    .is_some_and(|previous| previous != &identity)
                {
                    return Err(lex.error("conflicting server-duid headers"));
                }
                server_duid = Some(identity);
                counts.server_duid_present = true;
            }
            Token::Word(word) if word == "ia-na" => {
                let little =
                    order.ok_or_else(|| lex.error("IA_NA requires authoring-byte-order header"))?;
                counts.association_records += 1;
                if counts.association_records > limits.associations {
                    return Err(lex.error("association record count limit exceeded"));
                }
                lex.record_start = Some(lex.pos - 5);
                let id = lex.identifier(false)?;
                let iaid_bytes = [id[0], id[1], id[2], id[3]];
                let iaid = if little {
                    u32::from_le_bytes(iaid_bytes)
                } else {
                    u32::from_be_bytes(iaid_bytes)
                };
                let duid: Duid = id[4..]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
                    .parse()?;
                lex.punct(b'{')?;
                let mut addresses = BTreeMap::new();
                let mut cltt_seen = false;
                loop {
                    match lex.required()? {
                        Token::Punct(b'}') => break,
                        Token::Word(word) if word == "cltt" && !cltt_seen => {
                            lex.date(false)?;
                            cltt_seen = true;
                        }
                        Token::Word(word) if word == "iaaddr" => {
                            counts.address_records += 1;
                            if counts.address_records > limits.addresses {
                                return Err(lex.error("address record count limit exceeded"));
                            }
                            let address = address(&mut lex)?;
                            if addresses.insert(address.address, address).is_some() {
                                return Err(lex.error("duplicate child address"));
                            }
                        }
                        _ => return Err(lex.error("unknown or duplicate IA_NA statement")),
                    }
                }
                lex.record_start = None;
                if records
                    .insert((duid, iaid), addresses.into_values().collect())
                    .is_some()
                {
                    counts.replaced_associations += 1;
                }
            }
            Token::Word(word) if word == "ia-ta" || word == "ia-pd" => {
                return Err(lex.error("unsupported association type: IA_TA/IA_PD"));
            }
            _ => return Err(lex.error("unknown top-level statement")),
        }
    }
    // A truncated/zero-byte transport must not masquerade as an empty database.
    if order.is_none() && !counts.server_duid_present {
        return Err(lex.error("expected ISC database header"));
    }
    counts.latest_associations = records.len();
    Ok((records, counts))
}

fn address(lex: &mut Lexer<'_>) -> Result<Address> {
    let address = lex
        .word()?
        .parse::<Ipv6Addr>()
        .map_err(|_| lex.error("invalid IPv6 address"))?;
    lex.punct(b'{')?;
    let mut active = None;
    let mut preferred = None;
    let mut max = None;
    let mut ends = None;
    let mut bindings = std::collections::BTreeSet::new();
    loop {
        match lex.required()? {
            Token::Punct(b'}') => break,
            Token::Word(word) if word == "binding" && active.is_none() => {
                lex.keyword("state")?;
                active = Some(match lex.word()?.as_str() {
                    "active" => true,
                    "abandoned" | "free" | "expired" | "released" => false,
                    _ => return Err(lex.error("unsupported binding state")),
                });
                lex.punct(b';')?;
            }
            Token::Word(word) if word == "preferred-life" && preferred.is_none() => {
                preferred = Some(lex.number()?);
                lex.punct(b';')?;
            }
            Token::Word(word) if word == "max-life" && max.is_none() => {
                max = Some(lex.number()?);
                lex.punct(b';')?;
            }
            Token::Word(word) if word == "ends" && ends.is_none() => ends = Some(lex.date(true)?),
            Token::Word(word) if word == "set" => {
                let name = lex.word()?;
                if name.is_empty()
                    || !name.as_bytes()[0].is_ascii_alphabetic()
                    || !name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                    || !bindings.insert(name)
                {
                    return Err(lex.error("invalid or duplicate binding name"));
                }
                lex.punct(b'=')?;
                match lex.required()? {
                    Token::Bytes(_) => {}
                    Token::Word(value) if value == "true" || value == "false" => {}
                    Token::Word(value) if value.starts_with('%') => {
                        let number = &value[1..];
                        let digits = number.strip_prefix('-').unwrap_or(number);
                        if digits.is_empty()
                            || !digits.bytes().all(|b| b.is_ascii_digit())
                            || number.parse::<i32>().is_err()
                        {
                            return Err(
                                lex.error("numeric binding must be a signed 32-bit constant")
                            );
                        }
                    }
                    _ => return Err(lex.error("unsupported binding expression; constants only")),
                }
                lex.punct(b';')?;
            }
            Token::Word(word) if word == "on" => return Err(lex.error("unsupported on handler")),
            _ => return Err(lex.error("unknown or duplicate iaaddr statement")),
        }
    }
    let active = active.ok_or_else(|| lex.error("missing binding state"))?;
    let preferred = preferred.ok_or_else(|| lex.error("missing preferred-life"))?;
    let max = max.ok_or_else(|| lex.error("missing max-life"))?;
    if preferred > max {
        return Err(lex.error("preferred-life exceeds max-life"));
    }
    let ends = ends.ok_or_else(|| lex.error("missing explicit ends"))?;
    Ok(Address {
        address,
        active,
        ends,
    })
}

#[cfg(test)]
mod tests;
