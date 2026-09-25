use super::*;

const HEADER: &str = "authoring-byte-order little-endian;";

fn lease() -> String {
    format!(
        "{HEADER} ia-na 01:00:00:00:aa:bb {{ cltt epoch 1; iaaddr fd7a:115c:a1e0:17::1000 {{ binding state active; preferred-life 10; max-life 20; ends never; }} }}"
    )
}

fn lex(bytes: &[u8]) -> Lexer<'_> {
    Lexer {
        bytes,
        pos: 0,
        tokens: 0,
        limits: Limits::default(),
        record_start: None,
    }
}

#[test]
fn every_octal_octet_and_literal_delimiter_survives_without_utf8_loss() {
    let mut input = String::from("\"");
    for b in 0_u16..=255 {
        input.push_str(&format!("\\{b:03o}"));
    }
    input.push('"');
    assert_eq!(
        lex(input.as_bytes()).required().unwrap(),
        Token::Bytes((0..=255).collect())
    );
    assert_eq!(
        lex(br##""#;{}=\"\\~ " # ignored"##).required().unwrap(),
        Token::Bytes(b"#;{}=\"\\~ ".to_vec())
    );
    assert_eq!(
        lex(br#""\000\177\200\377""#).required().unwrap(),
        Token::Bytes(vec![0, 127, 128, 255])
    );
}

#[test]
fn invalid_quoted_escapes_raw_high_bytes_and_truncation_are_errors() {
    for input in [
        br#""\0""#.as_slice(),
        br#""\00""#,
        br#""\400""#,
        br#""\378""#,
        br#""\777""#,
        br#""\x00""#,
        br#""\n""#,
        br#""unfinished"#,
        b"\"raw\n\"",
        b"\"raw\0\"",
        b"\"raw\x80\"",
        b"\"\\",
    ] {
        assert!(lex(input).required().is_err(), "{input:?}");
    }
}

#[test]
fn quoted_and_hex_reader_length_boundaries_never_truncate() {
    for (server, min, max_q, max_hex) in [(true, 3, 127, 128), (false, 6, 131, 132)] {
        for len in [min - 1, min, max_q, max_hex, max_hex + 1] {
            let q = format!("\"{}\"", "a".repeat(len));
            let h = std::iter::repeat_n("61", len).collect::<Vec<_>>().join(":");
            assert_eq!(
                lex(q.as_bytes()).identifier(server).is_ok(),
                (min..=max_q).contains(&len)
            );
            assert_eq!(
                lex(h.as_bytes()).identifier(server).is_ok(),
                (min..=max_hex).contains(&len)
            );
        }
    }
    for bad in [
        "00010000aabb",
        "0:01:00:00:aa:bb",
        "01:00:00:00:aa:zz",
        "01::00:00:aa:bb",
        "01:00:00:00:aa:bb:",
    ] {
        assert!(lex(bad.as_bytes()).identifier(false).is_err());
    }
}

#[test]
fn headers_are_known_consistent_and_before_associations() {
    for bad in [
        String::new(),
        "# comments only".into(),
        "authoring-byte-order middle-endian;".into(),
        format!("{HEADER}{HEADER}"),
        format!("{HEADER}authoring-byte-order big-endian;"),
        "server-duid 00:01:aa; server-duid 00:01:bb;".into(),
        lease().replace(HEADER, ""),
        format!("{} {HEADER}", lease()),
        format!("{} server-duid 00:01:aa;", lease()),
        format!("{HEADER} unknown value;"),
    ] {
        assert!(parse(bad.as_bytes()).is_err(), "{bad}");
    }
    assert!(parse(b"server-duid 00:01:aa;").is_ok());
    assert!(parse(HEADER.as_bytes()).is_ok());
}

#[test]
fn identical_server_duid_replay_compares_decoded_bytes() {
    for repeated in [
        "server-duid 00:01:aa; server-duid 00:01:aa;",
        r#"server-duid 00:01:aa; server-duid "\000\001\252";"#,
        r#"server-duid "\000\001\252"; server-duid 00:01:AA;"#,
    ] {
        for text in [
            repeated.to_owned(),
            format!("{HEADER} {repeated}"),
            format!("{repeated} {}", lease()),
        ] {
            let (_, counts) = parse(text.as_bytes()).unwrap();
            assert!(counts.server_duid_present);
        }
    }
    for bad in [
        r#"server-duid "\000\001\252"; server-duid 00:01:ab;"#.to_owned(),
        "server-duid 00:01:aa; server-duid 00:01:aa".into(),
        format!("server-duid 00:01:aa; {} server-duid 00:01:aa;", lease()),
    ] {
        assert!(parse(bad.as_bytes()).is_err(), "{bad}");
    }
}

#[test]
fn missing_duplicate_unknown_scalars_and_unbalanced_blocks_are_rejected() {
    let good = lease();
    for field in [
        "binding state active;",
        "preferred-life 10;",
        "max-life 20;",
        "ends never;",
    ] {
        assert!(
            parse(good.replace(field, "").as_bytes()).is_err(),
            "{field}"
        );
        assert!(parse(good.replace(field, &format!("{field} {field}")).as_bytes()).is_err());
    }
    for bad in [
        good.replace("cltt epoch 1;", "cltt epoch 1; cltt epoch 2;"),
        good.replace("max-life 20;", "max-life 20"),
        good.replace("max-life 20;", "max-life 20; other 4;"),
        good.replace("iaaddr ", "iaaddr { "),
        good.replace("::1000", "::xyz"),
        good.replace("::1000", "::1000%eth0"),
        good.replace("::1000", "::1000/64"),
        good.replace("state active", "state unknown"),
        format!("{good} }}"),
        good[..good.len() - 1].into(),
    ] {
        assert!(parse(bad.as_bytes()).is_err(), "{bad}");
    }
}

#[test]
fn finite_calendar_epoch_never_and_expiration_boundaries() {
    for (date, epoch) in [
        ("4 1970/01/01 00:00:00;", 0),
        ("2 2000/02/29 00:00:00;", 951_782_400),
        ("4 2037/12/31 23:59:59;", 2_145_916_799),
        (
            "epoch 2147483646; # human local time is just a comment",
            2_147_483_646,
        ),
    ] {
        let end = lex(date.as_bytes()).date(true).unwrap();
        assert!(matches!(end, End::Finite(value) if value == epoch));
        assert!(!end.live_at(epoch));
        if epoch > 0 {
            assert!(end.live_at(epoch - 1));
        }
    }
    assert!(lex(b"never;").date(true).unwrap().live_at(u64::MAX));
    assert!(lex(b"never;").date(false).is_err());
    for bad in [
        "epoch 2147483647;",
        "epoch 4294967296;",
        "epoch -1;",
        "epoch +1;",
        "epoch 1 0;",
        "4 1970/01/01 00:00:00 +0000;",
        "5 2038/01/01 00:00:00;",
        "3 1969/12/31 23:59:59;",
        "3 2001/02/29 00:00:00;",
        "2 2000/02/30 00:00:00;",
        "2 2000/00/29 00:00:00;",
        "2 2000/13/29 00:00:00;",
        "2 2000/02/00 00:00:00;",
        "2 2000/02/29 24:00:00;",
        "2 2000/02/29 00:60:00;",
        "2 2000/02/29 00:00:60;",
        "7 2000/02/29 00:00:00;",
        "1 2000/02/29 00:00:00;",
        "2 2000/2/29 00:00:00;",
        "02 2000/02/29 00:00:00;",
    ] {
        assert!(lex(bad.as_bytes()).date(true).is_err(), "{bad}");
    }
}

#[test]
fn unsigned_lifetimes_are_bounded_and_ordered_including_infinity() {
    for (preferred, max, valid) in [
        ("0", "0", true),
        ("4294967295", "4294967295", true),
        ("20", "10", false),
        ("4294967295", "20", false),
        ("4294967296", "4294967296", false),
        ("-1", "20", false),
        ("+1", "20", false),
    ] {
        let text = lease()
            .replace("preferred-life 10", &format!("preferred-life {preferred}"))
            .replace("max-life 20", &format!("max-life {max}"));
        assert_eq!(parse(text.as_bytes()).is_ok(), valid, "{text}");
    }
}

#[test]
fn inert_bindings_are_checked_but_expressions_handlers_and_pd_ta_are_unsupported() {
    for value in [
        r#""\000\377#{};\"\\text""#,
        "%0",
        "%-2147483648",
        "%2147483647",
        "true",
        "false",
    ] {
        let text = lease().replace(
            "ends never;",
            &format!("ends never; set ddns-name = {value};"),
        );
        assert!(parse(text.as_bytes()).is_ok(), "{text}");
    }
    for statement in [
        "set x = concat(\"a\", \"b\");",
        "set x = execute(\"cmd\");",
        "set x = 10;",
        "set x = %2147483648;",
        "set x = %-2147483649;",
        "set x = %+1;",
        "set x = true; set x = false;",
        "set 1bad = true;",
        "on expiry { execute(\"cmd\"); }",
        "on release {}",
        "set x = null;",
    ] {
        assert!(
            parse(
                lease()
                    .replace("ends never;", &format!("ends never; {statement}"))
                    .as_bytes()
            )
            .is_err(),
            "{statement}"
        );
    }
    for kind in ["ia-ta", "ia-pd"] {
        assert!(
            parse(lease().replace("ia-na", kind).as_bytes())
                .unwrap_err()
                .to_string()
                .contains("unsupported association")
        );
    }
}

#[test]
fn precise_token_record_and_total_count_limits_include_replaced_records() {
    let base = lease();
    let default = Limits::default();
    let mut lexer = lex(base.as_bytes());
    while lexer.next().unwrap().is_some() {}
    for (tokens, valid) in [(lexer.tokens, true), (lexer.tokens - 1, false)] {
        assert_eq!(
            parse_with_limits(base.as_bytes(), Limits { tokens, ..default }).is_ok(),
            valid
        );
    }
    for limits in [
        Limits {
            tokens: 5,
            ..default
        },
        Limits {
            token_bytes: 4,
            ..default
        },
        Limits {
            record_bytes: 20,
            ..default
        },
        Limits {
            associations: 0,
            ..default
        },
        Limits {
            addresses: 0,
            ..default
        },
    ] {
        assert!(
            parse_with_limits(base.as_bytes(), limits)
                .unwrap_err()
                .to_string()
                .contains("limit")
        );
    }
    let record = &base[HEADER.len()..];
    assert!(
        parse_with_limits(
            format!("{base}{record}").as_bytes(),
            Limits {
                associations: 1,
                ..default
            }
        )
        .is_err()
    );
    assert!(
        parse_with_limits(
            format!("{base}{record}").as_bytes(),
            Limits {
                addresses: 1,
                ..default
            }
        )
        .is_err()
    );
    assert!(
        parse_with_limits(
            base.as_bytes(),
            Limits {
                associations: 1,
                addresses: 1,
                ..default
            }
        )
        .is_ok()
    );
    let record_len = record.trim_start().len();
    assert!(
        parse_with_limits(
            base.as_bytes(),
            Limits {
                record_bytes: record_len,
                ..default
            }
        )
        .is_ok()
    );
    assert!(
        parse_with_limits(
            base.as_bytes(),
            Limits {
                record_bytes: record_len - 1,
                ..default
            }
        )
        .is_err()
    );
    let token = format!("\"{}\"", "a".repeat(MAX_TOKEN_BYTES - 2));
    assert!(lex(token.as_bytes()).required().is_ok());
    assert!(lex(format!("{token}a").as_bytes()).required().is_ok());
    let too_big = format!("\"{}\"", "a".repeat(MAX_TOKEN_BYTES - 1));
    assert!(lex(too_big.as_bytes()).required().is_err());
    let comment = format!(
        "{HEADER} ia-na 01:00:00:00:aa:bb {{ #{}\n}}",
        "x".repeat(100)
    );
    assert!(
        parse_with_limits(
            comment.as_bytes(),
            Limits {
                record_bytes: 80,
                ..default
            }
        )
        .is_err()
    );
}

#[test]
fn every_truncated_association_prefix_fails_without_partial_results() {
    let good = lease();
    let start = good.find("ia-na").unwrap();
    for end in start + 1..good.len() {
        assert!(parse(&good.as_bytes()[..end]).is_err(), "prefix {end}");
    }
}
