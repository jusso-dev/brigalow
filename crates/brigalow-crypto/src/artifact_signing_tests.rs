use super::*;

#[test]
fn endpoint_is_https_azure_region_or_loopback_only() {
    for good in [
        "https://eus.codesigning.azure.net",
        "https://eus.codesigning.azure.net/",
        "https://weu.codesigning.azure.net",
        "https://australiaeast.codesigning.azure.net",
    ] {
        let (origin, loopback) = endpoint(good).unwrap();
        assert!(!loopback);
        assert!(!origin.ends_with('/'));
    }
    assert!(endpoint("https://127.0.0.1:8443").unwrap().1);
    assert!(endpoint("https://[::1]:8443").unwrap().1);
    for bad in [
        "http://eus.codesigning.azure.net",
        "https://codesigning.azure.net",
        "https://eus.codesigning.azure.net.attacker.test",
        "https://eus.codesigning.azure.net:8443",
        "https://EUS.codesigning.azure.net.evil",
        "https://e-us.codesigning.azure.net",
        "https://a.b.codesigning.azure.net",
        "https://eus.codesigning.azure.net/path",
        "https://eus.codesigning.azure.net/?q=1",
        "https://eus.codesigning.azure.net/#f",
        "https://user@eus.codesigning.azure.net",
        "https://localhost:8443",
        "https://10.0.0.1",
        "https://169.254.169.254",
        "http://127.0.0.1:8443",
        "eus.codesigning.azure.net",
        "",
    ] {
        assert!(endpoint(bad).is_err(), "{bad}");
    }
}

#[test]
fn resource_names_follow_arm_patterns() {
    assert!(resource_name("brigalow", 3, 24));
    assert!(resource_name("my-account-1", 3, 24));
    for bad in [
        "ab", "1abc", "-abc", "abc-", "a--b", "a/b", "a.b", "a_b", "a?b", "a%2fb",
    ] {
        assert!(!resource_name(bad, 3, 24), "{bad}");
    }
    assert!(!resource_name(&"a".repeat(25), 3, 24));
}

#[test]
fn imds_address_is_fixed_link_local_plain_http() {
    // The only permitted plain-HTTP call. Changing it needs a threat-model review.
    let url = reqwest::Url::parse(IMDS_TOKEN_URL).unwrap();
    assert_eq!(url.scheme(), "http");
    assert_eq!(url.host_str(), Some("169.254.169.254"));
    assert_eq!(url.port(), None);
    let imds = Imds::azure(None).unwrap();
    assert_eq!(imds.url.host_str(), Some("169.254.169.254"));
    assert!(imds
        .url
        .query_pairs()
        .any(|(k, v)| k == "resource" && v == TOKEN_RESOURCE));
    // The test seam accepts only loopback plain HTTP.
    for bad in [
        "https://127.0.0.1:1",
        "http://169.254.169.254",
        "http://10.0.0.1:80",
        "http://example.test",
    ] {
        assert!(Imds::test(bad, None).is_err(), "{bad}");
    }
}

#[test]
fn bundle_parser_rejects_malformed_input() {
    for bad in [
        "",
        "!!!",
        &STANDARD.encode("not a bundle"),
        &STANDARD.encode("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"),
        &STANDARD.encode("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"),
        &STANDARD.encode(STANDARD.encode([0x30u8, 0x03, 0x02, 0x01, 0x01])),
        &STANDARD.encode([0xffu8, 0xfe]),
    ] {
        assert!(parse_bundle(bad).is_err());
    }
}

#[test]
fn production_constructor_refuses_loopback_and_test_roots() {
    let settings = |endpoint: &str, tls: Option<Vec<u8>>, lab: bool| Settings {
        endpoint: endpoint.into(),
        tls_ca_pem: tls,
        lab,
        managed_identity_client_id: None,
        operation_timeout: Duration::from_secs(5),
        bindings: vec![],
    };
    // Loopback is lab-only and requires its own explicit TLS root.
    assert!(ArtifactSigning::new(settings("https://127.0.0.1:1", None, false)).is_err());
    assert!(ArtifactSigning::new(settings("https://127.0.0.1:1", None, true)).is_err());
    // An Azure endpoint never accepts an extra TLS root.
    assert!(ArtifactSigning::new(settings(
        "https://eus.codesigning.azure.net",
        Some(b"x".to_vec()),
        false
    ))
    .is_err());
    let backend =
        ArtifactSigning::new(settings("https://eus.codesigning.azure.net", None, false)).unwrap();
    assert!(!backend.is_lab());
    assert!(backend.rotates());
    let mut long = settings("https://eus.codesigning.azure.net", None, false);
    long.operation_timeout = Duration::from_secs(26);
    assert!(ArtifactSigning::new(long).is_err());
    let mut zero = settings("https://eus.codesigning.azure.net", None, false);
    zero.operation_timeout = Duration::ZERO;
    assert!(ArtifactSigning::new(zero).is_err());
}

#[test]
fn pinned_key_operations_are_absent() {
    let backend = ArtifactSigning::new(Settings {
        endpoint: "https://eus.codesigning.azure.net".into(),
        tls_ca_pem: None,
        lab: false,
        managed_identity_client_id: None,
        operation_timeout: Duration::from_secs(5),
        bindings: vec![],
    })
    .unwrap();
    let key = Key {
        id: Uuid::new_v4(),
        algorithm: Algorithm::Rsa3072,
        purpose: Purpose::Test,
    };
    assert!(backend.public_key(&key).is_err());
    assert!(backend
        .sign_digest(&key, DigestAlgorithm::Sha256, &[0; 32])
        .is_err());
    assert!(backend.sign_message(&key, b"m").is_err());
    assert!(backend.generate(Algorithm::Rsa3072, Purpose::Test).is_err());
    assert!(backend
        .remote_key(key.id, Uuid::new_v4(), Uuid::new_v4())
        .is_err());
    let attempt = backend.sign_rotating(&key, &[0; 32], &|_| Ok(()));
    assert!(attempt.operation_id.is_none() && attempt.outcome.is_err());
}

#[test]
fn operation_ids_are_bounded_tokens() {
    assert!(operation_id(&json!("0f1e2d3c-aaaa-bbbb-cccc-0123456789ab")).is_some());
    for bad in [
        json!(""),
        json!("../x"),
        json!("a?b"),
        json!("a b"),
        json!(1),
        json!(null),
        json!("x".repeat(129)),
    ] {
        assert!(operation_id(&bad).is_none());
    }
}
