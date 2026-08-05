// SPDX-License-Identifier: AGPL-3.0-or-later
//! `runs` — module de test EXTRAIT (PURE MOVE depuis `console/src/runs.rs`).
//! Corps IDENTIQUE ; ENFANT de `runs`, il voit donc toujours ses items privés.
//! Renommé `network_policy_ip_tests` -> `tests_net_policy` : `tests/test_portability_guard.py` n'exclut
//! que les fichiers `tests.rs` / `tests_*` et scannerait l'autre nom (garde au ROUGE).
use super::*;

    use super::{ip_is_private, target_is_private_literal};
    use std::net::IpAddr;

    fn priv_ip(s: &str) -> bool {
        ip_is_private(s.parse::<IpAddr>().expect("ip"))
    }

    #[test]
    fn private_v4_literals_are_flagged() {
        for ip in ["127.0.0.1", "127.5.5.5", "10.0.0.5", "10.255.255.255",
                   "172.16.0.9", "172.31.255.1", "192.168.1.1", "169.254.1.1",
                   "0.0.0.0", "0.1.2.3", "100.64.0.1", "100.127.255.255"] {
            assert!(priv_ip(ip), "{ip} devait être classé privé");
        }
    }

    #[test]
    fn public_v4_literals_are_not_flagged() {
        // dont les plages DOCUMENTATION RFC5737 (utilisées comme « faux public » dans les tests) : NON bloquées.
        for ip in ["93.184.216.34", "8.8.8.8", "1.1.1.1", "203.0.113.10",
                   "198.51.100.5", "192.0.2.5", "172.15.0.1", "172.32.0.1", "100.63.255.255", "100.128.0.0"] {
            assert!(!priv_ip(ip), "{ip} devait être classé public");
        }
    }

    #[test]
    fn private_v6_literals_are_flagged() {
        for ip in ["::1", "::", "fc00::1", "fd12:3456::1", "fe80::1",
                   "::ffff:127.0.0.1", "::ffff:10.0.0.5", "::ffff:192.168.1.1"] {
            assert!(priv_ip(ip), "{ip} devait être classé privé");
        }
    }

    #[test]
    fn public_v6_literals_are_not_flagged() {
        for ip in ["2001:4860:4860::8888", "::ffff:93.184.216.34", "2606:4700:4700::1111"] {
            assert!(!priv_ip(ip), "{ip} devait être classé public");
        }
    }

    #[test]
    fn cidr_base_decides_literal_verdict() {
        assert!(target_is_private_literal("10.0.0.0/24"), "CIDR de base privée -> bloqué");
        assert!(target_is_private_literal("192.168.0.0/16"), "CIDR RFC1918 -> bloqué");
        assert!(target_is_private_literal("fc00::/7"), "CIDR ULA -> bloqué");
        assert!(!target_is_private_literal("93.184.216.0/24"), "CIDR public -> non bloqué");
    }

    #[test]
    fn hostnames_are_not_literal_private() {
        // un hostname (même s'il résout en privé) n'est PAS tranché ici : c'est le moteur Python (roe.py)
        // qui l'attrape autoritativement via getaddrinfo. La couche Rust ne juge QUE le littéral.
        for h in ["example.com", "localhost", "internal.corp", "rebind.attacker.test"] {
            assert!(!target_is_private_literal(h), "{h} n'est pas un littéral -> non bloqué côté Rust");
        }
    }
