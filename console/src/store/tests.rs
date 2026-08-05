// SPDX-License-Identifier: AGPL-3.0-or-later
//! `store` — module de test EXTRAIT (PURE MOVE depuis `console/src/store.rs`).
//! Corps IDENTIQUE ; ENFANT de `store`, il voit donc toujours ses items privés.
use super::*;

    use super::*;

    /// One row with a column PER storage class (INTEGER, REAL, TEXT, BLOB) plus a NULL cell. Each cell
    /// is read via `get_value`, asserting the neutral `Value` variant matches — the value-driven
    /// dispatch that the type-strict getters cannot perform. Also shows the one-line `Value ->
    /// serde_json::Value` mapping is byte-identical to `query.rs::cell`'s current output.
    #[test]
    fn get_value_dispatches_on_runtime_storage_class() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE mixed (i INTEGER, r REAL, s TEXT, b BLOB, n TEXT);
             INSERT INTO mixed (i, r, s, b, n) VALUES (42, 3.5, 'hello', x'0102', NULL);",
        )
        .unwrap();

        let mut stmt = conn.prepare("SELECT i, r, s, b, n FROM mixed").unwrap();
        let mut rows = stmt.query([]).unwrap();
        let raw = rows.next().unwrap().unwrap();
        let row = Row::sqlite(raw);

        // Value-driven dispatch: one accessor reads a cell of UNKNOWN compile-time type and returns
        // the variant matching its ACTUAL storage class.
        assert_eq!(row.get_value(0).unwrap(), Value::Int(42));
        assert_eq!(row.get_value(1).unwrap(), Value::Real(3.5));
        assert_eq!(row.get_value(2).unwrap(), Value::Text("hello".to_string()));
        assert_eq!(row.get_value(3).unwrap(), Value::Blob(vec![1, 2]));
        assert_eq!(row.get_value(4).unwrap(), Value::Null);

        // By-name variant reads identically.
        assert_eq!(row.get_value_by("i").unwrap(), Value::Int(42));
        assert_eq!(row.get_value_by("n").unwrap(), Value::Null);

        // The typed getter CANNOT do this: `get_i64` on the TEXT column errors (rusqlite's type-strict
        // `FromSql for i64` rejects a Text cell) — which is exactly why the SoQL reader needs the
        // dynamic `get_value`.
        assert!(row.get_i64(2).is_err());

        // One-line `Value -> serde_json::Value` mapping, IDENTICAL to `query.rs::cell`'s output:
        // Int -> number, Real -> number, Text -> string, Blob -> Null, Null -> Null.
        let to_json = |v: &Value| -> serde_json::Value {
            match v {
                Value::Int(n) => serde_json::json!(n),
                Value::Real(f) => serde_json::json!(f),
                Value::Text(s) => serde_json::json!(s),
                Value::Blob(_) => serde_json::Value::Null,
                Value::Null => serde_json::Value::Null,
            }
        };
        assert_eq!(to_json(&row.get_value(0).unwrap()), serde_json::json!(42));
        assert_eq!(to_json(&row.get_value(1).unwrap()), serde_json::json!(3.5));
        assert_eq!(to_json(&row.get_value(2).unwrap()), serde_json::json!("hello"));
        assert_eq!(to_json(&row.get_value(3).unwrap()), serde_json::Value::Null);
        assert_eq!(to_json(&row.get_value(4).unwrap()), serde_json::Value::Null);
    }
