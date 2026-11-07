//! Shared DynamoDB-vs-in-memory store selector.
//!
//! pigeon, granite, and bowerbird each carry a structurally identical
//! `build_store()`: read a table-name env var; if it is set, load the default
//! AWS config, construct a DynamoDB client, and build the DynamoDB-backed
//! store; otherwise build the in-memory store. Each then tags the result with a
//! `&'static str` store-kind label for `/_service-info`.
//!
//! [`select_dynamo_or_memory`] encapsulates that whole dance — the
//! `aws_config::load_defaults` call, the `aws_sdk_dynamodb::Client::new`
//! construction, and the env-var branch — while staying generic over the store
//! type. The caller supplies only the two constructors:
//!
//! ```no_run
//! # struct DynamoStore;
//! # struct MemStore;
//! # enum Store { Dynamo(DynamoStore), Mem(MemStore) }
//! # impl DynamoStore { fn new(_c: aws_sdk_dynamodb::Client, _t: String) -> Store { Store::Dynamo(DynamoStore) } }
//! # impl MemStore { fn new() -> Store { Store::Mem(MemStore) } }
//! # async fn build_store() -> (Store, &'static str) {
//! platform_lambda::store::select_dynamo_or_memory(
//!     "PIGEON_CONTACTS_TABLE",
//!     |client, table| DynamoStore::new(client, table),
//!     || MemStore::new(),
//! )
//! .await
//! # }
//! ```
//!
//! The closures return the *same* type `S` (typically the service's shared
//! store alias, e.g. `SharedPigeonStore`), so this matches the existing
//! `(SharedStore, &'static str)` return shape exactly.
//!
//! Services with a more elaborate selector (drive nests a second S3 branch
//! inside the DynamoDB arm) are intentionally out of scope for this helper —
//! it captures the common two-way branch, not every variant.

/// Select a DynamoDB-backed store when `table_env` is set, else an in-memory
/// store, returning the store alongside a `&'static str` kind label
/// (`"dynamodb"` / `"memory"`) suitable for `/_service-info`.
///
/// When `table_env` is present, this loads the default AWS config
/// ([`aws_config::load_defaults`] at the latest [`aws_config::BehaviorVersion`])
/// and constructs an [`aws_sdk_dynamodb::Client`], handing both the client and
/// the resolved table name to `from_dynamo`. When it is absent, `from_memory`
/// is called with no arguments.
///
/// Both constructors must produce the same store type `S` (e.g. a service's
/// `SharedStore` alias). The branch is taken on env-var *presence*, matching
/// the `match std::env::var(...) { Ok(table) => .., Err(_) => .. }` shape the
/// services hand-wrote.
pub async fn select_dynamo_or_memory<S, FDyn, FMem>(
    table_env: &str,
    from_dynamo: FDyn,
    from_memory: FMem,
) -> (S, &'static str)
where
    FDyn: FnOnce(aws_sdk_dynamodb::Client, String) -> S,
    FMem: FnOnce() -> S,
{
    match std::env::var(table_env) {
        Ok(table_name) => {
            let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
            let client = aws_sdk_dynamodb::Client::new(&config);
            (from_dynamo(client, table_name), "dynamodb")
        }
        Err(_) => (from_memory(), "memory"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::Mutex;

    // Guards process-global env-var mutation so the two tests below can't race
    // each other on the same key (cargo runs tests in parallel by default).
    // An async lock: it's held across `select_dynamo_or_memory(..).await`,
    // whose config load reads the environment.
    static ENV_LOCK: Mutex<()> = Mutex::const_new(());

    #[derive(Debug, PartialEq, Eq)]
    enum FakeStore {
        Dynamo { table: String },
        Memory,
    }

    #[tokio::test]
    async fn selects_memory_when_env_unset() {
        let _guard = ENV_LOCK.lock().await;
        let key = "PLATFORM_LAMBDA_TEST_SELECT_TABLE_UNSET";
        // SAFETY: serialized by ENV_LOCK; no other thread reads/writes this key.
        unsafe { std::env::remove_var(key) };

        let (store, kind) = select_dynamo_or_memory(
            key,
            |_client, table| FakeStore::Dynamo { table },
            || FakeStore::Memory,
        )
        .await;

        assert_eq!(kind, "memory");
        assert_eq!(store, FakeStore::Memory);
    }

    // The Dynamo arm builds a real `aws_sdk_dynamodb::Client`, which only
    // requires loading the default config (no network call at construction
    // time), so this is safe to exercise in a unit test. We assert the branch
    // is taken and the resolved table name is threaded through to the
    // constructor.
    #[tokio::test]
    async fn selects_dynamo_and_threads_table_name_when_env_set() {
        let _guard = ENV_LOCK.lock().await;
        let key = "PLATFORM_LAMBDA_TEST_SELECT_TABLE_SET";
        // SAFETY: serialized by ENV_LOCK; no other thread reads/writes this key.
        unsafe { std::env::set_var(key, "my-table") };

        let (store, kind) = select_dynamo_or_memory(
            key,
            |_client, table| FakeStore::Dynamo { table },
            || FakeStore::Memory,
        )
        .await;

        // SAFETY: serialized by ENV_LOCK.
        unsafe { std::env::remove_var(key) };

        assert_eq!(kind, "dynamodb");
        assert_eq!(
            store,
            FakeStore::Dynamo {
                table: "my-table".to_owned()
            }
        );
    }
}
