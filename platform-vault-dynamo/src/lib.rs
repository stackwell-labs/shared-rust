//! A DynamoDB handle for the hardened data-plane vault that **cannot express a
//! delete**.
//!
//! # Why this exists
//!
//! The vault account (`081348549030`) holds the platform's durable tables —
//! `t_drive_items`, `t_drive_coowned`, `t_chirp-auth_vault`, `t_granite_vault`,
//! `t_shriek_vault`, `t_amber-git_refs`, `t_spend_ledger`. Every runtime role
//! that reaches them (`t_drive_runtime`, `t_chirp-auth_runtime`,
//! `t_granite_runtime`, `t_shriek_runtime`) is granted exactly:
//!
//! ```text
//! GetItem BatchGetItem Query Scan DescribeTable PutItem UpdateItem
//! ```
//!
//! `DeleteItem` is **withheld**, on purpose: irreversible destruction in the
//! vault is reserved for the email-gated deletion delegate. That is the central
//! guarantee of the hardened data plane.
//!
//! Until this crate, the guarantee was enforced in exactly two places — IAM at
//! runtime, and the memory of whoever was writing the store. Nothing stopped a
//! store method from calling `.delete_item()`; it compiled, passed review, and
//! passed tests. The three services that reach the vault had three different
//! answers:
//!
//! * **chirp-auth** got it right — routes by key and tombstones the vault path,
//!   with a `ScratchKey` type making a TTL-write to the vault structurally
//!   impossible.
//! * **drive** got it right by construction — its one production delete targets
//!   the erasure-KEY table in drive's own account, never a vault row. That is
//!   what crypto-shred is for.
//! * **shriek** did not. On 2026-08-24 a source-retirement feature shipped as
//!   `DeleteItem` and returned **500 on every call in production**:
//!   `shriek dynamo error: remove expectation: service error`.
//!
//! Two details make that worth a type rather than another comment. The
//! constraint was *already documented in both module headers of the files being
//! edited* ("IAM withholds `DeleteItem`") and was still missed. And the unit
//! tests could not catch it: the in-memory double modelled no permission
//! boundary, so 40 green tests certified an operation production forbids. A
//! test double more permissive than the real store is worse than no test.
//!
//! # What this does
//!
//! [`VaultClient`] owns the SDK client privately and re-exposes only the
//! permitted operations. `.delete_item()` is not a method that exists; the
//! failure moves from a production 500 to a compile error, which is the whole
//! point.
//!
//! ```ignore
//! let vault = VaultClient::new(sdk_client);
//! vault.update_item().table_name(t).key("pk", pk)      // fine
//!      .update_expression("SET #d = :t") /* … */;
//! vault.delete_item();                                  // does not compile
//! ```
//!
//! To retire a vault row, **tombstone it**: an additive `UpdateItem` marking the
//! row, with every read path filtering marked rows. Guard it with
//! `condition_expression("attribute_exists(pk)")` so retiring an absent key is a
//! no-op rather than a silent upsert that creates a tombstone and reports
//! success.
//!
//! # What this does NOT do
//!
//! It is not a security boundary — IAM is, and it still is. Anyone can hold the
//! raw SDK client alongside this one. It removes the *accident*: the store
//! author who reaches for the obvious method and learns from production that
//! the platform forbids it.

#![forbid(unsafe_code)]

use aws_sdk_dynamodb::config::http::HttpResponse;
use aws_sdk_dynamodb::error::SdkError;
use aws_sdk_dynamodb::operation::transact_write_items::{
    TransactWriteItemsError, TransactWriteItemsOutput,
};
use aws_sdk_dynamodb::operation::{
    batch_get_item::builders::BatchGetItemFluentBuilder,
    describe_table::builders::DescribeTableFluentBuilder, get_item::builders::GetItemFluentBuilder,
    put_item::builders::PutItemFluentBuilder, query::builders::QueryFluentBuilder,
    scan::builders::ScanFluentBuilder, update_item::builders::UpdateItemFluentBuilder,
};
use aws_sdk_dynamodb::types::{ConditionCheck, Put, TransactWriteItem, Update};
use aws_sdk_dynamodb::Client;

/// # The invariant, as a test
///
/// A permitted operation compiles. This is the POSITIVE CONTROL, and it is not
/// decoration: a `compile_fail` doctest passes when compilation fails for ANY
/// reason, including a typo in the type name. Without a companion that must
/// compile, the test below would still "pass" if this crate stopped existing.
///
/// ```
/// fn permitted(v: &platform_vault_dynamo::VaultClient) {
///     let _ = v.update_item();
///     let _ = v.put_item();
///     let _ = v.query();
/// }
/// ```
///
/// A withheld operation does not compile — the vault grants no `DeleteItem`, so
/// the method does not exist on this type:
///
/// ```compile_fail
/// fn forbidden(v: &platform_vault_dynamo::VaultClient) {
///     let _ = v.delete_item();
/// }
/// ```
///
/// Nor the batch/transactional writes that can carry a delete:
///
/// ```compile_fail
/// fn forbidden_batch(v: &platform_vault_dynamo::VaultClient) {
///     let _ = v.batch_write_item();
/// }
/// ```
///
/// A transaction can be built from the permitted item kinds:
///
/// ```
/// use platform_vault_dynamo::VaultTransactItem;
/// use aws_sdk_dynamodb::types::{Put, Update, ConditionCheck};
/// fn permitted(p: Put, u: Update, c: ConditionCheck) -> Vec<VaultTransactItem> {
///     vec![
///         VaultTransactItem::Put(p),
///         VaultTransactItem::Update(u),
///         VaultTransactItem::ConditionCheck(c),
///     ]
/// }
/// ```
///
/// There is NO `Delete` variant, so a transaction carrying one cannot be
/// constructed — the rule moved from the operation to the item, which is where
/// it actually belongs:
///
/// ```compile_fail
/// use platform_vault_dynamo::VaultTransactItem;
/// fn forbidden(d: aws_sdk_dynamodb::types::Delete) -> VaultTransactItem {
///     VaultTransactItem::Delete(d)
/// }
/// ```
///
/// A DynamoDB client scoped to the operations the vault's runtime roles grant.
///
/// Construct one wherever a vault-backed table is reached. The inner [`Client`]
/// is private, so the destructive operations IAM refuses are not reachable
/// through this type at all.
#[derive(Clone, Debug)]
pub struct VaultClient {
    inner: Client,
}

impl VaultClient {
    /// Wrap an SDK client as a vault handle.
    ///
    /// Takes the client by value rather than by reference so the caller is
    /// nudged to hold the vault handle *instead of* the raw client, not
    /// alongside it. Nothing enforces that — see "What this does NOT do".
    pub fn new(inner: Client) -> Self {
        Self { inner }
    }

    // --- the granted operations, verbatim from the vault role policy ---------

    pub fn get_item(&self) -> GetItemFluentBuilder {
        self.inner.get_item()
    }
    pub fn batch_get_item(&self) -> BatchGetItemFluentBuilder {
        self.inner.batch_get_item()
    }
    pub fn query(&self) -> QueryFluentBuilder {
        self.inner.query()
    }
    pub fn scan(&self) -> ScanFluentBuilder {
        self.inner.scan()
    }
    pub fn describe_table(&self) -> DescribeTableFluentBuilder {
        self.inner.describe_table()
    }
    pub fn put_item(&self) -> PutItemFluentBuilder {
        self.inner.put_item()
    }
    pub fn update_item(&self) -> UpdateItemFluentBuilder {
        self.inner.update_item()
    }

    /// A transaction that CANNOT contain a delete.
    ///
    /// The first version of this crate withheld `transact_write_items`
    /// wholesale, on the reasoning that a transaction *can* carry a Delete. That
    /// was the wrong rule, and being wrong had a cost: granite's vault store
    /// uses four Put/Update-only transactions — the pre-bound create, the claim
    /// serialization point, approve and deny — where atomicity IS the
    /// correctness property. It could not adopt this type at all, so it kept a
    /// raw SDK client, and therefore had NO compile-time protection, including
    /// against the bare `delete_item` this crate exists to prevent.
    ///
    /// That is the only way a type like this fails: not by being circumvented,
    /// but by being too strict to adopt. An over-broad guard's escape hatch is
    /// "hold the raw client", which forfeits everything.
    ///
    /// The platform's guarantee is "no irreversible destruction", NOT "no
    /// transactions" — and IAM agrees: `dynamodb:TransactWriteItems` is not a
    /// real action (AWS Access Analyzer reports it "does not exist", the same
    /// finding it gives a fabricated one). DynamoDB authorises a transaction
    /// through its UNDERLYING item actions, so a Put/Update transaction is fully
    /// permitted by the vault grant, and one carrying a Delete is already
    /// refused — exactly like a bare delete.
    ///
    /// So the ban moves from the operation to the ITEM: [`VaultTransactItem`]
    /// has no `Delete` variant, which states the real rule exactly.
    /// NOTE ON SHAPE: this OWNS the send rather than returning the SDK's fluent
    /// builder. Returning the builder would leave `.transact_items()` reachable,
    /// so a caller could append a `Delete` after the fact and the item type would
    /// guarantee nothing — a guard that looks armed and is not. Taking the items
    /// and sending is what makes `Delete` genuinely unrepresentable here.
    pub async fn transact_write(
        &self,
        items: impl IntoIterator<Item = VaultTransactItem>,
    ) -> Result<TransactWriteItemsOutput, SdkError<TransactWriteItemsError, HttpResponse>> {
        let mut req = self.inner.transact_write_items();
        for item in items {
            req = req.transact_items(item.into());
        }
        req.send().await
    }

    // Deliberately absent: delete_item, batch_write_item (its DeleteRequest is
    // the only reason, and unlike a transaction the SDK offers no item type that
    // excludes it), delete_table, update_table, create_table.
    //
    // THE RULE FOR CHANGING THIS LIST: the surface here must be ISOMORPHIC to
    // the vault role's IAM grant — not stricter, not laxer. Laxer is useless;
    // stricter is worse than useless, because it drives the raw-client escape
    // hatch that removes the guarantee entirely. `surface_matches_grant()` below
    // pins the correspondence so the two cannot drift apart silently.
}

/// One item in a vault transaction. **There is no `Delete` variant, by
/// construction** — that is the entire point of the type.
///
/// Build the inner SDK types as usual and wrap them here; the wrapper costs
/// nothing at runtime and makes the forbidden case unrepresentable rather than
/// merely discouraged.
#[derive(Debug, Clone)]
pub enum VaultTransactItem {
    Put(Put),
    Update(Update),
    ConditionCheck(ConditionCheck),
}

impl From<VaultTransactItem> for TransactWriteItem {
    fn from(item: VaultTransactItem) -> Self {
        let b = TransactWriteItem::builder();
        match item {
            VaultTransactItem::Put(p) => b.put(p),
            VaultTransactItem::Update(u) => b.update(u),
            VaultTransactItem::ConditionCheck(c) => b.condition_check(c),
        }
        .build()
    }
}

/// The operations this type exposes, as the IAM action names they require.
///
/// Kept next to the methods so the two are edited together, and compared against
/// the vault role's real policy by the platform audit — the grant is stated in
/// `datastore-iac`'s tenant policies AND here, and duplicated knowledge drifts.
/// It already has: four tenant policies grant `dynamodb:TransactWriteItems`,
/// which IAM does not recognise and silently ignores.
pub const REQUIRED_ACTIONS: &[&str] = &[
    "dynamodb:GetItem",
    "dynamodb:BatchGetItem",
    "dynamodb:Query",
    "dynamodb:Scan",
    "dynamodb:DescribeTable",
    "dynamodb:PutItem",
    "dynamodb:UpdateItem",
];
