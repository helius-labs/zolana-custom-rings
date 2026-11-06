use anyhow::Result;
use custom_ring_interface::{tracking::TrackingAuthorization, REGISTER_KEY_CIPHERTEXT_LEN};
use sea_orm::{ConnectionTrait, QueryResult};
use solana_address::Address;

use super::{bytes, field, int, uint, TrackingStore};

/// The owner's authorization with no viewing key, final after its first `Enroll` except for the apply mark.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Enrollment {
    pub owner: [u8; 32],
    pub authorization: [u8; 32],
    pub member: [u8; 32],
    pub nullifier_pk: [u8; 32],
    pub ct_hash: [u8; 32],
    pub list_tag: [u8; 32],
    pub eph_u: [u8; 32],
    pub ciphertext: [u8; REGISTER_KEY_CIPHERTEXT_LEN],
    pub applied: bool,
}

impl Enrollment {
    /// The image the program's final field and apply checks run on, neither reads its zero viewing key.
    pub fn account(&self, registry: [u8; 32]) -> TrackingAuthorization {
        TrackingAuthorization {
            discriminator: TrackingAuthorization::DISCRIMINATOR,
            registry: Address::new_from_array(registry),
            owner: Address::new_from_array(self.owner),
            nullifier_pk: self.nullifier_pk,
            list_tag: self.list_tag,
            viewing_u: [0; 32],
            eph_u: self.eph_u,
            ciphertext: self.ciphertext,
            applied: u8::from(self.applied),
        }
    }
}

const ENROLLMENT_READ: &str = "SELECT owner, authorization_account, member, nullifier_pk, \
     ct_hash, list_tag, eph_u, ciphertext, \
     CAST(CASE WHEN applied_slot IS NULL THEN 0 ELSE 1 END AS BIGINT) AS applied \
     FROM tracking_authorizations";

impl<C: ConnectionTrait> TrackingStore<'_, C> {
    pub async fn enrollment(&self, owner: &[u8; 32]) -> Result<Option<Enrollment>> {
        self.enrollment_where("owner", owner).await
    }

    /// The account an apply names.
    pub async fn enrollment_at(&self, authorization: &[u8; 32]) -> Result<Option<Enrollment>> {
        self.enrollment_where("authorization_account", authorization)
            .await
    }

    /// The final fields of a member's authorization, the source of a leaf's seal.
    pub async fn enrollment_of(&self, member: &[u8; 32]) -> Result<Option<Enrollment>> {
        self.enrollment_where("member", member).await
    }

    async fn enrollment_where(&self, column: &str, key: &[u8; 32]) -> Result<Option<Enrollment>> {
        let sql = format!("{ENROLLMENT_READ} WHERE registry=$1 AND {column}=$2");
        let row = self.tree.query_one(&sql, vec![bytes(key)]).await?;
        row.as_ref().map(enrollment).transpose()
    }

    /// First enrollments no apply has inserted, ascending by owner.
    pub async fn pending(&self, after: Option<&[u8; 32]>, limit: u64) -> Result<Vec<Enrollment>> {
        let sql = format!(
            "{ENROLLMENT_READ} WHERE registry=$1 AND owner>$2 AND applied_slot IS NULL \
             ORDER BY owner LIMIT $3"
        );
        let after = bytes(after.unwrap_or(&[0; 32]));
        let rows = self.tree.query_all(&sql, vec![after, int(limit)?]).await?;
        rows.iter().map(enrollment).collect()
    }

    pub async fn save_first(&self, first: &Enrollment, slot: u64) -> Result<()> {
        let sql =
            "INSERT INTO tracking_authorizations(registry,owner,authorization_account,member,\
                   nullifier_pk,ct_hash,list_tag,eph_u,ciphertext,slot) \
                   VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)";
        let values = vec![
            bytes(&first.owner),
            bytes(&first.authorization),
            bytes(&first.member),
            bytes(&first.nullifier_pk),
            bytes(&first.ct_hash),
            bytes(&first.list_tag),
            bytes(&first.eph_u),
            bytes(&first.ciphertext),
            int(slot)?,
        ];
        self.tree.exec(sql, values).await
    }

    pub async fn mark_applied(&self, owner: &[u8; 32], slot: u64) -> Result<()> {
        let sql = "UPDATE tracking_authorizations SET applied_slot=$3 \
                   WHERE registry=$1 AND owner=$2";
        self.tree.exec(sql, vec![bytes(owner), int(slot)?]).await
    }
}

/// Enrollments carry no revision a registry undo can read.
pub(super) async fn rollback_slot<C: ConnectionTrait>(conn: &C, slot: u64) -> Result<()> {
    for sql in [
        "DELETE FROM tracking_authorizations WHERE slot=$1",
        "UPDATE tracking_authorizations SET applied_slot=NULL WHERE applied_slot=$1",
    ] {
        super::exec(conn, sql, vec![int(slot)?]).await?;
    }
    Ok(())
}

fn enrollment(row: &QueryResult) -> Result<Enrollment> {
    Ok(Enrollment {
        owner: field(row, "owner")?,
        authorization: field(row, "authorization_account")?,
        member: field(row, "member")?,
        nullifier_pk: field(row, "nullifier_pk")?,
        ct_hash: field(row, "ct_hash")?,
        list_tag: field(row, "list_tag")?,
        eph_u: field(row, "eph_u")?,
        ciphertext: field(row, "ciphertext")?,
        applied: uint(row, "applied")? != 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::database;

    const REGISTRY: [u8; 32] = [7; 32];

    fn first(owner: u8) -> Enrollment {
        Enrollment {
            owner: [owner; 32],
            authorization: [owner + 50; 32],
            member: [owner + 100; 32],
            nullifier_pk: [1; 32],
            ct_hash: [2; 32],
            list_tag: [3; 32],
            eph_u: [4; 32],
            ciphertext: [5; REGISTER_KEY_CIPHERTEXT_LEN],
            applied: false,
        }
    }

    #[tokio::test]
    async fn an_applied_enrollment_leaves_pending_for_good() {
        let db = database().await;
        let store = TrackingStore::new(&db, REGISTRY);
        let owner = first(9);
        store.save_first(&owner, 10).await.unwrap();
        assert_eq!(store.pending(None, 8).await.unwrap(), [owner]);
        store.mark_applied(&owner.owner, 11).await.unwrap();
        assert!(store.pending(None, 8).await.unwrap().is_empty());
        let applied = Enrollment {
            applied: true,
            ..owner
        };
        assert_eq!(
            store.enrollment_of(&owner.member).await.unwrap(),
            Some(applied)
        );
    }

    #[tokio::test]
    async fn pending_pages_ascend_by_owner_within_one_registry() {
        let db = database().await;
        let store = TrackingStore::new(&db, REGISTRY);
        for owner in [3, 1, 2] {
            store.save_first(&first(owner), 10).await.unwrap();
        }
        TrackingStore::new(&db, [8; 32])
            .save_first(&first(4), 10)
            .await
            .unwrap();
        let owners =
            |page: Vec<Enrollment>| page.iter().map(|row| row.owner[0]).collect::<Vec<_>>();
        assert_eq!(owners(store.pending(None, 2).await.unwrap()), [1, 2]);
        let after = [2; 32];
        assert_eq!(owners(store.pending(Some(&after), 2).await.unwrap()), [3]);
    }

    #[tokio::test]
    async fn a_rolled_back_block_restores_the_enrollment_it_moved() {
        let db = database().await;
        let store = TrackingStore::new(&db, REGISTRY);
        let owner = first(9);
        store.save_first(&owner, 10).await.unwrap();
        store.mark_applied(&owner.owner, 11).await.unwrap();
        rollback_slot(&db, 11).await.unwrap();
        assert_eq!(store.enrollment(&owner.owner).await.unwrap(), Some(owner));
        rollback_slot(&db, 10).await.unwrap();
        assert_eq!(store.enrollment(&owner.owner).await.unwrap(), None);
    }
}
