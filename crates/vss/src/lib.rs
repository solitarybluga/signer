//! Ristretto255 Feldman verifiable secret sharing for the KEK.
//!
//! A secret scalar is shared with a degree `t-1` polynomial. The dealer
//! publishes one Ristretto255 commitment per coefficient; holders and the
//! server can verify a 33-byte share (`index || y`) against those commitments
//! without learning the polynomial or the secret.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

/// Scheme identifier persisted in `kek_check.json`, manifests, and vaults.
pub const SCHEME: &str = "ristretto255-feldman-v1";

/// Encoded share: one index byte followed by a 32-byte scalar.
pub const SHARE_LEN: usize = 33;

/// Compressed Ristretto255 point length.
pub const COMMITMENT_LEN: usize = 32;

/// Plaintext shares returned by [`split_secret`].
pub type VssShares = Vec<Zeroizing<Vec<u8>>>;

/// Result of splitting a secret: shares plus public commitments.
pub type SplitResult = (VssShares, VssCommitments);

/// Errors returned by VSS operations.
#[derive(Debug, Error)]
pub enum VssError {
    #[error("invalid threshold or share count")]
    InvalidThreshold,

    #[error("invalid secret scalar")]
    InvalidSecret,

    #[error("invalid share")]
    InvalidShare,

    #[error("duplicate share index")]
    DuplicateIndex,

    #[error("invalid commitments")]
    InvalidCommitments,

    #[error("share verification failed")]
    VerificationFailed,

    #[error("not enough shares")]
    NotEnoughShares,

    #[error("secret recovery failed")]
    RecoveryFailed,
}

/// Public commitments to the coefficients of the sharing polynomial.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VssCommitments {
    pub scheme: String,
    /// Hex-encoded compressed Ristretto255 points, `C_0..C_{t-1}`.
    pub commitments: Vec<String>,
}

impl Default for VssCommitments {
    fn default() -> Self {
        Self {
            scheme: SCHEME.to_string(),
            commitments: Vec::new(),
        }
    }
}

impl VssCommitments {
    pub fn from_points(points: &[RistrettoPoint]) -> Self {
        Self {
            scheme: SCHEME.to_string(),
            commitments: points
                .iter()
                .map(|point| hex::encode(point.compress().to_bytes()))
                .collect(),
        }
    }

    /// Decode and validate all commitments.
    pub fn decode(&self) -> Result<Vec<RistrettoPoint>, VssError> {
        if self.scheme != SCHEME || self.commitments.is_empty() {
            return Err(VssError::InvalidCommitments);
        }

        self.commitments
            .iter()
            .map(|value| {
                let bytes: [u8; COMMITMENT_LEN] = hex::decode(value.trim())
                    .map_err(|_| VssError::InvalidCommitments)?
                    .try_into()
                    .map_err(|_| VssError::InvalidCommitments)?;
                CompressedRistretto(bytes)
                    .decompress()
                    .ok_or(VssError::InvalidCommitments)
            })
            .collect()
    }

    pub fn len(&self) -> usize {
        self.commitments.len()
    }

    pub fn is_empty(&self) -> bool {
        self.commitments.is_empty()
    }
}

/// Generate a uniformly random canonical scalar to use as the KEK.
pub fn generate_secret() -> Result<Zeroizing<[u8; 32]>, VssError> {
    loop {
        let scalar = random_scalar();
        if scalar != Scalar::ZERO {
            let bytes = scalar.to_bytes();
            let mut scalar = scalar;
            scalar.zeroize();
            return Ok(Zeroizing::new(bytes));
        }
    }
}

/// Split `secret` into `total_shares` shares with the given threshold.
///
/// The returned shares are zeroized on drop. `secret` must be a canonical
/// 32-byte scalar; use [`generate_secret`] to create one.
pub fn split_secret(
    secret: &[u8; 32],
    threshold: u8,
    total_shares: u8,
) -> Result<SplitResult, VssError> {
    if threshold == 0 || total_shares == 0 || threshold > total_shares {
        return Err(VssError::InvalidThreshold);
    }

    // Decode the canonical scalar s
    let secret_scalar: Option<Scalar> = Scalar::from_canonical_bytes(*secret).into();
    let mut coefficients = Vec::with_capacity(threshold as usize);
    // polynomial
    coefficients.push(secret_scalar.ok_or(VssError::InvalidSecret)?);
    for _ in 1..threshold {
        coefficients.push(random_scalar());
    }

    // i*G
    let commitments: Vec<RistrettoPoint> =
        coefficients.iter().map(RistrettoPoint::mul_base).collect();

    let mut shares = Vec::with_capacity(total_shares as usize);
    for index in 1..=total_shares {
        let x = Scalar::from(u64::from(index));
        // y = f(i)
        let y = evaluate(&coefficients, &x);
        let mut share = vec![0u8; SHARE_LEN];
        share[0] = index;
        share[1..].copy_from_slice(&y.to_bytes());
        shares.push(Zeroizing::new(share));
    }

    for coefficient in &mut coefficients {
        coefficient.zeroize();
    }

    Ok((shares, VssCommitments::from_points(&commitments)))
}

/// Verify that a 33-byte share is consistent with the commitments.
pub fn verify_share(commitments: &VssCommitments, share: &[u8]) -> Result<(), VssError> {
    let points = commitments.decode()?;
    let (index, mut y) = parse_share(share)?;

    let mut left = RistrettoPoint::mul_base(&y);
    let x = Scalar::from(u64::from(index));
    let mut power = Scalar::ONE;
    let mut right = RistrettoPoint::identity();
    for commitment in &points {
        right += commitment * power;
        power *= x;
    }

    // Avoid exposing a secret-dependent comparison path; both sides are
    // compressed and compared as bytes.
    let matches = left.compress().to_bytes() == right.compress().to_bytes();
    left.zeroize();
    y.zeroize();
    if !matches {
        return Err(VssError::VerificationFailed);
    }

    Ok(())
}

/// Recover the secret from verified shares.
///
/// The caller must pass shares that already passed [`verify_share`]. If more
/// than `t` shares are supplied, all of them are used; for a degree `t-1`
/// polynomial this yields the same result.
pub fn recover_secret(
    commitments: &VssCommitments,
    shares: &[Vec<u8>],
) -> Result<Zeroizing<[u8; 32]>, VssError> {
    let points = commitments.decode()?;
    let threshold = points.len();
    if shares.len() < threshold {
        return Err(VssError::NotEnoughShares);
    }

    let mut parsed: Vec<(u8, Scalar)> = Vec::with_capacity(shares.len());
    for share in shares {
        let (index, value) = parse_share(share)?;
        if parsed.iter().any(|(existing, _)| *existing == index) {
            return Err(VssError::DuplicateIndex);
        }
        parsed.push((index, value));
    }

    let mut secret = Scalar::ZERO;
    for (i, (x_i, y_i)) in parsed.iter().enumerate() {
        let x_i = Scalar::from(u64::from(*x_i));
        let mut lambda = Scalar::ONE;
        for (j, (x_j, _)) in parsed.iter().enumerate() {
            if i == j {
                continue;
            }
            let x_j = Scalar::from(u64::from(*x_j));
            lambda *= x_j * (x_j - x_i).invert();
        }
        secret += *y_i * lambda;
    }

    let expected = points[0].compress().to_bytes();
    if RistrettoPoint::mul_base(&secret).compress().to_bytes() != expected {
        secret.zeroize();
        return Err(VssError::RecoveryFailed);
    }

    let bytes = secret.to_bytes();
    secret.zeroize();
    for (_, value) in &mut parsed {
        value.zeroize();
    }

    Ok(Zeroizing::new(bytes))
}

fn parse_share(share: &[u8]) -> Result<(u8, Scalar), VssError> {
    if share.len() != SHARE_LEN {
        return Err(VssError::InvalidShare);
    }
    let index = share[0];
    if index == 0 {
        return Err(VssError::InvalidShare);
    }

    let bytes: [u8; 32] = share[1..].try_into().map_err(|_| VssError::InvalidShare)?;
    let scalar: Option<Scalar> = Scalar::from_canonical_bytes(bytes).into();
    let scalar = scalar.ok_or(VssError::InvalidShare)?;
    Ok((index, scalar))
}
// Horner（秦九韶算法）
fn evaluate(coefficients: &[Scalar], x: &Scalar) -> Scalar {
    let mut value = Scalar::ZERO;
    for coefficient in coefficients.iter().rev() {
        value = value * x + coefficient;
    }
    value
}

fn random_scalar() -> Scalar {
    let mut wide = [0u8; 64];
    OsRng.fill_bytes(&mut wide);
    let scalar = Scalar::from_bytes_mod_order_wide(&wide);
    wide.zeroize();
    scalar
}

#[cfg(test)]
mod tests {
    use super::*;

    type SplitFixture = (Zeroizing<[u8; 32]>, VssShares, VssCommitments);

    fn split(threshold: u8, total: u8) -> SplitFixture {
        let secret = generate_secret().unwrap();
        let (shares, commitments) = split_secret(&secret, threshold, total).unwrap();
        (secret, shares, commitments)
    }

    #[test]
    fn verifies_and_recovers_all_threshold_subsets() {
        let (secret, shares, commitments) = split(2, 3);
        for share in &shares {
            verify_share(&commitments, share).unwrap();
        }

        let combinations = [(0, 1), (0, 2), (1, 2)];
        for (a, b) in combinations {
            let recovered =
                recover_secret(&commitments, &[shares[a].to_vec(), shares[b].to_vec()]).unwrap();
            assert_eq!(&*recovered, &*secret);
        }
    }

    #[test]
    fn rejects_tampered_share_and_wrong_commitment() {
        let (_, shares, commitments) = split(2, 3);
        let mut tampered = shares[0].to_vec();
        tampered[5] ^= 1;
        assert!(matches!(
            verify_share(&commitments, &tampered),
            Err(VssError::VerificationFailed) | Err(VssError::InvalidShare)
        ));

        let mut wrong = commitments.clone();
        wrong.commitments[0] = hex::encode([9u8; 32]);
        assert!(verify_share(&wrong, &shares[0]).is_err());
    }

    #[test]
    fn rejects_duplicate_indices_and_insufficient_shares() {
        let (_, shares, commitments) = split(2, 3);
        assert!(matches!(
            recover_secret(&commitments, &[shares[0].to_vec()]),
            Err(VssError::NotEnoughShares)
        ));
        assert!(matches!(
            recover_secret(&commitments, &[shares[0].to_vec(), shares[0].to_vec()]),
            Err(VssError::DuplicateIndex)
        ));
    }

    #[test]
    fn mixed_ceremonies_are_rejected() {
        let (_, shares_a, commitments_a) = split(2, 3);
        let (_, shares_b, _) = split(2, 3);
        assert!(verify_share(&commitments_a, &shares_b[0]).is_err());
        assert!(
            recover_secret(
                &commitments_a,
                &[shares_a[0].to_vec(), shares_b[1].to_vec()]
            )
            .is_err()
        );
    }

    #[test]
    fn commitments_roundtrip_json() {
        let (_, _, commitments) = split(3, 5);
        let encoded = serde_json::to_string(&commitments).unwrap();
        let decoded: VssCommitments = serde_json::from_str(&encoded).unwrap();
        assert_eq!(commitments, decoded);
        assert_eq!(decoded.len(), 3);
    }
}
