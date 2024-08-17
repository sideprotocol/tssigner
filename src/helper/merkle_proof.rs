use std::hash::Hasher;
use std::iter::FromIterator;

use bitcoin::Txid;
use bitcoin_hashes::Hash;

use crypto::digest::Digest;
use crypto::sha2::Sha256;
use merkle_light::hash::Algorithm;
use merkle_light::merkle;
use merkle_light::merkle::MerkleTree;

use super::encoding::to_base64;

#[derive(Clone)]
struct CryptoBitcoinAlgorithm(Sha256);

impl CryptoBitcoinAlgorithm {
    fn new() -> CryptoBitcoinAlgorithm {
        CryptoBitcoinAlgorithm(Sha256::new())
    }
}

impl Default for CryptoBitcoinAlgorithm {
    fn default() -> CryptoBitcoinAlgorithm {
        CryptoBitcoinAlgorithm::new()
    }
}

impl Hasher for CryptoBitcoinAlgorithm {
    #[inline]
    fn write(&mut self, msg: &[u8]) {
        self.0.input(msg)
    }

    #[inline]
    fn finish(&self) -> u64 {
        unimplemented!()
    }
}

type CryptoSHA256Hash = [u8; 32];

impl Algorithm<CryptoSHA256Hash> for CryptoBitcoinAlgorithm {
    #[inline]
    fn hash(&mut self) -> CryptoSHA256Hash {
        let mut h = [0u8; 32];
        self.0.result(&mut h);

        // double sha256
        let mut c = Sha256::new();
        c.input(h.as_ref());
        c.result(&mut h);
        h
    }

    #[inline]
    fn reset(&mut self) {
        self.0.reset();
    }

    fn leaf(&mut self, leaf: CryptoSHA256Hash) -> CryptoSHA256Hash {
        leaf
    }

    fn node(&mut self, left: CryptoSHA256Hash, right: CryptoSHA256Hash) -> CryptoSHA256Hash {
        self.write(left.as_ref());
        self.write(right.as_ref());
        self.hash()
    }
}

pub fn compute_tx_proof(txids: Vec<Txid>, index: usize) -> Vec<String> {
    let leaves = txids.iter().map(|txid| txid.as_raw_hash().to_byte_array());

    let mt: MerkleTree<CryptoSHA256Hash, CryptoBitcoinAlgorithm> =
        merkle::MerkleTree::from_iter(leaves);
    let proof = mt.gen_proof(index);

    let lemma = proof.lemma();
    let branches = &lemma[1..lemma.len() - 1];

    branches
        .iter()
        .enumerate()
        .map(|(i, b)| {
            let mut prefixed_branch = vec![0u8; 33];
            prefixed_branch[0] = if proof.path()[i] { 0 } else { 1 };
            prefixed_branch[1..].copy_from_slice(b);

            to_base64(&prefixed_branch)
        })
        .collect()
}
