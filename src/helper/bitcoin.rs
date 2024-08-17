use bitcoin::{
    key::Secp256k1, opcodes, script::Instruction, Address, BlockHash, Network, PublicKey,
    ScriptBuf, TapNodeHash, Transaction, Txid, XOnlyPublicKey,
};
use bitcoincore_rpc::RpcApi;
use frost_secp256k1_tr::VerifyingKey;

use crate::app::config;

use super::{encoding, merkle_proof};

pub fn get_group_address(verify_key: &VerifyingKey, network: Network) -> Address {
    // let verifying_key_b = json_data.pubkey_package.verifying_key();
    let pubk = PublicKey::from_slice(&verify_key.serialize()[..]).unwrap();
    let internal_key = XOnlyPublicKey::from(pubk.inner);
    let secp = Secp256k1::new();
    Address::p2tr(&secp, internal_key, None, network)
}

pub fn get_group_address_by_tweak(
    verify_key: &VerifyingKey,
    tweak: Vec<u8>,
    network: Network,
) -> Address {
    // let verifying_key_b = json_data.pubkey_package.verifying_key();
    let pubk = PublicKey::from_slice(&verify_key.serialize()[..]).unwrap();
    let internal_key = XOnlyPublicKey::from(pubk.inner);
    let secp = Secp256k1::new();

    let mut hash: [u8; 32] = [0; 32];
    hash[0..tweak.len()].copy_from_slice(tweak.as_slice());
    let merkle_root = TapNodeHash::assume_hidden(hash);

    Address::p2tr(&secp, internal_key, Some(merkle_root), network)
}

pub fn get_address_from_pk_script(pk_script: ScriptBuf, network: Network) -> String {
    match Address::from_script(&pk_script, network) {
        Ok(address) => address.to_string(),
        _ => String::new(),
    }
}

pub fn compute_tx_proof(txids: Vec<Txid>, index: usize) -> Vec<String> {
    merkle_proof::compute_tx_proof(txids, index)
}

pub fn is_deposit_tx(tx: &Transaction, network: Network) -> bool {
    tx.output.iter().any(|out| {
        config::address_exists(
            get_address_from_pk_script(out.clone().script_pubkey, network).as_str(),
        )
    })
}

pub fn may_be_withdraw_tx(tx: &Transaction) -> bool {
    let script = &tx.output[0].script_pubkey;
    let instructions = script.instruction_indices();

    for inst in instructions {
        match inst {
            Ok((0, Instruction::Op(opcodes::all::OP_RETURN))) => {}
            Ok((1, Instruction::PushBytes(bytes))) => {
                if bytes.as_bytes().ne("side".as_bytes()) {
                    return false;
                }
            }
            Ok((6, Instruction::PushBytes(bytes))) => {
                if bytes.len() > 8 {
                    return false;
                }
            }
            _ => {
                return false;
            }
        }
    }

    return true;
}

#[cfg(test)]
mod tests {
    use bitcoin::{transaction::Version, Amount, OutPoint, TxIn, TxOut};
    use bitcoin_hashes::Hash;

    use encoding::from_base64;

    use super::*;

    #[test]
    fn test_withdraw_tx_check() {
        let mut protocol = [0u8; 4];
        protocol.copy_from_slice("side".as_bytes());

        let sequence = u64::MAX;

        let tx = Transaction {
            version: Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: [TxIn {
                previous_output: OutPoint {
                    txid: Txid::all_zeros(),
                    vout: 0,
                },
                ..Default::default()
            }]
            .to_vec(),
            output: [TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::builder()
                    .push_opcode(opcodes::all::OP_RETURN)
                    .push_slice(protocol)
                    .push_slice(sequence.to_be_bytes())
                    .into_script(),
            }]
            .to_vec(),
        };

        assert!(may_be_withdraw_tx(&tx), "may be a withdrawal tx")
    }

    #[test]
    fn test_tx_proof() {
        // mainnet block: 80000
        let mut txid1 =
            hex::decode("c06fbab289f723c6261d3030ddb6be121f7d2508d77862bb1e484f5cd7f92b25")
                .unwrap();
        let mut txid2 =
            hex::decode("5a4ebf66822b0b2d56bd9dc64ece0bc38ee7844a23ff1d7320a88c5fdb2ad3e2")
                .unwrap();

        txid1.reverse();
        txid2.reverse();

        let txids = vec![
            Txid::from_slice(txid1.as_slice()).unwrap(),
            Txid::from_slice(txid2.as_slice()).unwrap(),
        ];

        let proof = compute_tx_proof(txids, 1);
        assert_eq!(proof.len(), 1);

        let mut branch = from_base64(&proof[0]).unwrap();
        branch[1..].reverse();
        assert_eq!(
            hex::encode(branch),
            "01c06fbab289f723c6261d3030ddb6be121f7d2508d77862bb1e484f5cd7f92b25"
        );
    }
}
