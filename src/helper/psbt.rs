use std::str::FromStr;

use super::encoding::*;
use super::utxo;

use bitcoin::{absolute::LockTime, transaction::Version, SignedAmount, TxIn, Witness};
use bitcoin::{key::Secp256k1, Address, Network, PublicKey, TapNodeHash, XOnlyPublicKey};
use bitcoin::{opcodes::all::OP_RETURN, psbt::PsbtSighashType, script::Builder, Psbt};
use bitcoin::{Amount, ScriptBuf, Transaction, TxOut};
use ordinals::Edict;
use ordinals::{RuneId, Runestone};

use frost_secp256k1_tr::VerifyingKey;

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
    hash.copy_from_slice(tweak.as_slice());
    let merkle_root = TapNodeHash::assume_hidden(hash);

    Address::p2tr(&secp, internal_key, Some(merkle_root), network)
}

pub async fn build_psbt(
    btc_vault: &String,
    recipient: &String,
    amount: u64,
    sequence: u64,
    fee_rate: u64,
) -> String {
    let recipient_addr = Address::from_str(&recipient).unwrap().assume_checked();

    let sequence_out = TxOut {
        value: Amount::ZERO,
        script_pubkey: build_op_return_script(sequence),
    };
    let recipient_out = TxOut {
        value: Amount::from_sat(amount),
        script_pubkey: recipient_addr.script_pubkey(),
    };

    let utxos = utxo::get_btc_utxos(btc_vault).await;
    let (unsigned_tx, selected_utxos) = build_unsigned_transaction(
        &Vec::new(),
        &vec![sequence_out, recipient_out],
        &utxos,
        btc_vault,
        fee_rate,
    );

    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();
    for i in 0..psbt.inputs.len() - 1 {
        psbt.inputs[i].witness_utxo = Some(selected_utxos[i].tx_out.clone());
        psbt.inputs[i].sighash_type = Some(PsbtSighashType::from_str("SIGHASH_DEFAULT").unwrap());
    }

    to_base64(psbt.serialize().as_slice())
}

pub async fn build_runes_psbt(
    btc_vault: &String,
    runes_vault: &String,
    recipient: &String,
    rune_id: &String,
    amount: &String,
    sequence: u64,
    fee_rate: u64,
) -> String {
    let recipient_addr = Address::from_str(&recipient).unwrap().assume_checked();

    let runes_out = TxOut {
        value: Amount::ZERO,
        script_pubkey: build_runes_edict_script(rune_id, amount, 2),
    };
    let sequence_out = TxOut {
        value: Amount::ZERO,
        script_pubkey: build_op_return_script(sequence),
    };
    let recipient_out = TxOut {
        value: Amount::from_sat(546),
        script_pubkey: recipient_addr.script_pubkey(),
    };

    let payment_utxos = utxo::get_btc_utxos(btc_vault).await;
    let runes_utxos = utxo::get_runes_utxos(runes_vault).await;

    let (unsigned_tx, selected_utxos) = build_unsigned_transaction(
        &runes_utxos,
        &vec![runes_out, sequence_out, recipient_out],
        &payment_utxos,
        btc_vault,
        fee_rate,
    );

    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();

    for i in 0..runes_utxos.len() {
        psbt.inputs[i].witness_utxo = Some(runes_utxos[i].tx_out.clone());
        psbt.inputs[i].sighash_type = Some(PsbtSighashType::from_str("SIGHASH_DEFAULT").unwrap());
    }

    for i in 0..selected_utxos.len() {
        psbt.inputs[i + runes_utxos.len()].witness_utxo = Some(selected_utxos[i].tx_out.clone());
        psbt.inputs[i + runes_utxos.len()].sighash_type =
            Some(PsbtSighashType::from_str("SIGHASH_DEFAULT").unwrap());
    }

    to_base64(psbt.serialize().as_slice())
}

pub fn build_unsigned_transaction(
    utxos: &Vec<utxo::UTXO>,
    tx_outs: &Vec<TxOut>,
    payment_utxos: &Vec<utxo::UTXO>,
    change: &String,
    fee_rate: u64,
) -> (Transaction, Vec<utxo::UTXO>) {
    let mut tx: Transaction = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: Vec::new(),
        output: Vec::new(),
    };

    let in_amount = utxos
        .iter()
        .map(|utxo| {
            tx.input.push(TxIn {
                previous_output: utxo.out_point,
                ..Default::default()
            });
            utxo.get_value()
        })
        .sum::<Amount>();

    let out_amount = tx_outs
        .iter()
        .map(|out| {
            tx.output.push(out.clone());
            out.value
        })
        .sum::<Amount>();

    let change_addr = Address::from_str(change).unwrap().assume_checked();

    let selected_utxos = add_payment_utxos(
        &mut tx,
        in_amount
            .to_signed()
            .unwrap()
            .checked_sub(out_amount.to_signed().unwrap())
            .unwrap(),
        payment_utxos,
        &change_addr,
        fee_rate,
    );

    (tx, selected_utxos)
}

pub fn add_payment_utxos(
    tx: &mut Transaction,
    delta: SignedAmount,
    payment_utxos: &Vec<utxo::UTXO>,
    change: &Address,
    fee_rate: u64,
) -> Vec<utxo::UTXO> {
    let mut selected_utxos = Vec::new();
    let mut payment_value = Amount::ZERO;

    for utxo in payment_utxos {
        tx.input.push(TxIn {
            previous_output: utxo.out_point,
            ..Default::default()
        });
        tx.output.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: change.script_pubkey(),
        });

        selected_utxos.push(utxo.clone());

        payment_value = payment_value.checked_add(utxo.get_value()).unwrap();
        let fee = get_tx_virtual_size(&tx) as u64 * fee_rate;

        let change_value = delta.to_sat() + payment_value.to_sat() as i64 - fee as i64;
        if change_value > 0 {
            tx.output.last_mut().unwrap().value = Amount::from_sat(change_value as u64);
            if is_dust_out(tx.output.last().unwrap()) {
                tx.output.pop();
            }

            return selected_utxos;
        }

        tx.output.pop();

        if change_value == 0 {
            return selected_utxos;
        }

        let fee_without_change = get_tx_virtual_size(tx) as u64 * fee_rate;
        if delta.to_sat() + payment_value.to_sat() as i64 - fee_without_change as i64 >= 0 {
            return selected_utxos;
        }
    }

    Vec::new()
}

pub fn is_dust_out(tx_out: &TxOut) -> bool {
    tx_out
        .value
        .lt(&TxOut::minimal_non_dust(tx_out.script_pubkey.clone()).value)
}

pub fn get_tx_virtual_size(tx: &Transaction) -> usize {
    let witness = vec![vec![0u8; 64]];

    let mut cloned_tx = tx.clone();
    cloned_tx
        .input
        .iter_mut()
        .map(|input| input.witness = Witness::from_slice(witness.as_slice()));

    Transaction::vsize(tx)
}

pub fn build_op_return_script(data: u64) -> ScriptBuf {
    let mut protocol = [0u8; 4];
    protocol.copy_from_slice("side".as_bytes());

    Builder::new()
        .push_opcode(OP_RETURN)
        .push_slice(protocol)
        .push_slice(data.to_be_bytes())
        .into_script()
}

pub fn build_runes_edict_script(id: &String, amount: &String, output: u32) -> ScriptBuf {
    let rune_id = RuneId::from_str(&id).unwrap();
    let amount = u128::from_str(&amount).unwrap();

    let runestone = Runestone {
        edicts: vec![Edict {
            id: rune_id,
            amount: amount,
            output: output,
        }],
        etching: None,
        mint: None,
        pointer: None,
    };

    ScriptBuf::from_bytes(runestone.encipher().to_bytes())
}
