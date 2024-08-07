use super::http::get;
use bitcoin::{Amount, OutPoint, TxOut};

#[derive(Clone)]
pub struct UTXO {
    pub out_point: OutPoint,
    pub tx_out: TxOut,
}

impl UTXO {
    pub fn get_value(&self) -> Amount {
        self.tx_out.value
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct AddressUTXOResponse {}

pub async fn get_btc_utxos(address: &String) -> Vec<UTXO> {
    let api = format!("/address/{}/utxo", address);

    let res = get::<AddressUTXOResponse>(api.as_str()).await.unwrap();

    // TODO
    Vec::new()
}

pub async fn get_runes_utxos(address: &String) -> Vec<UTXO> {
    let api = format!("/address/{}/utxo", address);

    let res = get::<AddressUTXOResponse>(api.as_str()).await.unwrap();

    // TODO
    Vec::new()
}
