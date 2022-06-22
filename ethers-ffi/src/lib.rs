extern crate libc;

// use the ethers_signers crate to manage LocalWallet and Signer
use coins_bip32::{
    enc::{MainnetEncoder, XKeyEncoder},
    path::DerivationPath,
};
use coins_bip39::{English, Mnemonic};
use ethers_core::{
    types::{Address, H256},
    utils::{keccak256, to_checksum},
};
use ethers_signers::{LocalWallet, Signer};
use k256::{ecdsa::VerifyingKey, elliptic_curve::sec1::ToEncodedPoint};

use ffi_convert::*;
use futures_executor::block_on;
use libc::c_char;
use std::{
    ffi::{CStr, CString},
    str::FromStr,
};

const DEFAULT_DERIVATION_PATH_PREFIX: &str = "m/44'/60'/0'/0/";

// copied from aws/utils
/// Convert a verifying key to an ethereum address
fn verifying_key_to_checksummed_address(key: VerifyingKey) -> String {
    // false for uncompressed
    let uncompressed_pub_key = key.to_encoded_point(false);
    let public_key = uncompressed_pub_key.to_bytes();
    debug_assert_eq!(public_key[0], 0x04);
    let hash = keccak256(&public_key[1..]);
    let address = Address::from_slice(&hash[12..]);
    let checksum = to_checksum(&address, None);
    return checksum
}

pub struct PrivateKey {
    private_key: String,
    address: String,
}

#[repr(C)]
#[derive(CReprOf, AsRust, CDrop)]
#[target_type(PrivateKey)]
pub struct CPrivateKey {
    private_key: *const c_char,
    address: *const c_char,
}

pub struct MnemonicAndAddress {
    mnemonic: String,
    address: String,
}

#[repr(C)]
#[derive(CReprOf, AsRust, CDrop)]
#[target_type(MnemonicAndAddress)]
pub struct CMnemonicAndAddress {
    mnemonic: *const c_char,
    address: *const c_char,
}

pub struct SignedTransaction {
    signature: String,
}

#[repr(C)]
#[derive(CReprOf, AsRust, CDrop)]
#[target_type(SignedTransaction)]
pub struct CSignedTransaction {
    signature: *const c_char,
}

#[no_mangle]
pub extern "C" fn generate_mnemonic() -> CMnemonicAndAddress {
    let rng = &mut rand::thread_rng();
    let mnemonic = Mnemonic::<English>::new_with_count(rng, 12).unwrap().to_phrase().unwrap();
    let mnem_clone = mnemonic.clone();
    let private_key = derive_private_key(mnemonic, 0);

    let mnemonic_struct = MnemonicAndAddress { mnemonic: mnem_clone, address: private_key.address };

    return CMnemonicAndAddress::c_repr_of(mnemonic_struct).unwrap()
}

#[no_mangle]
pub extern "C" fn mnemonic_free(mnemonic: CMnemonicAndAddress) {
    drop(mnemonic);
}

fn derive_private_key(mnemonic_str: String, index: u32) -> PrivateKey {
    let mnemonic = Mnemonic::<English>::new_from_phrase(&mnemonic_str).unwrap();
    let derivation_path = DerivationPath::from_str(&format!(
        "{}{}",
        DEFAULT_DERIVATION_PATH_PREFIX,
        index.to_string()
    ))
    .unwrap();
    let private_key = mnemonic.derive_key(derivation_path, None).unwrap();
    let private_key_str = MainnetEncoder::xpriv_to_base58(&private_key).unwrap();
    let verifying_key = private_key.verify_key();
    let address = verifying_key_to_checksummed_address(verifying_key.key);

    return PrivateKey { private_key: private_key_str, address }
}

#[no_mangle]
pub extern "C" fn private_key_from_mnemonic(mnemonic: *const c_char, index: u32) -> CPrivateKey {
    let mnemonic_c_str = unsafe {
        assert!(!mnemonic.is_null());
        CStr::from_ptr(mnemonic)
    };
    let mnemonic_str = mnemonic_c_str.to_str().unwrap();
    let priv_struct = derive_private_key(mnemonic_str.to_string(), index);
    return CPrivateKey::c_repr_of(priv_struct).unwrap()
}

#[no_mangle]
pub extern "C" fn private_key_free(private_key: CPrivateKey) {
    drop(private_key);
}

#[no_mangle]
pub extern "C" fn wallet_from_private_key(private_key: *const c_char) -> *mut LocalWallet {
    let private_key_c_str = unsafe {
        assert!(!private_key.is_null());
        CStr::from_ptr(private_key)
    };
    let private_key_str = private_key_c_str.to_str().unwrap();
    let xpriv = MainnetEncoder::xpriv_from_base58(private_key_str).unwrap();
    let wallet: LocalWallet = LocalWallet::from(xpriv.key);
    println!("Created wallet with address: {}", wallet.address());
    return opaque_pointer::raw(wallet)
}

#[no_mangle]
pub extern "C" fn wallet_free(wallet_ptr: *mut LocalWallet) {
    unsafe { opaque_pointer::own_back(wallet_ptr) }.unwrap();
}

#[no_mangle]
pub extern "C" fn sign_tx_with_wallet(
    wallet_ptr: *const LocalWallet,
    tx_hash: *const c_char,
    chain_id: u64,
) -> CSignedTransaction {
    let wallet = unsafe { opaque_pointer::object(wallet_ptr) }.unwrap();
    let tx_hash_c_str = unsafe {
        assert!(!tx_hash.is_null());
        CStr::from_ptr(tx_hash)
    };

    let tx_hash_str = tx_hash_c_str.to_str().unwrap();
    let wallet = wallet.clone().with_chain_id(chain_id);
    let hex_tx = hex::decode(tx_hash_str).unwrap();
    let hex_slice = hex_tx.as_slice();
    let fixed_arr: [u8; 32] = hex_slice.try_into().unwrap();
    let tx_hash = H256::from(fixed_arr);

    let signature = wallet.sign_hash(tx_hash);
    let sig_string = format!("{}", signature);

    let t = SignedTransaction { signature: sig_string };
    return CSignedTransaction::c_repr_of(t).unwrap()
}

#[no_mangle]
pub extern "C" fn sign_message_with_wallet(
    wallet_ptr: *const LocalWallet,
    message: *const c_char,
) -> *mut c_char {
    let wallet = unsafe { opaque_pointer::object(wallet_ptr) }.unwrap();
    let message_c_str = unsafe {
        assert!(!message.is_null());

        CStr::from_ptr(message)
    };
    let message_str = message_c_str.to_str().unwrap();
    let signature = block_on(wallet.sign_message(&message_str)).unwrap();

    let sig_string = format!("{}", signature);
    let sig_c_str = CString::new(sig_string).unwrap();
    return sig_c_str.into_raw()
}

#[no_mangle]
pub extern "C" fn sign_hash_with_wallet(
    wallet_ptr: *const LocalWallet,
    hash: *const c_char,
    chain_id: u64,
) -> *mut c_char {
    let wallet = unsafe { opaque_pointer::object(wallet_ptr) }.unwrap();
    let hash_c_str = unsafe {
        assert!(!hash.is_null());

        CStr::from_ptr(hash)
    };
    let hash_str = hash_c_str.to_str().unwrap();
    let wallet = wallet.clone().with_chain_id(chain_id);

    let hex_hash = hex::decode(hash_str).unwrap();
    let hex_slice = hex_hash.as_slice();
    let fixed_arr: [u8; 32] = hex_slice.try_into().unwrap();
    let hash = H256::from(fixed_arr);

    let signature = wallet.sign_hash(hash);

    let sig_string = format!("{}", signature);
    let sig_c_str = CString::new(sig_string).unwrap();
    return sig_c_str.into_raw()
}

#[no_mangle]
pub extern "C" fn string_free(string: *mut c_char) {
    unsafe {
        if string.is_null() {
            return
        }
        CString::from_raw(string)
    };
}
