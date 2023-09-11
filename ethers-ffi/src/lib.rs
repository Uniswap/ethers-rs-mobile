extern crate libc;

// use the ethers_signers crate to manage LocalWallet and Signer
use coins_bip32::{
    enc::{MainnetEncoder, XKeyEncoder},
    path::DerivationPath,
};
use coins_bip39::{English, Mnemonic, Wordlist};
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

pub extern "C" fn validate_mnemonic(mnemonic: *const c_char) -> bool {
    let mnemonic_c_str = unsafe {
        assert!(!mnemonic.is_null());
        CStr::from_ptr(mnemonic)
    };
    let mnemonic_str = mnemonic_c_str.to_str().unwrap();
    let words = mnemonic_str.split(" ");
    
    for word in words {
        match <English as Wordlist>::get_index(word) {
            Ok(_res) => (),
            Err(_err) => return false,
        }
    }
    true
}

#[no_mangle]
fn generate_mnemonic_rust() -> MnemonicAndAddress {
    let rng = &mut rand::thread_rng();
    let mnemonic = Mnemonic::<English>::new_with_count(rng, 12).unwrap().to_phrase().unwrap();
    let mnem_clone = mnemonic.clone();
    let private_key = derive_private_key(mnemonic, 0);

    let mnemonic_struct = MnemonicAndAddress { mnemonic: mnem_clone, address: private_key.address };
    return mnemonic_struct
}

#[no_mangle]
pub extern "C" fn generate_mnemonic() -> CMnemonicAndAddress {
    let mnemonic_struct = generate_mnemonic_rust();
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
fn private_key_from_mnemonic_rust(mnemonic: String, index: u32) -> PrivateKey {
    let priv_struct = derive_private_key(mnemonic, index);
    return priv_struct
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
        drop(CString::from_raw(string));
    };
}

/*
 * The following block of code is used for Android platform specific functionality.
 * It uses the Java Native Interface (JNI) to interact with Java code from Rust.
 *
 * The functions defined in this block are used to:
 * - Generate mnemonics
 * - Derive private keys from mnemonics
 * - Create wallets from private keys
 * - Sign transactions and messages with wallets
 * - Free up memory
 *
 * The functions are declared with the #[no_mangle] attribute to keep their names intact after compilation,
 * and they are declared as extern "system" to use the system's default C calling convention.
 *
 * The functions can be called from Java code using the Java_com_uniswap_RnEthersRs_00024Companion prefix,
 * where:
 * - 'Java_' is a prefix added by the JNI
 * - 'com_uniswap_EthersRs' is the package and class name in the Java code
 */
#[cfg(target_os="android")]
#[allow(non_snake_case)]
pub mod android {
    extern crate jni;

    use super::*;
    use self::jni::JNIEnv;
    use self::jni::objects::{JClass, JString, JValue, JObject};
    use self::jni::sys::{jlong, jobject, jstring, jboolean};

    use coins_bip39::Wordlist;

    fn rust_string_to_jstring<'a>(env: &'a JNIEnv, rust_string: String) -> JString<'a> {
        env.new_string(rust_string).expect("Failed to create Java string")
    }

    fn jstring_to_rust_string(env: &JNIEnv, jstring: JString) -> String {
        let jstr = env.get_string(jstring).expect("Couldn't get java string!");
        return jstr.to_str().expect("Invalid UTF-8 in java string").to_string();
    }

    fn jstring_to_cstring(env: &JNIEnv, jstring: JString) -> CString {
        let jstr = env.get_string(jstring).expect("Couldn't get java string!");
        let cstring = CString::new(jstr.to_str().expect("Invalid UTF-8 in java string"))
            .expect("Failed to create CString");
        cstring
    }

    #[no_mangle]
    pub extern "system" fn Java_com_uniswap_EthersRs_validateMnemonic(env: JNIEnv, _class: JClass, mnemonic: JString) -> jboolean{
        let mnemonic_string = jstring_to_rust_string(&env, mnemonic);
        let words = mnemonic_string.split(" ");
        
        for word in words {
            match <English as Wordlist>::get_index(word) {
                Ok(_res) => (),
                Err(_err) => return false as u8,
            }
        }
        true as u8
    }

    #[no_mangle]
    pub extern "system" fn Java_com_uniswap_EthersRs_generateMnemonic(env: JNIEnv, _class: JClass) -> jobject{
        let mnemonic_struct = generate_mnemonic_rust();

        let class_name = "com/uniswap/MnemonicAndAddress";
        let class = env
            .find_class(class_name)
            .expect(&format!("Failed to find class: {}", class_name));

        // Create a new Java string from the Rust string
        let mnemonic_jstring = rust_string_to_jstring(&env, mnemonic_struct.mnemonic.clone());
        let address_jstring = rust_string_to_jstring(&env, mnemonic_struct.address.clone());

        let object = env
            .new_object(
                class,
                "(Ljava/lang/String;Ljava/lang/String;)V",
                &[
                    JValue::Object(JObject::from(mnemonic_jstring).into()), 
                    JValue::Object(JObject::from(address_jstring).into())
                ],
            )
            .expect("Failed to create MnemonicAndAddress object");
        
        //consume the JObject and return the underlying jobject, which is a raw pointer to the Java object.
        object.into_inner()
    }

    #[no_mangle]
    pub extern "system" fn Java_com_uniswap_EthersRs_privateKeyFromMnemonic(env: JNIEnv, _class: JClass, mnemonic: JString, index: jlong) -> jobject {
        
        let mnemonic_string = jstring_to_rust_string(&env, mnemonic);
        let private_key_struct = private_key_from_mnemonic_rust(mnemonic_string, index as u32);

        let class_name = "com/uniswap/PrivateKeyAndAddress";
        let class = env
            .find_class(class_name)
            .expect(&format!("Failed to find class: {}", class_name));

        // Create a new Java string from the Rust string
        let private_key_jstring = rust_string_to_jstring(&env, private_key_struct.private_key.clone());
        let address_jstring = rust_string_to_jstring(&env, private_key_struct.address.clone());

        // Create a new instance of CMnemonicAndAddress
        let object = env
            .new_object(
                class,
                "(Ljava/lang/String;Ljava/lang/String;)V",
                &[
                    JValue::Object(JObject::from(private_key_jstring).into()), 
                    JValue::Object(JObject::from(address_jstring).into()),
                ],
            )
            .expect("Failed to create PrivateKey object");
        object.into_inner()
    }

    // Function to get a wallet from a private key
    #[no_mangle]
    pub extern "system" fn Java_com_uniswap_EthersRs_walletFromPrivateKey(env: JNIEnv, _class: JClass, private_key: JString)  -> u64 {
        let private_key_cstring = jstring_to_cstring(&env, private_key);
        let wallet_ptr = wallet_from_private_key(private_key_cstring.as_ptr() as *const c_char);
        let wallet_ptr_long: u64 = wallet_ptr as u64;
        wallet_ptr_long
    }
    
    // Function to free the wallet
    #[no_mangle]
    pub extern "system" fn Java_com_uniswap_EthersRs_walletFree(_env: JNIEnv, _class: JClass, wallet_ptr: jlong) {
        // Free the wallet
        wallet_free(wallet_ptr as *mut LocalWallet);
    }
    
    // Function to sign a transaction with a wallet
    #[no_mangle]
    pub extern "system" fn Java_com_uniswap_EthersRs_signTxWithWallet(env: JNIEnv, _class: JClass, wallet_ptr: jlong, tx_hash: JString, chain_id: jlong) -> jstring {
        let tx_hash_cstring = jstring_to_cstring(&env, tx_hash);
        let tx_hash_ptr = tx_hash_cstring.as_ptr();

        // Sign the transaction with the wallet
        let signature_struct = sign_tx_with_wallet(wallet_ptr as *mut LocalWallet, tx_hash_ptr, chain_id as u64);
        // Convert the signature to a Rust String
        let signature = unsafe { CStr::from_ptr(signature_struct.signature).to_string_lossy().into_owned() };
        // Convert the Rust String to a JString
        let output = env.new_string(signature).expect("Couldn't create java string!");
        // Return the JString
        output.into_inner()
    }

    // Function to sign a message with a wallet
    #[no_mangle]
    pub extern "system" fn Java_com_uniswap_EthersRs_signMessageWithWallet(env: JNIEnv, _class: JClass, wallet_ptr: jlong, message: JString) -> jstring {
        let message_cstring = jstring_to_cstring(&env, message);
        let message_ptr = message_cstring.as_ptr();

        // Sign the message with the wallet
        let signature_ptr = sign_message_with_wallet(wallet_ptr as *const LocalWallet, message_ptr);

        // Convert the signature to a Rust String
        let signature = unsafe { CStr::from_ptr(signature_ptr).to_string_lossy().into_owned() };

        // Convert the Rust String to a JString
        let output = env.new_string(signature).expect("Couldn't create java string!");

        // Free signature pointer in C 
        string_free(signature_ptr);

        // Return the JString
        output.into_inner()
    }


    // Function to sign a hash with a wallet
    #[no_mangle]
    pub extern "system" fn Java_com_uniswap_EthersRs_signHashWithWallet(env: JNIEnv, _class: JClass, wallet_ptr: jlong, hash: JString, chain_id: jlong) -> jstring {

        let hash_cstring = jstring_to_cstring(&env, hash);
        let hash_ptr = hash_cstring.as_ptr();

        // Sign the hash with the wallet
        let signature_ptr = sign_hash_with_wallet(wallet_ptr as *const LocalWallet, hash_ptr, chain_id as u64);

        // Convert the signature to a Rust String
        let signature = unsafe { CStr::from_ptr(signature_ptr).to_string_lossy().into_owned() };

        // Convert the Rust String to a JString
        let output = env.new_string(signature).expect("Couldn't create java string!");

        // Free signature pointer in C 
        string_free(signature_ptr);

        // Return the JString
        output.into_inner()
    }
}
