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
 * - 'com_uniswap_RnEthersRs' is the package and class name in the Java code
 * - '_00024Companion' is the escaped form of $Companion, which is a static nested class generated by Kotlin for companion objects.
 */
#[cfg(target_os="android")]
#[allow(non_snake_case)]
pub mod android {
    extern crate jni;

    use super::*;
    use self::jni::JNIEnv;
    use self::jni::objects::{JClass, JString, JValue, JObject};
    use self::jni::sys::{jlong, jobject, jstring};

    #[no_mangle]
    pub extern "system" fn Java_com_uniswap_RnEthersRs_00024Companion_generateMnemonic(env: JNIEnv, _class: JClass) -> jobject{
        let mnemonic_struct = generate_mnemonic();

        let class_name = "com/uniswap/CMnemonicAndAddress";
        let class = env
            .find_class(class_name)
            .expect(&format!("Failed to find class: {}", class_name));

            // Convert the mnemonic and address fields to Rust String
        let mnemonic = unsafe { CStr::from_ptr(mnemonic_struct.mnemonic).to_string_lossy().into_owned() };
        let address = unsafe { CStr::from_ptr(mnemonic_struct.address).to_string_lossy().into_owned() };

        // Convert the Rust String to UTF-8 encoded C string
        let mnemonic_cstring = CString::new(mnemonic.clone()).expect("Failed to create CString for mnemonic");
        let address_cstring = CString::new(address.clone()).expect("Failed to create CString for address");

        // Create a new Java string from the UTF-8 encoded C string
        let mnemonic_jstring = env
            .new_string(mnemonic_cstring.to_str().expect("Invalid UTF-8 in mnemonic"))
            .expect("Failed to create Java string from mnemonic");

        let address_jstring = env
            .new_string(address_cstring.to_str().expect("Invalid UTF-8 in address"))
            .expect("Failed to create Java string from address");

        // Create a Box that owns the mnemonic_struct (box) is a smart pointer that allocates data on the heap).
        // When this Box is dropped (goes out of scope), it will deallocate the mnemonic_struct as well.
        let mnemonic_box = Box::new(mnemonic_struct);
        let mnemonic_ptr = Box::into_raw(mnemonic_box);
    
        // Cast the raw pointer to a jlong, which is a pointer to a JLong object
        let handle = mnemonic_ptr as jlong;

        let object = env
            .new_object(
                class,
                "(Ljava/lang/String;Ljava/lang/String;J)V",
                &[
                    JValue::Object(JObject::from(mnemonic_jstring).into()), 
                    JValue::Object(JObject::from(address_jstring).into()),
                    JValue::Long(handle)
                ],
            )
            .expect("Failed to create CMnemonicAndAddress object");
        
        //consume the JObject and return the underlying jobject, which is a raw pointer to the Java object.
        object.into_inner()
    }

    #[no_mangle]
    pub extern "system" fn Java_com_uniswap_RnEthersRs_00024Companion_privateKeyFromMnemonic(env: JNIEnv, _class: JClass, mnemonic: JString, index: jlong) -> jobject {
        let mnemonic_str: String = env.get_string(mnemonic).expect("Couldn't get java string!").into();
        let mnemonic_cstring = CString::new(mnemonic_str).expect("Failed to create CString");
        let mnemonic_ptr = mnemonic_cstring.as_ptr() as *const c_char;

        let private_key_struct = private_key_from_mnemonic(mnemonic_ptr, index as u32);

        let class_name = "com/uniswap/CPrivateKey";
        let class = env
            .find_class(class_name)
            .expect(&format!("Failed to find class: {}", class_name));

        // Convert the mnemonic and address fields to Rust String
        let private_key = unsafe { CStr::from_ptr(private_key_struct.private_key).to_string_lossy().into_owned() };
        let address = unsafe { CStr::from_ptr(private_key_struct.address).to_string_lossy().into_owned() };

        // Convert the Rust String to UTF-8 encoded C string
        let private_key_cstring = CString::new(private_key.clone()).expect("Failed to create CString for mnemonic");
        let address_cstring = CString::new(address.clone()).expect("Failed to create CString for address");

        // Create a new Java string from the UTF-8 encoded C string
        let private_key_jstring = env
            .new_string(private_key_cstring.to_str().expect("Invalid UTF-8 in mnemonic"))
            .expect("Failed to create Java string from mnemonic");


        let address_jstring = env
            .new_string(address_cstring.to_str().expect("Invalid UTF-8 in address"))
            .expect("Failed to create Java string from address");

        // Create a Box that owns the prv struct (box) is a smart pointer that allocates data on the heap).
        // When this Box is dropped (goes out of scope), it will deallocate  prv as well.
        let private_key_box = Box::new(private_key_struct);
        let private_key_ptr = Box::into_raw(private_key_box);
    
        // Cast the raw pointer to a jlong, which is a pointer to a JLong object
        let handle = private_key_ptr as jlong;

        // Create a new instance of CMnemonicAndAddress
        let object = env
            .new_object(
                class,
                "(Ljava/lang/String;Ljava/lang/String;J)V",
                &[
                    JValue::Object(JObject::from(private_key_jstring).into()), 
                    JValue::Object(JObject::from(address_jstring).into()),
                    JValue::Long(handle)
                ],
            )
            .expect("Failed to create CPrivateKey object");
        object.into_inner()
    }

    // Function to free the mnemonic
    #[no_mangle]
    pub extern "system" fn Java_com_uniswap_RnEthersRs_00024Companion_mnemonicFree(env: JNIEnv, _class: JClass, mnemonic: jobject) {
        // Get the handle field (which is a pointer to the Rust object) from the Java object
        let mnemonic_object = JObject::from(mnemonic);
        let handle = env.get_field(mnemonic_object, "handle", "J").expect("Should be able to get field handle").j().expect("handle should be a long");

        // Cast the handle to a pointer to the Rust object
        let mnemonic_ptr = handle as *mut CMnemonicAndAddress;

        // Take ownership of the Rust object and free it
        let mnemonic_struct =  unsafe { opaque_pointer::own_back(mnemonic_ptr).unwrap() };
        mnemonic_free(mnemonic_struct);
    }

    // Function to free the private key
    #[no_mangle]
    pub extern "system" fn Java_com_uniswap_RnEthersRs_00024Companion_privateKeyFree(env: JNIEnv, _class: JClass, private_key: jobject) {
        // Convert the jobject to a JObject
        let private_key_object = JObject::from(private_key);

        // Get the handle field from the JObject. The handle is a jlong that we will cast to a pointer.
        let handle = env.get_field(private_key_object, "handle", "J")
            .expect("Should be able to get field handle")
            .j().expect("handle should be a long");

        // Cast the handle to a pointer to the Rust object
        let private_key_ptr = handle as *mut CPrivateKey;

        // Take ownership of the Rust object and free it
        let private_key_struct =  unsafe { opaque_pointer::own_back(private_key_ptr).unwrap() };
        private_key_free(private_key_struct);
    }

    // Function to get a wallet from a private key
    #[no_mangle]
    pub extern "system" fn Java_com_uniswap_RnEthersRs_00024Companion_walletFromPrivateKey(env: JNIEnv, _class: JClass, private_key: JString)  -> u64 {
        // Convert the JString to a Rust String
        let private_key: String = env.get_string(private_key).expect("Couldn't get java string!").into();

        // Convert the Rust String to a CString
        let private_key_str = CString::new(private_key.clone()).expect("Failed to create CString for mnemonic");

        // Get a wallet from the private key
        let wallet_ptr = wallet_from_private_key(private_key_str.as_ptr() as *const c_char);
        let wallet_ptr_long: u64 = wallet_ptr as u64;
        wallet_ptr_long
    }

    // Function to free the wallet
    #[no_mangle]
    pub extern "system" fn Java_com_uniswap_RnEthersRs_00024Companion_walletFree(_env: JNIEnv, _class: JClass, wallet_ptr: jlong) {
        // Free the wallet
        wallet_free(wallet_ptr as *mut LocalWallet);
    }
    
    // Function to sign a transaction with a wallet
    #[no_mangle]
    pub extern "system" fn Java_com_uniswap_RnEthersRs_00024Companion_signTxWithWallet(env: JNIEnv, _class: JClass, wallet_ptr: jlong, tx_hash: JString, chain_id: jlong) -> jstring {
        // Convert the JString to a Rust String
        let tx_hash_str: String = env.get_string(tx_hash).expect("Couldn't get java string!").into();
        let tx_hash_cstring = CString::new(tx_hash_str).expect("Failed to create CString");
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
    pub extern "system" fn Java_com_uniswap_RnEthersRs_00024Companion_signMessageWithWallet(env: JNIEnv, _class: JClass, wallet_ptr: jlong, message: JString) -> jstring {
        // Convert the JString to a Rust String
        let message_str: String = env.get_string(message).expect("Couldn't get java string!").into();
        let message_cstring = CString::new(message_str).expect("Failed to create CString");
        let message_ptr = message_cstring.as_ptr();

        // Sign the message with the wallet
        let signature_ptr = sign_message_with_wallet(wallet_ptr as *const LocalWallet, message_ptr);

        // Convert the signature to a Rust String
        let signature = unsafe { CStr::from_ptr(signature_ptr).to_string_lossy().into_owned() };

        // Convert the Rust String to a JString
        let output = env.new_string(signature).expect("Couldn't create java string!");

        // Return the JString
        output.into_inner()
    }


    // Function to sign a hash with a wallet
    #[no_mangle]
    pub extern "system" fn Java_com_uniswap_RnEthersRs_00024Companion_signHashWithWallet(env: JNIEnv, _class: JClass, wallet_ptr: jlong, hash: JString, chain_id: jlong) -> jstring {
        // Convert the JString to a Rust String
        let hash_str: String = env.get_string(hash).expect("Couldn't get java string!").into();
        let hash_cstring = CString::new(hash_str.clone()).expect("Failed to create CString");
        let hash_ptr = hash_cstring.as_ptr();

        // Sign the hash with the wallet
        let signature_ptr = sign_hash_with_wallet(wallet_ptr as *const LocalWallet, hash_ptr, chain_id as u64);

        // Convert the signature to a Rust String
        let signature = unsafe { CStr::from_ptr(signature_ptr).to_string_lossy().into_owned() };

        // Convert the Rust String to a JString
        let output = env.new_string(signature).expect("Couldn't create java string!");

        // Return the JString
        output.into_inner()
    }

    // Function to free a string
    #[no_mangle]
    pub extern "system" fn Java_com_uniswap_RnEthersRs_00024Companion_stringFree(env: JNIEnv, _class: JClass, string: JString) {
        // Convert the JString to a Rust String
        let string_str: String = env.get_string(string).expect("Couldn't get java string!").into();

        // Convert the Rust String to a CString
        let c_string_str = CString::new(string_str).expect("Failed to create CString for mnemonic");

        // Convert the CString into a raw pointer
        let c_string_ptr = c_string_str.into_raw(); // makes mutable raw pointer

        // Free the string
        string_free(c_string_ptr);
    }
}
