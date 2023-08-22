package com.uniswap

 /**
 * This object is not used directly in this repo, but is included to show what the JNI bindings correspond with. 
 */
object EthersRs {
    /**
     * Generates a mnemonic and its associated address.
     * @return A CMnemonicAndAddress object containing the generated mnemonic and its associated address.
     */
    external fun generateMnemonic(): CMnemonicAndAddress


    /**
     * Frees the memory allocated for the mnemonic.
     * @param mnemonic The mnemonic to be freed.
     */
    external fun mnemonicFree(mnemonic: CMnemonicAndAddress)

    /**
     * Generates a private key from a given mnemonic.
     * @param mnemonic The mnemonic to generate the private key from.
     * @param index The index of the private key to generate.
     * @return A CPrivateKey object containing the generated private key.
     */
    external fun privateKeyFromMnemonic(mnemonic: String?, index: Int): CPrivateKey

    /**
     * Frees the memory allocated for the private key.
     * @param privateKey The private key to be freed.
     */
    external fun privateKeyFree(privateKey: CPrivateKey)

    /**
     * Creates a wallet from a given private key.
     * @param privateKey The private key to create the wallet from.
     * @return A long representing the pointer to the created wallet.
     */
    external fun walletFromPrivateKey(privateKey: String?): Long

    /**
     * Frees the memory allocated for the wallet.
     * @param walletPtr The pointer to the wallet to be freed.
     */
    external fun walletFree(walletPtr: Long)

    /**
     * Signs a transaction with a wallet.
     * @param localWallet The wallet to sign the transaction with.
     * @param txHash The transaction hash to sign.
     * @param chainId The id of the blockchain network.
     * @return A signed transaction hash.
     */
    external fun signTxWithWallet(
      localWallet: Long,
      txHash: String,
      chainId: Long
    ): String

    /**
     * Signs a message with a wallet.
     * @param localWallet The wallet to sign the message with.
     * @param message The message to sign.
     * @return The signed message.
     */
    external fun signMessageWithWallet(
      localWallet: Long,
      message: String
    ): String

    /**
     * Signs a hash with a wallet.
     * @param localWallet The wallet to sign the hash with.
     * @param hash The hash to sign.
     * @param chainId The id of the blockchain network.
     * @return The signed hash.
     */
    external fun signHashWithWallet(
      localWallet: Long,
      hash: String,
      chainId: Long
    ): String

  /**
   * Frees the memory allocated for the string.
   * @param string The string to be freed.
   */
  external fun stringFree(string: String)
}

/**
 * Represents a private key and its associated address.
 * @property privateKey The private key.
 * @property address The address associated with the private key.
 * @property handle This is a pointer to a Rust CPrivateKey struct.
 */
class CPrivateKey(
  var privateKey: String,
  var address: String,
  var handle: Long
)

/**
 * Represents a mnemonic and its associated address.
 * @property mnemonic The mnemonic phrase.
 * @property address The address associated with the mnemonic.
 * @property handle This is a pointer to a Rust CMnemonicAndAddress struct.
 */
class CMnemonicAndAddress(
  var mnemonic: String,
  var address: String,
  var handle: Long
)
