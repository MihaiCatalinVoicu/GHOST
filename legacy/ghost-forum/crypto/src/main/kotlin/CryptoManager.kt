package com.ghost.forum.crypto

import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.*
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.signal.protocol.*
import org.signal.protocol.state.*
import org.signal.protocol.util.ByteUtil

/**
 * Main crypto manager for Ghost Forum
 * Handles all encryption and decryption operations using Bouncy Castle and Signal Protocol
 */
class CryptoManager {
    
    companion object {
        private const val CHACha20_POLY1305 = "ChaCha20-Poly1305"
        private const val AES_256_GCM = "AES/GCM/NoPadding"
        private const val X25519 = "X25519"
        private const val ED25519 = "Ed25519"
        private const val AES_KEY_SIZE = 32
        private const val IV_SIZE = 12
        private const val TAG_SIZE = 16
        
        init {
            // Add Bouncy Castle provider
            Security.addProvider(BouncyCastleProvider())
        }
        
        // Secure random generator for key generation
        private val secureRandom = SecureRandom()
    }
    
    /**
     * Generates a new Ed25519 key pair for user identity
     * @return Pair of public and private keys as base64 strings
     */
    fun generateIdentityKeys(): Pair<String, String> {
        try {
            val keyPairGenerator = KeyPairGenerator.getInstance("Ed25519", "BC")
            val keyPair = keyPairGenerator.generateKeyPair()
            
            val publicKey = keyPair.public.encoded
            val privateKey = keyPair.private.encoded
            
            return Base64.getEncoder().encodeToString(publicKey) to 
                   Base64.getEncoder().encodeToString(privateKey)
        } catch (e: Exception) {
            throw SecurityException("Failed to generate Ed25519 keys", e)
        }
    }
    
    /**
     * Generates a new X25519 key pair for Diffie-Hellman key exchange
     * @return Pair of public and private keys as base64 strings
     */
    fun generateKeyExchangeKeys(): Pair<String, String> {
        try {
            val keyPairGenerator = KeyPairGenerator.getInstance("X25519", "BC")
            val keyPair = keyPairGenerator.generateKeyPair()
            
            val publicKey = keyPair.public.encoded
            val privateKey = keyPair.private.encoded
            
            return Base64.getEncoder().encodeToString(publicKey) to 
                   Base64.getEncoder().encodeToString(privateKey)
        } catch (e: Exception) {
            throw SecurityException("Failed to generate X25519 keys", e)
        }
    }
    
    /**
     * Generates a random symmetric key for message encryption
     * @return 32-byte AES-256 key
     */
    fun generateSymmetricKey(): ByteArray {
        val keyGenerator = KeyGenerator.getInstance("AES", "BC")
        keyGenerator.init(256)
        val secretKey = keyGenerator.generateKey()
        return secretKey.encoded
    }
    
    /**
     * Encrypts data using AES-256-GCM
     * @param data Data to encrypt
     * @param key 32-byte AES key
     * @return Encrypted data with nonce prepended
     */
    fun encryptAesGcm(data: ByteArray, key: ByteArray): ByteArray {
        try {
            val cipher = Cipher.getInstance(AES_256_GCM, "BC")
            
            // Generate a random IV (nonce)
            val iv = ByteArray(IV_SIZE)
            secureRandom.nextBytes(iv)
            
            // Create GCM parameter spec with IV
            val gcmSpec = GCMParameterSpec(TAG_SIZE * 8, iv)
            
            // Initialize cipher for encryption
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), gcmSpec)
            
            // Encrypt the data
            val encryptedData = cipher.doFinal(data)
            
            // Prepend IV to encrypted data
            val result = ByteArray(iv.size + encryptedData.size)
            System.arraycopy(iv, 0, result, 0, iv.size)
            System.arraycopy(encryptedData, 0, result, iv.size, encryptedData.size)
            
            return result
        } catch (e: Exception) {
            throw SecurityException("Failed to encrypt data with AES-GCM", e)
        }
    }
    
    /**
     * Decrypts data using AES-256-GCM
     * @param encryptedData Data to decrypt (IV prepended)
     * @param key 32-byte AES key
     * @return Decrypted data
     */
    fun decryptAesGcm(encryptedData: ByteArray, key: ByteArray): ByteArray {
        try {
            // Extract IV from the beginning of the data
            val iv = encryptedData.copyOfRange(0, IV_SIZE)
            val cipherText = encryptedData.copyOfRange(IV_SIZE, encryptedData.size)
            
            val gcmSpec = GCMParameterSpec(TAG_SIZE * 8, iv)
            val cipher = Cipher.getInstance(AES_256_GCM, "BC")
            
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), gcmSpec)
            
            return cipher.doFinal(cipherText)
        } catch (e: Exception) {
            throw SecurityException("Failed to decrypt data with AES-GCM", e)
        }
    }
    
    /**
     * Signs data using Ed25519
     * @param data Data to sign
     * @param privateKey Private key as base64 string
     * @return Signature as byte array
     */
    fun signData(data: ByteArray, privateKey: String): ByteArray {
        try {
            val keyFactory = KeyFactory.getInstance("Ed25519", "BC")
            val privateKeySpec = PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKey))
            val signingKey = keyFactory.generatePrivate(privateKeySpec)
            
            val signer = Signature.getInstance("Ed25519", "BC")
            signer.initSign(signingKey)
            signer.update(data)
            
            return signer.sign()
        } catch (e: Exception) {
            throw SecurityException("Failed to sign data with Ed25519", e)
        }
    }
    
    /**
     * Verifies signature using Ed25519
     * @param data Data that was signed
     * @param signature Signature to verify
     * @param publicKey Public key as base64 string
     * @return True if signature is valid, false otherwise
     */
    fun verifySignature(data: ByteArray, signature: ByteArray, publicKey: String): Boolean {
        try {
            val keyFactory = KeyFactory.getInstance("Ed25519", "BC")
            val publicKeySpec = X509EncodedKeySpec(Base64.getDecoder().decode(publicKey))
            val verificationKey = keyFactory.generatePublic(publicKeySpec)
            
            val verifier = Signature.getInstance("Ed25519", "BC")
            verifier.initVerify(verificationKey)
            verifier.update(data)
            
            return verifier.verify(signature)
        } catch (e: Exception) {
            return false
        }
    }
    
    /**
     * Derives a Curve25519 key from an Ethereum address using EIP-712 signature
     * @param ethereumAddress Ethereum address (without 0x prefix)
     * @param eip712Signature The signed EIP-712 message
     * @return Curve25519 private key for Signal Protocol
     */
    fun deriveSignalKeyFromEthereum(ethereumAddress: String, eip712Signature: String): ByteArray {
        val web3Bridge = Web3Bridge()
        return web3Bridge.deriveSignalKeyFromEthereum(ethereumAddress, eip712Signature)
    }
    
    /**
     * Generates a deterministic signature for EIP-712 message
     * @param ethereumAddress The user's Ethereum address
     * @return A signature that can be verified by the app
     */
    fun generateEip712Signature(ethereumAddress: String): String {
        val web3Bridge = Web3Bridge()
        return web3Bridge.generateEip712Signature(ethereumAddress)
    }
    
    /**
     * Verifies that the signature corresponds to the Ethereum address
     * @param ethereumAddress The Ethereum address to verify
     * @param eip712Signature The EIP-712 signature
     * @return True if signature is valid for the address, false otherwise
     */
    fun verifyEthereumSignature(ethereumAddress: String, eip712Signature: String): Boolean {
        val web3Bridge = Web3Bridge()
        return web3Bridge.verifyEthereumSignature(ethereumAddress, eip712Signature)
    }
}