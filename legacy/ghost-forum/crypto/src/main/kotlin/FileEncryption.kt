package com.ghost.forum.crypto

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * File encryption utilities for Ghost Forum
 * Used to encrypt media files (images, videos) before uploading
 */
class FileEncryption {
    
    companion object {
        private const val AES_256_GCM = "AES/GCM/NoPadding"
        private const val IV_SIZE = 12
        private const val TAG_SIZE = 16
        private val secureRandom = SecureRandom()
    }
    
    /**
     * Encrypts a file using AES-256-GCM encryption
     * @param data File data to encrypt
     * @param encryptionKey 32-byte AES key
     * @return Encrypted data with IV prepended
     */
    fun encryptFile(data: ByteArray, encryptionKey: ByteArray): ByteArray {
        try {
            val cipher = Cipher.getInstance(AES_256_GCM, "BC")
            
            // Generate a random IV (nonce)
            val iv = ByteArray(IV_SIZE)
            secureRandom.nextBytes(iv)
            
            // Create GCM parameter spec with IV
            val gcmSpec = GCMParameterSpec(TAG_SIZE * 8, iv)
            
            // Initialize cipher for encryption
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(encryptionKey, "AES"), gcmSpec)
            
            // Encrypt the data
            val encryptedData = cipher.doFinal(data)
            
            // Prepend IV to encrypted data
            val result = ByteArray(iv.size + encryptedData.size)
            System.arraycopy(iv, 0, result, 0, iv.size)
            System.arraycopy(encryptedData, 0, result, iv.size, encryptedData.size)
            
            return result
        } catch (e: Exception) {
            throw SecurityException("Failed to encrypt file data", e)
        }
    }
    
    /**
     * Decrypts a file using AES-256-GCM encryption
     * @param encryptedData File data to decrypt (IV prepended)
     * @param encryptionKey 32-byte AES key
     * @return Decrypted data
     */
    fun decryptFile(encryptedData: ByteArray, encryptionKey: ByteArray): ByteArray {
        try {
            // Extract IV from the beginning of the data
            val iv = encryptedData.copyOfRange(0, IV_SIZE)
            val cipherText = encryptedData.copyOfRange(IV_SIZE, encryptedData.size)
            
            val gcmSpec = GCMParameterSpec(TAG_SIZE * 8, iv)
            val cipher = Cipher.getInstance(AES_256_GCM, "BC")
            
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(encryptionKey, "AES"), gcmSpec)
            
            return cipher.doFinal(cipherText)
        } catch (e: Exception) {
            throw SecurityException("Failed to decrypt file data", e)
        }
    }
    
    /**
     * Generates a random encryption key for files
     * @return 32-byte AES-256 key
     */
    fun generateFileEncryptionKey(): ByteArray {
        val keyGenerator = KeyGenerator.getInstance("AES", "BC")
        keyGenerator.init(256)
        val secretKey = keyGenerator.generateKey()
        return secretKey.encoded
    }
    
    /**
     * Encrypts a file with chunked encryption for large files
     * @param data Large file data to encrypt
     * @param encryptionKey 32-byte AES key
     * @return Encrypted chunks
     */
    fun encryptFileChunks(data: ByteArray, encryptionKey: ByteArray, chunkSize: Int = 1024 * 1024): List<ByteArray> {
        val chunks = mutableListOf<ByteArray>()
        
        for (i in data.indices step chunkSize) {
            val end = minOf(i + chunkSize, data.size)
            val chunk = data.copyOfRange(i, end)
            
            // Encrypt each chunk
            val encryptedChunk = encryptFile(chunk, encryptionKey)
            chunks.add(encryptedChunk)
        }
        
        return chunks
    }
    
    /**
     * Decrypts file chunks back to original data
     * @param chunks Encrypted chunks to decrypt
     * @param encryptionKey 32-byte AES key
     * @return Decrypted data
     */
    fun decryptFileChunks(chunks: List<ByteArray>, encryptionKey: ByteArray): ByteArray {
        val decryptedData = mutableListOf<Byte>()
        
        for (chunk in chunks) {
            val decryptedChunk = decryptFile(chunk, encryptionKey)
            decryptedData.addAll(decryptedChunk.asList())
        }
        
        return decryptedData.toByteArray()
    }
}