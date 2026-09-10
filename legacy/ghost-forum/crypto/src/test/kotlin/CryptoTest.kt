package com.ghost.forum.crypto

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*
import java.util.Base64

class CryptoTest {
    
    @Test
    fun testIdentityKeyGeneration() {
        val cryptoManager = CryptoManager()
        
        // Generate identity keys
        val (publicKey, privateKey) = cryptoManager.generateIdentityKeys()
        
        // Verify they're valid base64 strings
        assertNotNull(publicKey)
        assertNotNull(privateKey)
        assertFalse(publicKey.isEmpty())
        assertFalse(privateKey.isEmpty())
        
        // Verify they can be decoded
        val publicKeyBytes = Base64.getDecoder().decode(publicKey)
        val privateKeyBytes = Base64.getDecoder().decode(privateKey)
        
        assertTrue(publicKeyBytes.isNotEmpty())
        assertTrue(privateKeyBytes.isNotEmpty())
    }
    
    @Test
    fun testKeyExchangeKeyGeneration() {
        val cryptoManager = CryptoManager()
        
        // Generate key exchange keys
        val (publicKey, privateKey) = cryptoManager.generateKeyExchangeKeys()
        
        // Verify they're valid base64 strings
        assertNotNull(publicKey)
        assertNotNull(privateKey)
        assertFalse(publicKey.isEmpty())
        assertFalse(privateKey.isEmpty())
        
        // Verify they can be decoded
        val publicKeyBytes = Base64.getDecoder().decode(publicKey)
        val privateKeyBytes = Base64.getDecoder().decode(privateKey)
        
        assertTrue(publicKeyBytes.isNotEmpty())
        assertTrue(privateKeyBytes.isNotEmpty())
    }
    
    @Test
    fun testSymmetricKeyGeneration() {
        val cryptoManager = CryptoManager()
        
        // Generate symmetric key
        val key = cryptoManager.generateSymmetricKey()
        
        // Verify it's 32 bytes (256 bits)
        assertEquals(32, key.size)
        assertTrue(key.isNotEmpty())
    }
    
    @Test
    fun testAesGcmEncryptionDecryption() {
        val cryptoManager = CryptoManager()
        
        // Generate a key
        val key = cryptoManager.generateSymmetricKey()
        
        // Test data
        val originalData = "Hello, Ghost Forum!".toByteArray()
        
        // Encrypt
        val encrypted = cryptoManager.encryptAesGcm(originalData, key)
        
        // Verify encrypted data is not the same as original
        assertFalse(encrypted.contentEquals(originalData))
        
        // Decrypt
        val decrypted = cryptoManager.decryptAesGcm(encrypted, key)
        
        // Verify decryption worked
        assertArrayEquals(originalData, decrypted)
    }
    
    @Test
    fun testChaCha20Poly1305EncryptionDecryption() {
        val cryptoManager = CryptoManager()
        
        // Generate a key
        val key = cryptoManager.generateSymmetricKey()
        
        // Test data
        val originalData = "Hello, ChaCha20-Poly1305!".toByteArray()
        
        // Encrypt
        val encrypted = cryptoManager.encryptChaCha20Poly1305(originalData, key)
        
        // Verify encrypted data is not the same as original
        assertFalse(encrypted.contentEquals(originalData))
        
        // Decrypt
        val decrypted = cryptoManager.decryptChaCha20Poly1305(encrypted, key)
        
        // Verify decryption worked
        assertArrayEquals(originalData, decrypted)
    }
    
    @Test
    fun testSignatureVerification() {
        val cryptoManager = CryptoManager()
        
        // Generate identity keys
        val (publicKey, privateKey) = cryptoManager.generateIdentityKeys()
        
        // Test data
        val data = "This is a signed message".toByteArray()
        
        // Sign
        val signature = cryptoManager.signData(data, privateKey)
        
        // Verify signature
        val isValid = cryptoManager.verifySignature(data, signature, publicKey)
        
        assertTrue(isValid)
    }
    
    @Test
    fun testDoubleRatchetBasic() {
        val doubleRatchet = DoubleRatchet()
        
        // Generate keys for testing
        val cryptoManager = CryptoManager()
        val (ourPublicKey, ourPrivateKey) = cryptoManager.generateKeyExchangeKeys()
        val (peerPublicKey, peerPrivateKey) = cryptoManager.generateKeyExchangeKeys()
        
        // Initialize ratchet
        doubleRatchet.initialize(
            Base64.getDecoder().decode(ourPrivateKey),
            Base64.getDecoder().decode(ourPublicKey),
            Base64.getDecoder().decode(peerPublicKey)
        )
        
        // Test encryption/decryption
        val originalMessage = "Secret message for ratchet"
        val encryptedMessage = doubleRatchet.encrypt(originalMessage.toByteArray())
        val decryptedMessage = doubleRatchet.decrypt(encryptedMessage)
        
        assertEquals(originalMessage, String(decryptedMessage))
    }
    
    @Test
    fun testFileEncryption() {
        val fileEncryption = FileEncryption()
        
        // Generate a key
        val encryptionKey = fileEncryption.generateFileEncryptionKey()
        
        // Create test file content
        val testContent = "This is test content for file encryption\nIt should be encrypted properly".toByteArray()
        
        // Write test file
        val tempFile = java.io.File.createTempFile("test", ".txt")
        tempFile.writeBytes(testContent)
        
        // Encrypt file
        val encryptedFile = java.io.File.createTempFile("encrypted", ".dat")
        fileEncryption.encryptFile(tempFile.absolutePath, encryptedFile.absolutePath, encryptionKey)
        
        // Verify encrypted file exists and is different from original
        assertTrue(encryptedFile.exists())
        assertTrue(encryptedFile.length() > tempFile.length())
        
        // Decrypt file
        val decryptedFile = java.io.File.createTempFile("decrypted", ".txt")
        fileEncryption.decryptFile(encryptedFile.absolutePath, decryptedFile.absolutePath, encryptionKey)
        
        // Verify decryption worked
        val decryptedContent = decryptedFile.readBytes()
        assertArrayEquals(testContent, decryptedContent)
        
        // Cleanup
        tempFile.delete()
        encryptedFile.delete()
        decryptedFile.delete()
    }
    
    @Test
    fun testMLSBasic() {
        val mls = MLS()
        
        // Create members
        val member1 = MLS.Member(
            identity = "user1",
            publicKey = ByteArray(32) { 0x01 },
            capabilities = listOf("chat", "media")
        )
        
        val member2 = MLS.Member(
            identity = "user2",
            publicKey = ByteArray(32) { 0x02 },
            capabilities = listOf("chat", "media")
        )
        
        // Create group
        val group = mls.createGroup("test-group", listOf(member1, member2))
        
        // Test encryption/decryption
        val message = "This is a group message"
        val encryptedMessage = mls.encryptMessage(message)
        val decryptedMessage = mls.decryptMessage(encryptedMessage)
        
        assertEquals(message, decryptedMessage)
    }
}