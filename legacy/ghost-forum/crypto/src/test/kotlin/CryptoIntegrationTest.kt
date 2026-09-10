package com.ghost.forum.crypto

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*
import java.util.Base64

class CryptoIntegrationTest {
    
    @Test
    fun testCompleteCryptoFlow() {
        val cryptoManager = CryptoManager()
        val doubleRatchet = DoubleRatchet()
        val fileEncryption = FileEncryption()
        
        // 1. Generate identity keys
        val (publicKey, privateKey) = cryptoManager.generateIdentityKeys()
        assertNotNull(publicKey)
        assertNotNull(privateKey)
        
        // 2. Test signature verification
        val message = "This is a test message"
        val signature = cryptoManager.signData(message.toByteArray(), privateKey)
        val isValid = cryptoManager.verifySignature(message.toByteArray(), signature, publicKey)
        assertTrue(isValid)
        
        // 3. Test symmetric encryption
        val key = cryptoManager.generateSymmetricKey()
        val encrypted = cryptoManager.encryptAesGcm(message.toByteArray(), key)
        val decrypted = cryptoManager.decryptAesGcm(encrypted, key)
        assertEquals(message, String(decrypted))
        
        // 4. Test file encryption
        val testContent = "Test file content for encryption\nThis should work properly".toByteArray()
        val tempFile = java.io.File.createTempFile("test", ".txt")
        tempFile.writeBytes(testContent)
        
        val encryptedFile = java.io.File.createTempFile("encrypted", ".dat")
        fileEncryption.encryptFile(tempFile.absolutePath, encryptedFile.absolutePath, key)
        
        val decryptedFile = java.io.File.createTempFile("decrypted", ".txt")
        fileEncryption.decryptFile(encryptedFile.absolutePath, decryptedFile.absolutePath, key)
        
        val decryptedContent = decryptedFile.readBytes()
        assertArrayEquals(testContent, decryptedContent)
        
        // 5. Cleanup
        tempFile.delete()
        encryptedFile.delete()
        decryptedFile.delete()
        
        // 6. Test that all operations are secure
        assertFalse(encrypted.contentEquals(message.toByteArray()))
        assertTrue(encrypted.size > message.length)
    }
    
    @Test
    fun testKeyGenerationSecurity() {
        val cryptoManager = CryptoManager()
        
        // Generate multiple keys and ensure they're different
        val key1 = cryptoManager.generateSymmetricKey()
        val key2 = cryptoManager.generateSymmetricKey()
        
        // Keys should be different (very high probability)
        assertFalse(key1.contentEquals(key2))
        
        // Both should be 32 bytes
        assertEquals(32, key1.size)
        assertEquals(32, key2.size)
        
        // Test key exchange keys
        val (pubKey1, privKey1) = cryptoManager.generateKeyExchangeKeys()
        val (pubKey2, privKey2) = cryptoManager.generateKeyExchangeKeys()
        
        assertNotNull(pubKey1)
        assertNotNull(privKey1)
        assertNotNull(pubKey2)
        assertNotNull(privKey2)
        
        assertFalse(pubKey1 == pubKey2)
        assertFalse(privKey1 == privKey2)
    }
}