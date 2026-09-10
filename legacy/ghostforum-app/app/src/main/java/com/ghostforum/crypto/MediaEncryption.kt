package com.ghostforum.crypto

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Criptare pentru media (imagini, video) într-un forum privat
 */
class MediaEncryption {
    
    private val aesKey: SecretKey
    private val ivLength = 12 // 96 bits for GCM
    
    init {
        // Generare cheie AES-256
        val keyGenerator = KeyGenerator.getInstance("AES")
        keyGenerator.init(256)
        aesKey = keyGenerator.generateKey()
    }
    
    /**
     * Criptează un fișier media
     */
    fun encryptMedia(data: ByteArray): EncryptedMedia {
        // Generare IV aleator
        val iv = ByteArray(ivLength)
        val random = SecureRandom()
        random.nextBytes(iv)
        
        // Configurare GCM
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(128, iv)
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, spec)
        
        // Criptare date
        val encryptedData = cipher.doFinal(data)
        
        return EncryptedMedia(
            data = encryptedData,
            iv = iv,
            key = aesKey.encoded
        )
    }
    
    /**
     * Decriptează un fișier media
     */
    fun decryptMedia(encryptedMedia: EncryptedMedia): ByteArray {
        // Configurare GCM cu IV-ul din date
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(128, encryptedMedia.iv)
        cipher.init(Cipher.DECRYPT_MODE, aesKey, spec)
        
        // Decriptare date
        return cipher.doFinal(encryptedMedia.data)
    }
    
    /**
     * Criptează o cheie pentru distribuire
     */
    fun encryptKey(key: ByteArray): ByteArray {
        // Într-o implementare reală, aceasta ar folosi:
        // - RSA pentru criptarea cheii simetrice
        // - Diffie-Hellman pentru distribuirea sigură a cheilor
        
        val random = SecureRandom()
        val encryptedKey = ByteArray(key.size + 16)
        random.nextBytes(encryptedKey)
        
        // Simulare criptare cu cheie aleatorie
        for (i in key.indices) {
            encryptedKey[i] = (key[i].toInt() xor random.nextInt().toByte().toInt()).toByte()
        }
        
        return encryptedKey
    }
    
    /**
     * Decriptează o cheie
     */
    fun decryptKey(encryptedKey: ByteArray): ByteArray {
        // Într-o implementare reală, aceasta ar folosi:
        // - RSA pentru decriptarea cheii simetrice
        // - Diffie-Hellman pentru distribuirea sigură a cheilor
        
        val random = SecureRandom()
        val key = ByteArray(encryptedKey.size - 16)
        
        // Simulare decriptare cu cheie aleatorie
        for (i in key.indices) {
            key[i] = (encryptedKey[i].toInt() xor random.nextInt().toByte().toInt()).toByte()
        }
        
        return key
    }
}

/**
 * Rezultat al criptării media
 */
data class EncryptedMedia(
    val data: ByteArray,
    val iv: ByteArray,
    val key: ByteArray
)