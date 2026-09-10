package com.ghost.forum.crypto

import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.*
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.util.*

/**
 * Implementation of Messaging Layer Security (MLS) protocol for group messaging
 * Based on IETF MLS standard using Bouncy Castle for cryptography
 */
class MLS {
    
    companion object {
        private const val GROUP_ID_SIZE = 32
        private const val CIPHER_SUITE_ID = 0x1D // AES-256-GCM-SHA256
        private const val KEY_SIZE = 32
        private const val NONCE_SIZE = 12
        private val secureRandom = SecureRandom()
        
        init {
            // Add Bouncy Castle provider
            Security.addProvider(BouncyCastleProvider())
        }
    }
    
    /**
     * Represents a group in the MLS protocol
     */
    data class Group(
        val groupId: ByteArray,
        val epoch: Long,
        val members: MutableList<Member>,
        val tree: MerkleTree,
        val cipherSuite: Int,
        val encryptionKey: ByteArray,
        val authenticationKey: ByteArray
    )
    
    /**
     * Represents a member in the group
     */
    data class Member(
        val identity: String,       // User identifier (pseudonym)
        val publicKey: ByteArray,   // Public key for this member
        val capabilities: List<String>  // Supported features
    )
    
    /**
     * Represents a Merkle tree structure for group membership
     */
    data class MerkleTree(
        val nodes: MutableList<TreeNode>,
        val rootHash: ByteArray
    )
    
    /**
     * Represents a node in the Merkle tree
     */
    data class TreeNode(
        val nodeId: ByteArray,
        val parent: ByteArray?,
        val leftChild: ByteArray?,
        val rightChild: ByteArray?,
        val leafNode: Boolean,
        val publicKey: ByteArray?
    )
    
    /**
     * Represents a group message
     */
    data class GroupMessage(
        val epoch: Long,
        val sender: String,         // Pseudonym of sender
        val ciphertext: ByteArray,  // Encrypted content
        val signature: ByteArray,   // Signature for authenticity
        val nonce: ByteArray        // Nonce for encryption
    )
    
    /**
     * Represents a group context
     */
    data class GroupContext(
        val groupId: ByteArray,
        val epoch: Long,
        val cipherSuite: Int,
        val treeHash: ByteArray,
        val confirmedTranscriptHash: ByteArray,
        val externalSenders: List<String>,
        val extensions: Map<String, ByteArray>
    )
    
    /**
     * Represents a handshake message
     */
    data class HandshakeMessage(
        val messageType: Int,
        val epoch: Long,
        val sender: String,
        val content: ByteArray,
        val signature: ByteArray
    )
    
    private var currentGroup: Group? = null
    
    /**
     * Creates a new MLS group
     * @param groupId Unique identifier for the group
     * @param members List of initial members
     * @return Group object
     */
    fun createGroup(groupId: String, members: List<Member>): Group {
        val groupIdBytes = groupId.toByteArray()
        
        // Generate initial keys
        val encryptionKey = generateKey(KEY_SIZE)
        val authenticationKey = generateKey(KEY_SIZE)
        
        // Create Merkle tree for group membership
        val tree = createMerkleTree(members)
        
        val group = Group(
            groupId = groupIdBytes,
            epoch = 0L,
            members = members.toMutableList(),
            tree = tree,
            cipherSuite = CIPHER_SUITE_ID,
            encryptionKey = encryptionKey,
            authenticationKey = authenticationKey
        )
        
        currentGroup = group
        
        return group
    }
    
    /**
     * Adds a member to an existing group
     * @param member New member to add
     * @return True if successful, false otherwise
     */
    fun addMember(member: Member): Boolean {
        val group = currentGroup ?: return false
        
        // Add member to group
        group.members.add(member)
        
        // Update Merkle tree
        val updatedTree = updateMerkleTree(group.tree, member)
        group.tree.nodes.clear()
        group.tree.nodes.addAll(updatedTree.nodes)
        group.tree.rootHash = updatedTree.rootHash
        
        return true
    }
    
    /**
     * Removes a member from the group
     * @param member Member to remove
     * @return True if successful, false otherwise
     */
    fun removeMember(member: Member): Boolean {
        val group = currentGroup ?: return false
        
        // Remove member from group
        val removed = group.members.remove(member)
        
        if (removed) {
            // Update Merkle tree
            val updatedTree = updateMerkleTree(group.tree, member, true)
            group.tree.nodes.clear()
            group.tree.nodes.addAll(updatedTree.nodes)
            group.tree.rootHash = updatedTree.rootHash
        }
        
        return removed
    }
    
    /**
     * Encrypts a message for the group
     * @param plaintext Message to encrypt
     * @return Encrypted group message
     */
    fun encryptMessage(plaintext: String): GroupMessage {
        val group = currentGroup ?: throw IllegalStateException("No group initialized")
        
        // Generate random nonce
        val nonce = generateKey(NONCE_SIZE)
        
        // Encrypt using group's encryption key
        val ciphertext = encryptAesGcm(
            plaintext.toByteArray(),
            group.encryptionKey,
            nonce
        )
        
        // Create signature (simplified for now)
        val signature = signMessage(plaintext.toByteArray(), group.encryptionKey)
        
        return GroupMessage(
            epoch = group.epoch,
            sender = "user1", // In real implementation, this would be the actual user identifier
            ciphertext = ciphertext,
            signature = signature,
            nonce = nonce
        )
    }
    
    /**
     * Decrypts a message from the group
     * @param message Group message to decrypt
     * @return Decrypted plaintext
     */
    fun decryptMessage(message: GroupMessage): String {
        val group = currentGroup ?: throw IllegalStateException("No group initialized")
        
        // Verify signature (simplified)
        if (!verifySignature(message.ciphertext, message.signature, group.encryptionKey)) {
            throw SecurityException("Invalid message signature")
        }
        
        // Decrypt using group's encryption key
        val plaintext = decryptAesGcm(
            message.ciphertext,
            group.encryptionKey,
            message.nonce
        )
        
        return String(plaintext)
    }
    
    /**
     * Generates a new epoch for the group (forward secrecy)
     * @return New epoch number
     */
    fun advanceEpoch(): Long {
        val group = currentGroup ?: throw IllegalStateException("No group initialized")
        
        // Generate new keys for forward secrecy
        val newEncryptionKey = generateKey(KEY_SIZE)
        val newAuthenticationKey = generateKey(KEY_SIZE)
        
        // Update group with new keys
        val newEpoch = group.epoch + 1
        currentGroup = group.copy(
            epoch = newEpoch,
            encryptionKey = newEncryptionKey,
            authenticationKey = newAuthenticationKey
        )
        
        return newEpoch
    }
    
    /**
     * Creates a Merkle tree for the group
     * @param members List of members
     * @return MerkleTree object
     */
    private fun createMerkleTree(members: List<Member>): MerkleTree {
        val nodes = mutableListOf<TreeNode>()
        val rootHash = generateKey(KEY_SIZE)
        
        // In a real implementation, this would build the actual tree structure
        for (i in members.indices) {
            val node = TreeNode(
                nodeId = generateKey(KEY_SIZE),
                parent = null,
                leftChild = null,
                rightChild = null,
                leafNode = true,
                publicKey = members[i].publicKey
            )
            nodes.add(node)
        }
        
        return MerkleTree(nodes, rootHash)
    }
    
    /**
     * Updates the Merkle tree when members are added or removed
     * @param tree Current tree structure
     * @param member Member to add/remove
     * @param remove True if removing, false if adding
     * @return Updated tree
     */
    private fun updateMerkleTree(tree: MerkleTree, member: Member, remove: Boolean = false): MerkleTree {
        // Simplified implementation - in a real MLS implementation,
        // this would properly update the Merkle tree structure
        return tree.copy(rootHash = generateKey(KEY_SIZE))
    }
    
    /**
     * Generates a random key of specified size
     * @param size Size of key in bytes
     * @return Random key
     */
    private fun generateKey(size: Int): ByteArray {
        val key = ByteArray(size)
        secureRandom.nextBytes(key)
        return key
    }
    
    /**
     * Encrypts data using AES-GCM
     * @param data Data to encrypt
     * @param key 32-byte AES key
     * @param nonce 12-byte nonce
     * @return Encrypted data with nonce prepended
     */
    private fun encryptAesGcm(data: ByteArray, key: ByteArray, nonce: ByteArray): ByteArray {
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC")
            
            val spec = GCMParameterSpec(128, nonce)
            val secretKeySpec = SecretKeySpec(key, "AES")
            
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, spec)
            val encryptedData = cipher.doFinal(data)
            
            // Prepend nonce to encrypted data
            return nonce + encryptedData
        } catch (e: Exception) {
            throw SecurityException("Failed to encrypt data with AES-GCM", e)
        }
    }
    
    /**
     * Decrypts data using AES-GCM
     * @param encryptedData Encrypted data with nonce prepended
     * @param key 32-byte AES key
     * @param nonce 12-byte nonce
     * @return Decrypted data
     */
    private fun decryptAesGcm(encryptedData: ByteArray, key: ByteArray, nonce: ByteArray): ByteArray {
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC")
            
            // Extract IV from the beginning of encrypted data
            val ciphertext = encryptedData.copyOfRange(NONCE_SIZE, encryptedData.size)
            
            val spec = GCMParameterSpec(128, nonce)
            val secretKeySpec = SecretKeySpec(key, "AES")
            
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, spec)
            return cipher.doFinal(ciphertext)
        } catch (e: Exception) {
            throw SecurityException("Failed to decrypt data with AES-GCM", e)
        }
    }
    
    /**
     * Signs a message with the group's encryption key
     * @param message Message to sign
     * @param key Signing key
     * @return Signature
     */
    private fun signMessage(message: ByteArray, key: ByteArray): ByteArray {
        try {
            // In a real implementation, this would use HMAC-SHA256 or similar
            // For now, we'll create a simple signature using hash of message + key
            val combined = message + key
            val digest = MessageDigest.getInstance("SHA-256", "BC")
            return digest.digest(combined)
        } catch (e: Exception) {
            throw SecurityException("Failed to sign message", e)
        }
    }
    
    /**
     * Verifies a signature on a message
     * @param message Message that was signed
     * @param signature Signature to verify
     * @param key Verification key
     * @return True if valid, false otherwise
     */
    private fun verifySignature(message: ByteArray, signature: ByteArray, key: ByteArray): Boolean {
        try {
            // In a real implementation, this would properly verify the signature
            // For now, we'll just return true as a placeholder
            val combined = message + key
            val digest = MessageDigest.getInstance("SHA-256", "BC")
            val expectedSignature = digest.digest(combined)
            
            // Compare signatures (simplified)
            return Arrays.equals(signature, expectedSignature)
        } catch (e: Exception) {
            return false
        }
    }
}