package com.ghost.forum.app

import android.app.Application
import com.ghost.forum.crypto.CryptoManager

/**
 * Main application class for Ghost Forum
 * Initializes core components and manages application lifecycle
 */
class App : Application() {
    
    companion object {
        private lateinit var instance: App
        private lateinit var cryptoManager: CryptoManager
    }
    
    override fun onCreate() {
        super.onCreate()
        instance = this
        
        // Initialize crypto manager
        cryptoManager = CryptoManager()
        
        // Initialize other components
        initializeComponents()
    }
    
    /**
     * Get the application instance
     */
    fun getInstance(): App {
        return instance
    }
    
    /**
     * Get the crypto manager
     */
    fun getCryptoManager(): CryptoManager {
        return cryptoManager
    }
    
    /**
     * Initialize all components of the application
     */
    private fun initializeComponents() {
        // Initialize relay network connection
        // Initialize storage systems
        // Initialize notification systems
        // etc.
        
        println("Ghost Forum app initialized")
    }
}