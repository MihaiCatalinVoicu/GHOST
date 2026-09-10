package com.ghostforum.ui

import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.ghostforum.R
import com.ghostforum.model.ForumThread
import com.ghostforum.service.ForumService

class MainActivity : AppCompatActivity() {
    
    private lateinit var recyclerView: RecyclerView
    private lateinit var adapter: ThreadAdapter
    private lateinit var forumService: ForumService
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        
        // Inițializare serviciu forum
        forumService = ForumService(this)
        
        // Inițializare UI
        initUI()
        
        // Încarcă thread-urile
        loadThreads()
    }
    
    private fun initUI() {
        recyclerView = findViewById(R.id.recyclerView)
        recyclerView.layoutManager = LinearLayoutManager(this)
        
        val createThreadButton = findViewById<Button>(R.id.createThreadButton)
        val privacySettingsButton = findViewById<Button>(R.id.privacySettingsButton)
        val referralButton = findViewById<Button>(R.id.referralButton)
        
        createThreadButton.setOnClickListener {
            // Navigare către crearea unui nou thread
        }
        
        privacySettingsButton.setOnClickListener {
            // Navigare către setările de confidențialitate
            val intent = Intent(this, PrivacySettingsActivity::class.java)
            startActivity(intent)
        }
        
        referralButton.setOnClickListener {
            // Navigare către sistemul de referințe
        }
    }
    
    private fun loadThreads() {
        // Încarcă thread-urile din serviciu
        val threads = forumService.getAllThreads()
        adapter = ThreadAdapter(threads) { thread ->
            // Navigare către detalii thread
        }
        recyclerView.adapter = adapter
    }
}