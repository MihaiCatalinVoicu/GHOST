package com.ghostforum.ui

import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.ghostforum.R
import com.ghostforum.model.ForumPost
import com.ghostforum.model.ForumThread
import com.ghostforum.service.ForumService

class ThreadDetailActivity : AppCompatActivity() {
    
    private lateinit var recyclerView: RecyclerView
    private lateinit var adapter: PostAdapter
    private lateinit var forumService: ForumService
    private lateinit var thread: ForumThread
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_thread_detail)
        
        // Obține thread-ul din intent
        val threadId = intent.getStringExtra("thread_id")
        if (threadId != null) {
            thread = ForumService.getThreadById(threadId)
        }
        
        // Inițializare serviciu forum
        forumService = ForumService(this)
        
        // Inițializare UI
        initUI()
        
        // Încarcă postările
        loadPosts()
    }
    
    private fun initUI() {
        recyclerView = findViewById(R.id.recyclerView)
        recyclerView.layoutManager = LinearLayoutManager(this)
        
        val postEditText = findViewById<EditText>(R.id.postEditText)
        val postButton = findViewById<Button>(R.id.postButton)
        
        postButton.setOnClickListener {
            val content = postEditText.text.toString()
            if (content.isNotEmpty()) {
                // Adaugă o nouă postare
                forumService.createPost(thread.threadId, content)
                postEditText.text.clear()
                loadPosts()
            }
        }
    }
    
    private fun loadPosts() {
        // Încarcă postările din serviciu
        val posts = forumService.getPostsForThread(thread.threadId)
        adapter = PostAdapter(posts) { post ->
            // Handle post click if needed
        }
        recyclerView.adapter = adapter
    }
}