package com.ghost.forum.app

import android.os.Bundle
import android.view.MenuItem
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.ghost.forum.crypto.CryptoManager
import java.util.*

/**
 * Activity for displaying a specific forum thread and its posts
 */
class ThreadDetailActivity : AppCompatActivity() {
    
    private lateinit var recyclerView: RecyclerView
    private lateinit var adapter: PostAdapter
    private lateinit var cryptoManager: CryptoManager
    private var threadId: String = ""
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_thread_detail)
        
        // Initialize crypto manager for secure operations
        cryptoManager = CryptoManager()
        
        // Get thread ID from intent
        threadId = intent.getStringExtra("THREAD_ID") ?: ""
        
        setupToolbar()
        setupRecyclerView()
        loadThreadData()
    }
    
    private fun setupToolbar() {
        setSupportActionBar(findViewById(R.id.toolbar))
        supportActionBar?.title = "Thread Details"
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
    }
    
    private fun setupRecyclerView() {
        recyclerView = findViewById(R.id.recyclerView)
        adapter = PostAdapter(mutableListOf(), this)
        recyclerView.layoutManager = LinearLayoutManager(this)
        recyclerView.adapter = adapter
    }
    
    private fun loadThreadData() {
        // In a real implementation, this would:
        // 1. Connect to relay network
        // 2. Fetch encrypted thread and posts
        // 3. Decrypt using crypto manager
        // 4. Display content
        
        // Mock data for demonstration
        val mockPosts = listOf(
            Post("1", "Welcome to the discussion!", "user1", System.currentTimeMillis(), true),
            Post("2", "Thanks for sharing this topic. I have some thoughts...", "user2", System.currentTimeMillis() + 300000, false),
            Post("3", "I agree with what you said. Here's something else to consider...", "user3", System.currentTimeMillis() + 600000, false)
        )
        
        adapter.updatePosts(mockPosts)
    }
    
    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            android.R.id.home -> {
                finish()
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }
}

/**
 * Data class for forum posts
 */
data class Post(
    val id: String,
    val content: String,
    val author: String,
    val timestamp: Long,
    val isEncrypted: Boolean = false
)

/**
 * Adapter for forum posts
 */
class PostAdapter(
    private var posts: List<Post>,
    private val context: ThreadDetailActivity
) : androidx.recyclerview.widget.RecyclerView.Adapter<PostAdapter.PostViewHolder>() {
    
    class PostViewHolder(view: android.view.View) : androidx.recyclerview.widget.RecyclerView.ViewHolder(view) {
        val contentTextView: TextView = view.findViewById(R.id.post_content)
        val authorTextView: TextView = view.findViewById(R.id.post_author)
        val timestampTextView: TextView = view.findViewById(R.id.post_timestamp)
    }
    
    override fun onCreateViewHolder(parent: android.view.ViewGroup, viewType: Int): PostViewHolder {
        val view = android.view.LayoutInflater.from(context)
            .inflate(R.layout.item_post, parent, false)
        return PostViewHolder(view)
    }
    
    override fun onBindViewHolder(holder: PostViewHolder, position: Int) {
        val post = posts[position]
        
        holder.contentTextView.text = post.content
        holder.authorTextView.text = "by ${post.author}"
        holder.timestampTextView.text = formatTimestamp(post.timestamp)
    }
    
    override fun getItemCount() = posts.size
    
    fun updatePosts(newPosts: List<Post>) {
        posts = newPosts
        notifyDataSetChanged()
    }
    
    private fun formatTimestamp(timestamp: Long): String {
        val date = Date(timestamp)
        return android.text.format.DateFormat.format("MMM dd, yyyy hh:mm a", date) as String
    }
}