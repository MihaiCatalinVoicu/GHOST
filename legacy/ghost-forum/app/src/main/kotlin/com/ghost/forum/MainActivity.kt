package com.ghost.forum.app

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import android.view.Menu
import android.view.MenuItem
import android.widget.TextView
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.ghost.forum.crypto.CryptoManager

/**
 * Main activity for Ghost Forum - Private Discussion Platform
 */
class MainActivity : AppCompatActivity() {
    
    private lateinit var recyclerView: RecyclerView
    private lateinit var adapter: ForumAdapter
    private lateinit var cryptoManager: CryptoManager
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        
        // Initialize crypto manager for secure operations
        cryptoManager = CryptoManager()
        
        // Setup UI components
        setupRecyclerView()
        setupToolbar()
        
        // Load forum data (would be loaded from local storage or relay network)
        loadForumData()
    }
    
    private fun setupRecyclerView() {
        recyclerView = findViewById(R.id.recyclerView)
        adapter = ForumAdapter(mutableListOf(), this)
        recyclerView.layoutManager = LinearLayoutManager(this)
        recyclerView.adapter = adapter
    }
    
    private fun setupToolbar() {
        setSupportActionBar(findViewById(R.id.toolbar))
        supportActionBar?.title = "Ghost Forum"
    }
    
    private fun loadForumData() {
        // In a real implementation, this would:
        // 1. Connect to relay network
        // 2. Fetch encrypted forum data
        // 3. Decrypt using crypto manager
        // 4. Display content
        
        val mockThreads = listOf(
            ForumThread("1", "Welcome to Ghost Forum", "This is a private discussion platform", "user1", 10),
            ForumThread("2", "Privacy Discussion", "Let's talk about privacy and security", "user2", 5),
            ForumThread("3", "Crypto Implementation", "How we implement end-to-end encryption", "user3", 8)
        )
        
        adapter.updateThreads(mockThreads)
    }
    
    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.menu_main, menu)
        return true
    }
    
    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            R.id.action_new_thread -> {
                // Create new thread functionality
                true
            }
            R.id.action_settings -> {
                // Settings functionality
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }
}

/**
 * Data class for forum threads
 */
data class ForumThread(
    val id: String,
    val title: String,
    val excerpt: String,
    val author: String,
    val replyCount: Int
)

/**
 * Adapter for forum threads
 */
class ForumAdapter(
    private var threads: List<ForumThread>,
    private val context: MainActivity
) : RecyclerView.Adapter<ForumAdapter.ThreadViewHolder>() {
    
    override fun onCreateViewHolder(parent: android.view.ViewGroup, viewType: Int): ThreadViewHolder {
        val view = android.view.LayoutInflater.from(context)
            .inflate(R.layout.item_thread, parent, false)
        return ThreadViewHolder(view)
    }
    
    override fun onBindViewHolder(holder: ThreadViewHolder, position: Int) {
        holder.bind(threads[position])
    }
    
    override fun getItemCount(): Int = threads.size
    
    fun updateThreads(newThreads: List<ForumThread>) {
        threads = newThreads
        notifyDataSetChanged()
    }
    
    class ThreadViewHolder(itemView: android.view.View) : RecyclerView.ViewHolder(itemView) {
        private val titleText: TextView = itemView.findViewById(R.id.threadTitle)
        private val excerptText: TextView = itemView.findViewById(R.id.threadExcerpt)
        private val authorText: TextView = itemView.findViewById(R.id.threadAuthor)
        private val repliesText: TextView = itemView.findViewById(R.id.threadReplies)
        
        fun bind(thread: ForumThread) {
            titleText.text = thread.title
            excerptText.text = thread.excerpt
            authorText.text = "by ${thread.author}"
            repliesText.text = "${thread.replyCount} replies"
        }
    }
}