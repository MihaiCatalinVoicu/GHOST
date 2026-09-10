package com.ghostforum.ui

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.ghostforum.R
import com.ghostforum.model.ForumPost

class PostAdapter(
    private val posts: List<ForumPost>,
    private val onItemClick: (ForumPost) -> Unit
) : RecyclerView.Adapter<PostAdapter.ViewHolder>() {
    
    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val authorTextView: TextView = view.findViewById(R.id.postAuthor)
        val contentTextView: TextView = view.findViewById(R.id.postContent)
        val timestampTextView: TextView = view.findViewById(R.id.postTimestamp)
    }
    
    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_post, parent, false)
        return ViewHolder(view)
    }
    
    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val post = posts[position]
        holder.authorTextView.text = post.author
        holder.contentTextView.text = post.content
        holder.timestampTextView.text = post.timestamp
        
        holder.itemView.setOnClickListener {
            onItemClick(post)
        }
    }
    
    override fun getItemCount() = posts.size
}