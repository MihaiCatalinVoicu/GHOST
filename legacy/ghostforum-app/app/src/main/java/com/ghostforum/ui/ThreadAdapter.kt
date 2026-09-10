package com.ghostforum.ui

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.ghostforum.R
import com.ghostforum.model.ForumThread

class ThreadAdapter(
    private val threads: List<ForumThread>,
    private val onItemClick: (ForumThread) -> Unit
) : RecyclerView.Adapter<ThreadAdapter.ViewHolder>() {
    
    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val titleTextView: TextView = view.findViewById(R.id.threadTitle)
        val authorTextView: TextView = view.findViewById(R.id.threadAuthor)
        val postCountTextView: TextView = view.findViewById(R.id.postCount)
    }
    
    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_thread, parent, false)
        return ViewHolder(view)
    }
    
    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val thread = threads[position]
        holder.titleTextView.text = thread.title
        holder.authorTextView.text = thread.author
        holder.postCountTextView.text = "${thread.postCount} posts"
        
        holder.itemView.setOnClickListener {
            onItemClick(thread)
        }
    }
    
    override fun getItemCount() = threads.size
}