package com.ghostforum.model

data class ForumPost(
    val postId: String,
    val threadId: String,
    val author: String,
    val content: String,
    val timestamp: String
)