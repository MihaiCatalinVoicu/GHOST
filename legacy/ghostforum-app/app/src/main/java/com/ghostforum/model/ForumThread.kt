package com.ghostforum.model

data class ForumThread(
    val threadId: String,
    val title: String,
    val author: String,
    val content: String,
    val postCount: Int
)