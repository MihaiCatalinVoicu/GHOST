package org.ghost.media.play

import androidx.media3.datasource.cache.SimpleCache

/** PM-M10's mutation: the player wrapped in a caching data source. */
class Bad(val cache: SimpleCache)
