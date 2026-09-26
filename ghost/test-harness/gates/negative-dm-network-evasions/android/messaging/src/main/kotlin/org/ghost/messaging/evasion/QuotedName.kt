package org.ghost.messaging.evasion

// Backtick quoting of each part of a package name. Expected: line 5.
internal object QuotedName {
    val proxies = `java`.`net`.ProxySelector.getDefault()
}
