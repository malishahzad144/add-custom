package com.adshield

import android.content.Context
import android.content.SharedPreferences
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.update

data class LogEntry(val domain: String, val blocked: Boolean, val count: Int)

object ShieldState {
    private var sp: SharedPreferences? = null
    val running = MutableStateFlow(false)
    val blocked = MutableStateFlow(0L)
    val total = MutableStateFlow(0L)
    val listSize = MutableStateFlow(0)
    val error = MutableStateFlow<String?>(null)
    val message = MutableStateFlow<String?>(null)
    val updating = MutableStateFlow(false)
    val source = MutableStateFlow("builtin") // builtin | adguard | oisd | both
    val lastUpdate = MutableStateFlow(0L)
    val custom = MutableStateFlow<Set<String>>(emptySet())
    val log = MutableStateFlow<List<LogEntry>>(emptyList())
    private val logMap = LinkedHashMap<String, LogEntry>() // in memory only, never saved

    @Synchronized
    fun init(ctx: Context) {
        if (sp != null) return
        val p = ctx.applicationContext.getSharedPreferences("adshield", Context.MODE_PRIVATE)
        sp = p
        blocked.value = p.getLong("blocked", 0)
        total.value = p.getLong("total", 0)
        source.value = p.getString("source", "builtin") ?: "builtin"
        lastUpdate.value = p.getLong("lastUpdate", 0)
        custom.value = HashSet(p.getStringSet("custom", emptySet()) ?: emptySet())
    }

    fun addCustom(d: String) { custom.value = custom.value + d.lowercase(); saveCustom() }
    fun removeCustom(d: String) { custom.value = custom.value - d; saveCustom() }
    private fun saveCustom() { sp?.edit()?.putStringSet("custom", HashSet(custom.value))?.apply() }

    @Synchronized
    fun record(domain: String, blocked: Boolean) {
        val d = domain.lowercase()
        val old = logMap.remove(d)
        logMap[d] = LogEntry(d, blocked, (old?.count ?: 0) + 1)
        if (logMap.size > 150) { val it = logMap.keys.iterator(); it.next(); it.remove() }
        log.value = logMap.values.reversed().take(60)
    }

    @Synchronized
    fun clearLog() { logMap.clear(); log.value = emptyList() }

    fun persist() {
        sp?.edit()?.putLong("blocked", blocked.value)?.putLong("total", total.value)
            ?.putString("source", source.value)?.putLong("lastUpdate", lastUpdate.value)?.apply()
    }

    fun count(wasBlocked: Boolean) {
        total.update { it + 1 }
        if (wasBlocked) blocked.update { it + 1 }
        if (total.value % 25L == 0L) persist()
    }

    fun resetStats() { blocked.value = 0; total.value = 0; persist() }
}
