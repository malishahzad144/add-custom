package com.adshield

import android.content.Context
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

object Blocklist {
    private val URLS = mapOf(
        "adguard" to "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
        "oisd" to "https://small.oisd.nl/domainswild2"
    )

    // Ad-serving domains only (sub-domains are matched automatically). Normal sites/services are not listed.
    private val BUILTIN = listOf(
        // Google ads / AdMob
        "doubleclick.net", "googlesyndication.com", "googleadservices.com", "googleads.com",
        "adservice.google.com", "admob.com", "2mdn.net", "googletagservices.com", "ads.youtube.com",
        "pagead2.googlesyndication.com", "googleads.g.doubleclick.net",
        // Facebook / Meta ads
        "an.facebook.com", "ads.facebook.com", "ads.instagram.com", "adsmanager.facebook.com",
        // Other mobile ad networks
        "unityads.unity3d.com", "applovin.com", "applvn.com", "supersonicads.com", "ironsource.mobi",
        "ironsrc.com", "vungle.com", "chartboost.com", "adcolony.com", "inmobi.com", "mopub.com",
        "tapjoy.com", "fyber.com", "mintegral.com", "mtgglobals.com", "pangleglobal.com",
        "smaato.net", "startapp.com", "amazon-adsystem.com", "ads.twitter.com", "ads.tiktok.com",
        "ads.pinterest.com", "ads.linkedin.com", "ads.snapchat.com",
        // Ad exchanges / networks
        "adnxs.com", "criteo.com", "criteo.net", "taboola.com", "outbrain.com", "pubmatic.com",
        "rubiconproject.com", "openx.net", "adsrvr.org", "smartadserver.com", "moatads.com",
        "casalemedia.com", "adform.net", "bidswitch.net", "teads.tv", "revcontent.com", "mgid.com",
        "popads.net", "propellerads.com", "exoclick.com", "adsterra.com", "serving-sys.com",
        // Chinese ad SDKs (Pangle, Tencent GDT, Baidu) common in camera/utility apps
        "pangle.io", "pglstatp-toutiao.com", "pangolin-sdk-toutiao.com", "gdt.qq.com",
        "mobads.baidu.com", "mobads-logs.baidu.com"
    )

    @Volatile private var set: HashSet<String> = HashSet(BUILTIN)

    private fun ids(src: String): List<String> = when (src) {
        "both" -> listOf("adguard", "oisd")
        "adguard", "oisd" -> listOf(src)
        else -> emptyList()
    }

    fun load(ctx: Context) {
        val s = HashSet(BUILTIN)
        for (id in ids(ShieldState.source.value)) {
            val f = File(ctx.filesDir, "$id.txt")
            if (f.exists()) f.forEachLine { if (it.isNotEmpty()) s.add(it) }
        }
        set = s
        ShieldState.listSize.value = s.size
    }

    /** Downloads extra lists (optional). Returns an error message, or null on success. */
    fun update(ctx: Context): String? {
        val wanted = ids(ShieldState.source.value)
        if (wanted.isEmpty()) return "Built-in list is selected. Pick AdGuard, OISD or Both to download more."
        try {
            for (id in wanted) {
                val conn = URL(URLS.getValue(id)).openConnection() as HttpURLConnection
                conn.connectTimeout = 15000
                conn.readTimeout = 30000
                try {
                    if (conn.responseCode != 200) return "Download failed for $id (HTTP ${conn.responseCode})"
                    val domains = LinkedHashSet<String>()
                    conn.inputStream.bufferedReader().useLines { lines ->
                        lines.forEach { l -> parse(l)?.let { domains.add(it) } }
                    }
                    if (domains.size < 1000) return "List $id looks empty or invalid; kept previous list"
                    val tmp = File(ctx.filesDir, "$id.tmp")
                    tmp.bufferedWriter().use { w -> domains.forEach { w.write(it); w.newLine() } }
                    val dest = File(ctx.filesDir, "$id.txt")
                    dest.delete()
                    tmp.renameTo(dest)
                } finally {
                    conn.disconnect()
                }
            }
            load(ctx)
            ShieldState.lastUpdate.value = System.currentTimeMillis()
            ShieldState.persist()
            return null
        } catch (e: Exception) {
            return "Update failed: ${e.message ?: e.javaClass.simpleName}"
        }
    }

    internal fun parse(raw: String): String? {
        val l = raw.trim()
        if (l.isEmpty() || l[0] == '#' || l[0] == '!' || l[0] == '[' || l.startsWith("@@")) return null
        val d: String
        if (l.startsWith("||")) {
            val rest = l.substring(2)
            val end = rest.indexOfFirst { it == '^' || it == '/' || it == '$' }
            if (end >= 0 && rest[end] == '/') return null
            d = if (end >= 0) rest.substring(0, end) else rest
        } else if (l.contains(' ') || l.contains('\t')) {
            d = l.split(' ', '\t').filter { it.isNotEmpty() }.getOrNull(1) ?: return null
        } else {
            d = l
        }
        val name = d.removePrefix("*.").lowercase().trimEnd('.')
        if (!name.contains('.') || name.length > 253) return null
        if (!name.all { it in 'a'..'z' || it in '0'..'9' || it == '.' || it == '-' || it == '_' }) return null
        return name
    }

    fun isBlocked(name: String): Boolean {
        var d = name.lowercase().trimEnd('.')
        val s = set
        val c = ShieldState.custom.value
        while (true) {
            if (s.contains(d) || c.contains(d)) return true
            val i = d.indexOf('.')
            if (i < 0) return false
            d = d.substring(i + 1)
        }
    }
}
