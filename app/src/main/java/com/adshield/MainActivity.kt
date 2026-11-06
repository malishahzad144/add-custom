package com.adshield

import android.Manifest
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.text.DateFormat
import java.util.Date

private val Green = Color(0xFF4ADE80)
private val Scheme = darkColorScheme(
    primary = Green, onPrimary = Color(0xFF05210F), background = Color(0xFF0B0F14),
    surface = Color(0xFF131A22), onSurface = Color(0xFFE6EDF3), onBackground = Color(0xFFE6EDF3),
    surfaceVariant = Color(0xFF1B2530), onSurfaceVariant = Color(0xFF9AA7B4), error = Color(0xFFF87171)
)

class MainActivity : ComponentActivity() {
    private val vpnPermission = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        if (it.resultCode == RESULT_OK) startShield()
        else ShieldState.error.value = "Permission denied. Android needs your OK to let AdShield filter DNS on this device."
    }
    private val notifPermission = registerForActivityResult(ActivityResultContracts.RequestPermission()) {}

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        ShieldState.init(this)
        lifecycleScope.launch(Dispatchers.IO) { Blocklist.load(this@MainActivity) }
        if (Build.VERSION.SDK_INT >= 33) notifPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        setContent { MaterialTheme(colorScheme = Scheme) { Screen() } }
    }

    private fun startShield() {
        ContextCompat.startForegroundService(
            this, Intent(this, AdShieldVpnService::class.java).setAction(AdShieldVpnService.ACTION_START)
        )
    }

    private fun toggle() {
        if (ShieldState.running.value) {
            startService(Intent(this, AdShieldVpnService::class.java).setAction(AdShieldVpnService.ACTION_STOP))
        } else {
            ShieldState.error.value = null
            ShieldState.message.value = null
            val mode = Settings.Global.getString(contentResolver, "private_dns_mode")
            if (mode == "hostname") {
                ShieldState.error.value = "Private DNS is set to a specific server, which makes the internet fail while AdShield runs. Set it to Off or Automatic (Settings > Network > Private DNS), then press START again."
                return
            }
            val i = VpnService.prepare(this)
            if (i != null) vpnPermission.launch(i) else startShield()
        }
    }

    private fun refresh() {
        if (ShieldState.updating.value) return
        ShieldState.updating.value = true
        ShieldState.error.value = null
        ShieldState.message.value = null
        lifecycleScope.launch(Dispatchers.IO) {
            val err = Blocklist.update(this@MainActivity)
            if (err == null) ShieldState.message.value = "Lists updated" else ShieldState.error.value = err
            ShieldState.updating.value = false
        }
    }

    private fun pick(src: String) {
        ShieldState.source.value = src
        ShieldState.persist()
        lifecycleScope.launch(Dispatchers.IO) { Blocklist.load(this@MainActivity) }
    }

    @Composable
    private fun Screen() {
        val running by ShieldState.running.collectAsState()
        val blocked by ShieldState.blocked.collectAsState()
        val total by ShieldState.total.collectAsState()
        val size by ShieldState.listSize.collectAsState()
        val err by ShieldState.error.collectAsState()
        val msg by ShieldState.message.collectAsState()
        val updating by ShieldState.updating.collectAsState()
        val src by ShieldState.source.collectAsState()
        val last by ShieldState.lastUpdate.collectAsState()
        val log by ShieldState.log.collectAsState()
        val custom by ShieldState.custom.collectAsState()
        val dim = MaterialTheme.colorScheme.onSurfaceVariant

        Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
            Column(
                Modifier.verticalScroll(rememberScrollState()).padding(20.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                Text("AdShield", fontSize = 22.sp, fontWeight = FontWeight.SemiBold, modifier = Modifier.align(Alignment.Start))
                Spacer(Modifier.height(8.dp))
                Box(
                    Modifier.size(170.dp).clip(CircleShape)
                        .background(if (running) Green else MaterialTheme.colorScheme.surfaceVariant)
                        .clickable { toggle() },
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        if (running) "STOP" else "START", fontSize = 26.sp, fontWeight = FontWeight.Bold,
                        color = if (running) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onSurface
                    )
                }
                Text(
                    if (running) "Ad servers blocked" else "Not active", fontSize = 20.sp, fontWeight = FontWeight.Medium,
                    color = if (running) Green else dim
                )
                err?.let { Text(it, color = MaterialTheme.colorScheme.error, textAlign = TextAlign.Center) }
                if (err?.startsWith("Private DNS") == true) {
                    OutlinedButton(onClick = { try { startActivity(Intent(Settings.ACTION_WIRELESS_SETTINGS)) } catch (_: Exception) {} }) {
                        Text("Open network settings")
                    }
                }
                msg?.let { Text(it, color = Green, textAlign = TextAlign.Center) }

                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    Stat("Ads blocked", "%,d".format(blocked), Modifier.weight(1f))
                    Stat("DNS requests", "%,d".format(total), Modifier.weight(1f))
                    Stat("Blocked %", if (total > 0) "${blocked * 100 / total}%" else "0%", Modifier.weight(1f))
                }
                TextButton(onClick = { ShieldState.resetStats() }) { Text("Reset statistics") }

                CardBox {
                    Text("Block list", fontWeight = FontWeight.SemiBold)
                    Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        listOf("builtin" to "Built-in", "adguard" to "AdGuard", "oisd" to "OISD", "both" to "Both").forEach { (id, label) ->
                            FilterChip(selected = src == id, onClick = { pick(id) }, label = { Text(label) })
                        }
                    }
                    val stamp = if (last > 0 && src != "builtin")
                        " · updated " + DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(Date(last))
                    else ""
                    Text("%,d domains".format(size) + stamp, color = dim, fontSize = 13.sp)
                    Text(
                        "Built-in = Google/AdMob, Facebook/Meta, Unity, AppLovin, ironSource, Vungle, Chartboost, InMobi and other ad networks only. AdGuard/OISD add far more domains (including trackers).",
                        color = dim, fontSize = 12.sp
                    )
                    Button(onClick = { refresh() }, enabled = !updating && src != "builtin") {
                        if (updating) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary)
                        else Text("Download selected list")
                    }
                }

                CardBox {
                    Text("DNS log: find ads of a specific app", fontWeight = FontWeight.SemiBold)
                    Text(
                        "1) Press START. 2) Open the app (e.g. V380) until its ad shows. 3) Come back here and look for domains that look like ads (ads, adx, pangle, gdt, mobads...). Tap Block. Only block ad-looking names: if the app stops connecting, tap Unblock. The log is kept in memory only, never saved.",
                        color = dim, fontSize = 12.sp, lineHeight = 17.sp
                    )
                    if (log.isEmpty()) Text("No queries yet. Start AdShield and use an app.", color = dim, fontSize = 13.sp)
                    log.forEach { e ->
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Column(Modifier.weight(1f)) {
                                Text(e.domain, fontSize = 13.sp, color = if (e.blocked) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface)
                                Text((if (e.blocked) "blocked" else "allowed") + " · ${e.count}x", fontSize = 11.sp, color = dim)
                            }
                            if (custom.contains(e.domain)) TextButton(onClick = { ShieldState.removeCustom(e.domain) }) { Text("Unblock") }
                            else if (!e.blocked) TextButton(onClick = { ShieldState.addCustom(e.domain) }) { Text("Block") }
                        }
                    }
                    if (log.isNotEmpty()) TextButton(onClick = { ShieldState.clearLog() }) { Text("Clear log") }
                }

                CardBox {
                    Text("Domains you blocked", fontWeight = FontWeight.SemiBold)
                    if (custom.isEmpty()) Text("None yet.", color = dim, fontSize = 13.sp)
                    custom.sorted().forEach { d ->
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(d, Modifier.weight(1f), fontSize = 13.sp)
                            TextButton(onClick = { ShieldState.removeCustom(d) }) { Text("Unblock") }
                        }
                    }
                }

                CardBox {
                    Text("How it works & limitations", fontWeight = FontWeight.SemiBold)
                    Text(
                        "AdShield uses Android's VPN slot as a local DNS filter. Nothing leaves your phone through a VPN server: only DNS lookups are captured, and all other internet traffic goes directly as normal. Lookups for ad domains get an empty answer so ads can't load; every other lookup goes unchanged to Cloudflare/Google DNS. No logs, accounts or analytics.\n\n" +
                            "• You will see the VPN key icon while it runs. Only one VPN can be active at a time.\n" +
                            "• Turn off \"Private DNS\" (Settings > Network) or Android will bypass AdShield.\n" +
                            "• YouTube ads are NOT blocked: they come from the same servers as the videos.\n" +
                            "• Ads an app serves from its own servers can't be blocked by DNS.\n" +
                            "• Some apps may show empty ad spaces or refuse to work when their ads are blocked.",
                        color = dim, fontSize = 13.sp, lineHeight = 19.sp
                    )
                }
            }
        }
    }

    @Composable
    private fun Stat(label: String, value: String, modifier: Modifier) {
        Column(modifier.clip(RoundedCornerShape(16.dp)).background(MaterialTheme.colorScheme.surface).padding(14.dp)) {
            Text(value, fontSize = 20.sp, fontWeight = FontWeight.Bold)
            Text(label, fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }

    @Composable
    private fun CardBox(content: @Composable ColumnScope.() -> Unit) {
        Column(
            Modifier.fillMaxWidth().clip(RoundedCornerShape(16.dp)).background(MaterialTheme.colorScheme.surface).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp), content = content
        )
    }
}
