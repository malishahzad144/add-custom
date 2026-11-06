package com.adshield

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import java.io.ByteArrayOutputStream
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * Local-only DNS VPN. Only the virtual DNS address is routed into the tunnel, so all other traffic
 * bypasses the VPN completely. Ad domains get an empty (0.0.0.0 / ::) answer; every other DNS query
 * is forwarded unchanged to Cloudflare / Google public DNS (no extra filtering).
 */
class AdShieldVpnService : VpnService() {
    companion object {
        const val ACTION_START = "com.adshield.START"
        const val ACTION_STOP = "com.adshield.STOP"
        private const val CH = "adshield"
        private const val VPN_ADDR = "10.111.222.1"
        private const val VPN_DNS = "10.111.222.2"
        private val UPSTREAMS = arrayOf(
            byteArrayOf(1, 1, 1, 1),
            byteArrayOf(8, 8, 8, 8)
        )
    }

    private var tun: ParcelFileDescriptor? = null
    private var worker: Thread? = null
    private var pool: ExecutorService? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopShield()
            return START_NOT_STICKY
        }
        startForeground(1, notification())
        startShield()
        return START_STICKY
    }

    private fun notification(): Notification {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CH, "AdShield status", NotificationManager.IMPORTANCE_LOW))
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val stop = PendingIntent.getService(
            this, 1, Intent(this, AdShieldVpnService::class.java).setAction(ACTION_STOP), PendingIntent.FLAG_IMMUTABLE
        )
        return Notification.Builder(this, CH)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle("AdShield is active")
            .setContentText("Blocking ad servers")
            .setContentIntent(open)
            .setOngoing(true)
            .addAction(Notification.Action.Builder(null, "Stop", stop).build())
            .build()
    }

    private fun startShield() {
        if (tun != null) return
        ShieldState.init(this)
        val fd: ParcelFileDescriptor
        try {
            fd = Builder().setSession("AdShield").setMtu(1500)
                .addAddress(VPN_ADDR, 32).addDnsServer(VPN_DNS).addRoute(VPN_DNS, 32)
                .setBlocking(true).establish() ?: throw IOException("VPN permission was not granted")
        } catch (e: Exception) {
            ShieldState.error.value = "Could not start: ${e.message}"
            stopShield()
            return
        }
        tun = fd
        ShieldState.error.value = null
        ShieldState.running.value = true
        val p = Executors.newFixedThreadPool(6)
        pool = p
        worker = Thread({
            try {
                Blocklist.load(this)
                val input = FileInputStream(fd.fileDescriptor)
                val output = FileOutputStream(fd.fileDescriptor)
                val buf = ByteArray(32767)
                while (!Thread.currentThread().isInterrupted) {
                    val n = input.read(buf)
                    if (n < 0) break
                    if (n < 28) continue
                    val pkt = buf.copyOf(n)
                    p.execute { try { handle(pkt, output) } catch (_: Exception) {} }
                }
            } catch (e: Exception) {
                if (ShieldState.running.value) ShieldState.error.value = "Stopped: ${e.message}"
            } finally {
                ShieldState.running.value = false
            }
        }, "adshield-tun")
        worker!!.start()
    }

    private fun stopShield() {
        worker?.interrupt(); worker = null
        pool?.shutdownNow(); pool = null
        try { tun?.close() } catch (_: IOException) {}
        tun = null
        ShieldState.running.value = false
        ShieldState.persist()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onRevoke() { stopShield() }
    override fun onDestroy() { stopShield(); super.onDestroy() }

    private fun u16(b: ByteArray, o: Int) = ((b[o].toInt() and 0xFF) shl 8) or (b[o + 1].toInt() and 0xFF)

    private fun handle(p: ByteArray, out: FileOutputStream) {
        if ((p[0].toInt() shr 4) != 4) return
        val ihl = (p[0].toInt() and 0x0F) * 4
        if (p[9].toInt() == 6) { rstTcp(p, ihl, out); return }
        if (p[9].toInt() != 17 || p.size < ihl + 8) return
        if (u16(p, ihl + 2) != 53) return
        val srcPort = u16(p, ihl)
        val total = minOf(u16(p, 2), p.size)
        val dnsOff = ihl + 8
        if (total - dnsOff < 17) return
        val q = p.copyOfRange(dnsOff, total)
        val src = p.copyOfRange(12, 16)
        val dst = p.copyOfRange(16, 20)

        val parsed = parseQuestion(q)
        if (parsed == null) { forward(q, src, dst, srcPort, out); return }
        val isBlocked = Blocklist.isBlocked(parsed.name)
        ShieldState.record(parsed.name, isBlocked)
        if (isBlocked) {
            ShieldState.count(true)
            write(out, dst, src, 53, srcPort, blockedReply(q, parsed.qtype, parsed.qend))
        } else {
            ShieldState.count(false)
            forward(q, src, dst, srcPort, out)
        }
    }

    /** Refuse TCP (e.g. DNS-over-TLS on port 853) immediately so Android falls back to plain DNS. */
    private fun rstTcp(p: ByteArray, ihl: Int, out: FileOutputStream) {
        if (p.size < ihl + 20) return
        val flags = p[ihl + 13].toInt()
        if ((flags and 0x02) == 0 || (flags and 0x10) != 0) return // only a bare SYN
        val seq = ((p[ihl + 4].toLong() and 0xFF) shl 24) or ((p[ihl + 5].toLong() and 0xFF) shl 16) or
            ((p[ihl + 6].toLong() and 0xFF) shl 8) or (p[ihl + 7].toLong() and 0xFF)
        val ack = (seq + 1) and 0xFFFFFFFFL
        val b = ByteArray(40)
        b[0] = 0x45; b[3] = 40; b[6] = 0x40; b[8] = 64; b[9] = 6
        System.arraycopy(p, 16, b, 12, 4)
        System.arraycopy(p, 12, b, 16, 4)
        var sum = 0
        for (i in 0 until 20 step 2) sum += u16(b, i)
        while (sum shr 16 != 0) sum = (sum and 0xFFFF) + (sum shr 16)
        val ipck = sum.inv() and 0xFFFF
        b[10] = (ipck shr 8).toByte(); b[11] = ipck.toByte()
        b[20] = p[ihl + 2]; b[21] = p[ihl + 3]; b[22] = p[ihl]; b[23] = p[ihl + 1]
        b[28] = (ack shr 24).toByte(); b[29] = (ack shr 16).toByte(); b[30] = (ack shr 8).toByte(); b[31] = ack.toByte()
        b[32] = 0x50; b[33] = 0x14
        var t = 0
        for (i in 12 until 20 step 2) t += u16(b, i)
        t += 6 + 20
        for (i in 20 until 40 step 2) t += u16(b, i)
        while (t shr 16 != 0) t = (t and 0xFFFF) + (t shr 16)
        val tck = t.inv() and 0xFFFF
        b[36] = (tck shr 8).toByte(); b[37] = tck.toByte()
        synchronized(out) { out.write(b) }
    }

    private class Question(val name: String, val qtype: Int, val qend: Int)

    private fun parseQuestion(q: ByteArray): Question? {
        if (u16(q, 4) != 1) return null
        var i = 12
        val sb = StringBuilder()
        while (i < q.size) {
            val len = q[i].toInt() and 0xFF
            if (len == 0) { i++; break }
            if (len >= 0xC0 || i + len + 1 > q.size) return null
            if (sb.isNotEmpty()) sb.append('.')
            for (k in 1..len) sb.append((q[i + k].toInt() and 0xFF).toChar())
            i += len + 1
        }
        if (i + 4 > q.size) return null
        return Question(sb.toString(), u16(q, i), i + 4)
    }

    private fun blockedReply(q: ByteArray, qtype: Int, qend: Int): ByteArray {
        val o = ByteArrayOutputStream()
        val answer = qtype == 1 || qtype == 28
        o.write(q, 0, 2)
        o.write(byteArrayOf(0x81.toByte(), 0x80.toByte(), 0, 1, 0, if (answer) 1 else 0, 0, 0, 0, 0))
        o.write(q, 12, qend - 12)
        if (answer) {
            val len = if (qtype == 1) 4 else 16
            o.write(byteArrayOf(0xC0.toByte(), 0x0C, 0, qtype.toByte(), 0, 1, 0, 0, 0, 60, 0, len.toByte()))
            o.write(ByteArray(len))
        }
        return o.toByteArray()
    }

    private fun forward(q: ByteArray, src: ByteArray, dst: ByteArray, srcPort: Int, out: FileOutputStream) {
        for (up in UPSTREAMS) {
            try {
                DatagramSocket().use { s ->
                    protect(s)
                    s.soTimeout = 4000
                    s.send(DatagramPacket(q, q.size, InetAddress.getByAddress(up), 53))
                    val rb = ByteArray(4096)
                    val rp = DatagramPacket(rb, rb.size)
                    s.receive(rp)
                    write(out, dst, src, 53, srcPort, rb.copyOf(rp.length))
                }
                return
            } catch (_: IOException) { /* try next upstream */ }
        }
    }

    private fun write(out: FileOutputStream, srcIp: ByteArray, dstIp: ByteArray, sp: Int, dp: Int, payload: ByteArray) {
        val len = 28 + payload.size
        val b = ByteArray(len)
        b[0] = 0x45
        b[2] = (len shr 8).toByte(); b[3] = len.toByte()
        b[6] = 0x40; b[8] = 64; b[9] = 17
        System.arraycopy(srcIp, 0, b, 12, 4)
        System.arraycopy(dstIp, 0, b, 16, 4)
        var sum = 0
        for (i in 0 until 20 step 2) sum += u16(b, i)
        while (sum shr 16 != 0) sum = (sum and 0xFFFF) + (sum shr 16)
        val ck = sum.inv() and 0xFFFF
        b[10] = (ck shr 8).toByte(); b[11] = ck.toByte()
        b[20] = (sp shr 8).toByte(); b[21] = sp.toByte()
        b[22] = (dp shr 8).toByte(); b[23] = dp.toByte()
        val ul = 8 + payload.size
        b[24] = (ul shr 8).toByte(); b[25] = ul.toByte()
        System.arraycopy(payload, 0, b, 28, payload.size)
        synchronized(out) { out.write(b) }
    }
}
