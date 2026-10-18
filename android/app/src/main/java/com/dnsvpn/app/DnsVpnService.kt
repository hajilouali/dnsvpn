package com.dnsvpn.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import mobile.Mobile
import mobile.Protector

/**
 * Captures device traffic into a TUN and hands its file descriptor to the Go core
 * (mobile.aar), which runs the DNS tunnel + a userspace TCP/IP stack. The Protector
 * callback lets the Go client's own resolver sockets bypass this VPN.
 */
class DnsVpnService : VpnService(), Protector {

    private var tun: ParcelFileDescriptor? = null
    @Volatile private var worker: Thread? = null

    override fun protect(fd: Long): Boolean = protect(fd.toInt())

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            shutdown()
            return START_NOT_STICKY
        }
        val config = intent?.getStringExtra("config")
        if (config.isNullOrEmpty()) {
            shutdown()
            return START_NOT_STICKY
        }
        startForegroundSafe()
        startTunnel(config)
        return START_STICKY
    }

    private fun startTunnel(config: String) {
        if (isRunning) return
        val builder = Builder()
            .setSession("dnsvpn")
            .setMtu(MTU)
            .addAddress("10.0.0.2", 32)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("1.1.1.1")
        try {
            builder.setMetered(false)
        } catch (_: Throwable) { /* older APIs */ }

        val pfd = builder.establish() ?: run {
            Log.e(TAG, "establish() returned null (VPN not prepared?)")
            shutdown()
            return
        }
        tun = pfd
        val fd = pfd.fd.toLong()
        worker = Thread {
            try {
                Mobile.start(config, fd, MTU.toLong(), this)
                isRunning = true
            } catch (t: Throwable) {
                Log.e(TAG, "Mobile.start failed", t)
                shutdown()
            }
        }.also { it.start() }
    }

    private fun shutdown() {
        try {
            if (isRunning) Mobile.stop()
        } catch (t: Throwable) {
            Log.e(TAG, "Mobile.stop", t)
        }
        isRunning = false
        try { tun?.close() } catch (_: Throwable) {}
        tun = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        shutdown()
        super.onDestroy()
    }

    private fun startForegroundSafe() {
        val channelId = "dnsvpn"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(
                NotificationChannel(channelId, "dnsvpn", NotificationManager.IMPORTANCE_LOW)
            )
        }
        val n: Notification = Notification.Builder(this, channelId)
            .setContentTitle("dnsvpn")
            .setContentText("Tunnel active")
            .setSmallIcon(android.R.drawable.stat_sys_vpn_ic)
            .build()
        startForeground(1, n)
    }

    companion object {
        private const val TAG = "dnsvpn"
        private const val MTU = 1500
        const val ACTION_STOP = "com.dnsvpn.app.STOP"
        @Volatile var isRunning = false
            private set
    }
}
