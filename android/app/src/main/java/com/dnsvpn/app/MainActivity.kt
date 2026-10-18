package com.dnsvpn.app

import android.app.Activity
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.dnsvpn.mobile.Mobile
import org.json.JSONObject

class MainActivity : AppCompatActivity() {

    private lateinit var zone: EditText
    private lateinit var psk: EditText
    private lateinit var token: EditText
    private lateinit var candidates: EditText
    private lateinit var toggle: Button
    private lateinit var importLink: Button
    private lateinit var status: TextView

    private val prefs by lazy { getSharedPreferences("dnsvpn", Context.MODE_PRIVATE) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        zone = findViewById(R.id.zone)
        psk = findViewById(R.id.psk)
        token = findViewById(R.id.token)
        candidates = findViewById(R.id.candidates)
        toggle = findViewById(R.id.toggle)
        importLink = findViewById(R.id.importLink)
        status = findViewById(R.id.status)

        zone.setText(prefs.getString("zone", ""))
        psk.setText(prefs.getString("psk", ""))
        token.setText(prefs.getString("token", ""))
        candidates.setText(prefs.getString("candidates", ""))

        toggle.setOnClickListener {
            if (DnsVpnService.isRunning) {
                stopVpn()
            } else {
                save()
                prepareAndStart()
            }
        }
        importLink.setOnClickListener { importFromClipboard() }

        handleLinkIntent(intent)
        refresh()
    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleLinkIntent(intent)
    }

    override fun onResume() {
        super.onResume()
        refresh()
    }

    /** Import a dnsvpn:// link the app was opened with (tapped link / QR). */
    private fun handleLinkIntent(intent: Intent?) {
        val data = intent?.data ?: return
        if (data.scheme == "dnsvpn") applyLink(data.toString())
    }

    private fun importFromClipboard() {
        val cb = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val text = cb.primaryClip?.getItemAt(0)?.coerceToText(this)?.toString()?.trim()
        if (text.isNullOrEmpty() || !text.startsWith("dnsvpn://")) {
            toast("Clipboard has no dnsvpn:// link")
            return
        }
        applyLink(text)
    }

    private fun applyLink(link: String) {
        try {
            val json = JSONObject(Mobile.decodeLink(link))
            zone.setText(json.optString("zone"))
            psk.setText(json.optString("psk"))
            token.setText(json.optString("token"))
            candidates.setText(json.optString("candidates"))
            save()
            toast("Config imported" + (json.optString("name").let { if (it.isNotEmpty()) ": $it" else "" }))
        } catch (t: Throwable) {
            toast("Invalid link: ${t.message}")
        }
    }

    private fun toast(m: String) = Toast.makeText(this, m, Toast.LENGTH_SHORT).show()

    private fun save() {
        prefs.edit()
            .putString("zone", zone.text.toString().trim())
            .putString("psk", psk.text.toString().trim())
            .putString("token", token.text.toString().trim())
            .putString("candidates", candidates.text.toString().trim())
            .apply()
    }

    private fun configJson(): String = JSONObject().apply {
        put("zone", zone.text.toString().trim())
        put("psk", psk.text.toString().trim())
        put("token", token.text.toString().trim())
        put("candidates", candidates.text.toString().trim())
        put("socks", "127.0.0.1:1080")
        put("scan", true)
        put("workers", 128)
        put("max_resolvers", 20)
        put("max_inflight", 6)
        put("query_timeout", "1500ms")
    }.toString()

    private fun prepareAndStart() {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            startActivityForResult(intent, REQ_VPN)
        } else {
            onActivityResult(REQ_VPN, Activity.RESULT_OK, null)
        }
    }

    @Deprecated("deprecated API, fine for a single prepare() flow")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQ_VPN && resultCode == Activity.RESULT_OK) {
            val svc = Intent(this, DnsVpnService::class.java)
                .putExtra("config", configJson())
            startService(svc)
            status.postDelayed({ refresh() }, 800)
        }
    }

    private fun stopVpn() {
        startService(Intent(this, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_STOP))
        status.postDelayed({ refresh() }, 500)
    }

    private fun refresh() {
        val running = DnsVpnService.isRunning
        toggle.text = if (running) "Disconnect" else "Connect"
        status.text = if (running) "connected" else "stopped"
    }

    companion object {
        private const val REQ_VPN = 1001
    }
}
