package com.dnsvpn.app

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import org.json.JSONObject

class MainActivity : AppCompatActivity() {

    private lateinit var zone: EditText
    private lateinit var psk: EditText
    private lateinit var token: EditText
    private lateinit var candidates: EditText
    private lateinit var toggle: Button
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
        refresh()
    }

    override fun onResume() {
        super.onResume()
        refresh()
    }

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
