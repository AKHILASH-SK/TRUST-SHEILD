package com.example.trustshield.activities

import android.content.Intent
import android.os.Bundle
import android.provider.Settings
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.example.trustshield.PermissionManager
import com.example.trustshield.R
import com.google.android.material.button.MaterialButton

class PermissionActivity : AppCompatActivity() {

    private lateinit var permissionManager: PermissionManager
    private var isReturningFromSettings = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_permission)

        permissionManager = PermissionManager(this)

        val btnEnable = findViewById<MaterialButton>(R.id.btn_enable_permission)
        val btnSkip = findViewById<MaterialButton>(R.id.btn_skip_for_now)

        btnEnable.setOnClickListener {
            // Open Android Notification Listener Settings
            val intent = Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)
            startActivity(intent)
            isReturningFromSettings = true
            Toast.makeText(this, "Please enable TrustShield to proceed", Toast.LENGTH_LONG).show()
        }

        btnSkip.setOnClickListener {
            navigateToHome()
        }
    }

    override fun onResume() {
        super.onResume()
        // If the user came back from settings, check if they granted the permission
        if (isReturningFromSettings) {
            if (permissionManager.hasNotificationListenerAccess()) {
                Toast.makeText(this, "Permission Granted!", Toast.LENGTH_SHORT).show()
                navigateToHome()
            } else {
                Toast.makeText(this, "Permission not granted yet", Toast.LENGTH_SHORT).show()
                isReturningFromSettings = false
            }
        }
    }

    private fun navigateToHome() {
        startActivity(Intent(this, HomeActivity::class.java))
        finish()
    }
}
