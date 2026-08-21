package com.example.trustshield.activities

import android.os.Bundle
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import com.example.trustshield.R

class SecurityPrivacyActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_placeholder)

        val toolbar = findViewById<Toolbar>(R.id.toolbar)
        setSupportActionBar(toolbar)
        supportActionBar?.title = "Security & Privacy"
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        toolbar.setNavigationOnClickListener {
            onBackPressed()
        }

        findViewById<TextView>(R.id.tv_placeholder_title).text = "Security & Privacy"
        findViewById<TextView>(R.id.tv_placeholder_desc).text = "Configure your encryption settings, data sharing preferences, and two-factor authentication."
    }
}
