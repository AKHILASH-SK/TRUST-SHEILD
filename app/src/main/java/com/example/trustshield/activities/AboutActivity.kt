package com.example.trustshield.activities

import android.os.Bundle
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import com.example.trustshield.R

class AboutActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_placeholder)

        val toolbar = findViewById<Toolbar>(R.id.toolbar)
        setSupportActionBar(toolbar)
        supportActionBar?.title = "About TrustShield"
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        toolbar.setNavigationOnClickListener {
            onBackPressed()
        }

        findViewById<TextView>(R.id.tv_placeholder_title).text = "About TrustShield"
        findViewById<TextView>(R.id.tv_placeholder_desc).text = "TrustShield v1.0.0\n\nThe ultimate AI-powered security companion protecting you from malicious links, phishing, and malware."
    }
}
