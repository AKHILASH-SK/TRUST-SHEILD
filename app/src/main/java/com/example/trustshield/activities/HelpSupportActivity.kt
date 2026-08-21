package com.example.trustshield.activities

import android.os.Bundle
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import com.example.trustshield.R

class HelpSupportActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_placeholder)

        val toolbar = findViewById<Toolbar>(R.id.toolbar)
        setSupportActionBar(toolbar)
        supportActionBar?.title = "Help & Support"
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        toolbar.setNavigationOnClickListener {
            onBackPressed()
        }

        findViewById<TextView>(R.id.tv_placeholder_title).text = "Help & Support"
        findViewById<TextView>(R.id.tv_placeholder_desc).text = "View FAQs, read documentation, and contact our 24/7 customer support team."
    }
}
