package com.example.trustshield

import android.os.Bundle
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

/**
 * Test Activity - Minimal test to verify app can launch
 */
class TestActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Simple text view - no complex layouts
        val tv = TextView(this)
        tv.text = "✅ TrustShield App Loaded!\n\nIf you see this, the app framework is working.\n\nVersion: 1.0\nStatus: Ready for testing"
        tv.textSize = 18f
        tv.setPadding(20, 20, 20, 20)
        
        setContentView(tv)
    }
}
