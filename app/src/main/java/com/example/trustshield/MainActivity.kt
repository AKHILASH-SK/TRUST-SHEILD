package com.example.trustshield

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.material3.MaterialTheme
import com.example.trustshield.ui.theme.TrustShieldTheme
import android.util.Log

class MainActivity : ComponentActivity() {
    
    private lateinit var permissionManager: PermissionManager
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Initialize permission manager
        permissionManager = PermissionManager(this)
        
        // Request notification permission for Android 13+
        permissionManager.requestNotificationPermission(this)
        
        Log.d("MAIN", "MainActivity created and permission requested")
        
        enableEdgeToEdge()
        setContent {
            TrustShieldTheme {
                Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
                    MainScreen(
                        modifier = Modifier.padding(innerPadding)
                    )
                }
            }
        }
    }
}

@Composable
fun MainScreen(modifier: Modifier = Modifier) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(16.dp)
    ) {
        Text(
            text = "TrustShield",
            style = MaterialTheme.typography.headlineLarge
        )
        
        Spacer(modifier = Modifier.height(8.dp))
        
        Text(
            text = "Security & Phishing Protection",
            style = MaterialTheme.typography.headlineSmall
        )
        
        Spacer(modifier = Modifier.height(16.dp))
        
        Text(
            text = "What TrustShield Does:",
            style = MaterialTheme.typography.bodyLarge
        )
        
        Text(
            text = "• Monitors incoming messages for phishing links\n" +
                    "• Detects suspicious content from unknown numbers\n" +
                    "• Alerts you to potential security threats",
            style = MaterialTheme.typography.bodyMedium
        )
        
        Spacer(modifier = Modifier.height(16.dp))
        
        Text(
            text = "Privacy & Security:",
            style = MaterialTheme.typography.bodyLarge
        )
        
        Text(
            text = "• We analyze only for security threats\n" +
                    "• Your personal messages are NOT stored\n" +
                    "• Data is processed locally on your device\n" +
                    "• No data is shared with third parties",
            style = MaterialTheme.typography.bodyMedium
        )
        
        Spacer(modifier = Modifier.height(16.dp))
        
        Text(
            text = "How to Enable:\n" +
                    "1. Go to Settings > Apps & Notifications\n" +
                    "2. Find Special App Access > Device and App Notifications\n" +
                    "3. Enable TrustShield\n" +
                    "4. Allow TrustShield to send notifications",
            style = MaterialTheme.typography.bodySmall
        )
    }
}

@Preview(showBackground = true)
@Composable
fun MainScreenPreview() {
    TrustShieldTheme {
        MainScreen()
    }
}