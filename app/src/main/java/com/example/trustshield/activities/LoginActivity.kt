package com.example.trustshield.activities

import android.content.Intent
import android.os.Bundle
import android.widget.Toast
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.example.trustshield.R
import com.example.trustshield.network.RetrofitClient
import com.example.trustshield.network.models.LoginRequest
import com.google.android.material.button.MaterialButton
import com.google.android.material.textfield.TextInputEditText
import kotlinx.coroutines.launch

/**
 * LoginActivity
 * User authentication with phone number and PIN
 * 
 * Calls backend API: POST /api/auth/login
 * Request: {phone_number, pin}
 * Response: {id, name, email, phone_number, message}
 */
class LoginActivity : AppCompatActivity() {
    
    private var phoneInput: TextInputEditText? = null
    private var pinInput: TextInputEditText? = null
    private var loginButton: MaterialButton? = null
    private var registerButton: MaterialButton? = null
    private var isLoading = false
    private val TAG = "LoginActivity"
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        try {
            setContentView(R.layout.activity_login)
            Log.d(TAG, "Layout set successfully")
            
            initializeViews()
            setupListeners()
            Log.d(TAG, "LoginActivity initialized successfully")
            
        } catch (e: Exception) {
            Log.e(TAG, "onCreate error: ${e.message}", e)
            e.printStackTrace()
            Toast.makeText(this, "Initialization error: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }
    
    private fun initializeViews() {
        try {
            phoneInput = findViewById(R.id.et_phone_number)
            pinInput = findViewById(R.id.et_pin) // Assuming PIN field exists
            loginButton = findViewById(R.id.btn_login)
            registerButton = findViewById(R.id.btn_register) // Assuming register button exists
            
            Log.d(TAG, "Views initialized: phone=${phoneInput != null}, pin=${pinInput != null}, login=${loginButton != null}, register=${registerButton != null}")
            
        } catch (e: Exception) {
            Log.e(TAG, "initializeViews error: ${e.message}", e)
        }
    }
    
    private fun setupListeners() {
        try {
            loginButton?.setOnClickListener {
                val phoneNumber = phoneInput?.text?.toString()?.trim() ?: ""
                val pin = pinInput?.text?.toString()?.trim() ?: ""
                
                // Validate inputs
                if (phoneNumber.isEmpty()) {
                    Toast.makeText(this, "Please enter phone number", Toast.LENGTH_SHORT).show()
                    return@setOnClickListener
                }
                
                if (pin.isEmpty()) {
                    Toast.makeText(this, "Please enter PIN", Toast.LENGTH_SHORT).show()
                    return@setOnClickListener
                }
                
                if (pin.length != 4 && pin.length != 5 && pin.length != 6) {
                    Toast.makeText(this, "PIN must be 4-6 digits", Toast.LENGTH_SHORT).show()
                    return@setOnClickListener
                }
                
                Log.d(TAG, "Login attempt for phone: $phoneNumber")
                loginUser(phoneNumber, pin)
            }
            
            registerButton?.setOnClickListener {
                Log.d(TAG, "Navigate to registration")
                navigateToRegistration()
            }
            
            Log.d(TAG, "Click listeners setup complete")
        } catch (e: Exception) {
            Log.e(TAG, "setupListeners error: ${e.message}", e)
        }
    }
    
    private fun loginUser(phoneNumber: String, pin: String) {
        if (isLoading) return
        
        isLoading = true
        loginButton?.isEnabled = false
        
        lifecycleScope.launch {
            try {
                Log.d(TAG, "Calling backend API: POST /api/auth/login")
                
                // Create login request
                val loginRequest = LoginRequest(
                    phone_number = phoneNumber,
                    pin = pin
                )
                
                // Call backend
                val apiService = RetrofitClient.getInstance().getApiService()
                val response = apiService.login(loginRequest)
                
                if (response.isSuccessful && response.body() != null) {
                    val loginResponse = response.body()!!
                    Log.d(TAG, "Login successful for user: ${loginResponse.name}")
                    
                    // Save user data to SharedPreferences
                    saveUserData(loginResponse.id, loginResponse.name, loginResponse.email, loginResponse.phone_number)
                    
                    Toast.makeText(this@LoginActivity, "Login successful! Welcome ${loginResponse.name}", Toast.LENGTH_SHORT).show()
                    navigateToHome()
                    
                } else {
                    // Handle error response
                    val errorMessage = when (response.code()) {
                        401 -> "Invalid phone number or PIN"
                        400 -> "Missing required fields"
                        404 -> "User not found"
                        500 -> "Server error. Please try again later"
                        else -> "Login failed: ${response.code()} ${response.message()}"
                    }
                    Log.e(TAG, "Login failed: $errorMessage")
                    Toast.makeText(this@LoginActivity, errorMessage, Toast.LENGTH_SHORT).show()
                }
                
            } catch (e: Exception) {
                Log.e(TAG, "Login error: ${e.message}", e)
                Toast.makeText(this@LoginActivity, "Network error: ${e.message}", Toast.LENGTH_SHORT).show()
                
            } finally {
                isLoading = false
                loginButton?.isEnabled = true
            }
        }
    }
    
    private fun saveUserData(userId: Int, name: String, email: String, phoneNumber: String) {
        try {
            val sharedPref = getSharedPreferences("trustshield_prefs", MODE_PRIVATE)
            with(sharedPref.edit()) {
                putInt("user_id", userId)
                putString("user_name", name)
                putString("user_email", email)
                putString("user_phone", phoneNumber)
                putBoolean("is_logged_in", true)
                apply()
            }
            Log.d(TAG, "User data saved to SharedPreferences")
        } catch (e: Exception) {
            Log.e(TAG, "Error saving user data: ${e.message}", e)
        }
    }
    
    private fun navigateToHome() {
        try {
            Log.d(TAG, "Navigating to HomeActivity")
            val intent = Intent(this, HomeActivity::class.java)
            startActivity(intent)
            finish()
        } catch (e: Exception) {
            Log.e(TAG, "navigateToHome error: ${e.message}", e)
            Toast.makeText(this, "Navigation error: ${e.message}", Toast.LENGTH_SHORT).show()
        }
    }
    
    private fun navigateToRegistration() {
        try {
            Log.d(TAG, "Navigating to RegistrationActivity")
            val intent = Intent(this, RegistrationActivity::class.java)
            startActivity(intent)
        } catch (e: Exception) {
            Log.e(TAG, "navigateToRegistration error: ${e.message}", e)
            Toast.makeText(this, "Navigation error: ${e.message}", Toast.LENGTH_SHORT).show()
        }
    }
}
