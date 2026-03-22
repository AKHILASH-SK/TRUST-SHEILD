package com.example.trustshield.activities

import android.content.Intent
import android.os.Bundle
import android.widget.Toast
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.example.trustshield.R
import com.example.trustshield.network.RetrofitClient
import com.example.trustshield.network.models.RegisterRequest
import com.google.android.material.button.MaterialButton
import com.google.android.material.textfield.TextInputEditText
import kotlinx.coroutines.launch

/**
 * RegistrationActivity
 * User registration with email, phone, and PIN
 * 
 * Calls backend API: POST /api/auth/register
 * Request: {name, last_name, email, phone_number, pin}
 * Response: {id, name, email, phone_number, created_at}
 */
class RegistrationActivity : AppCompatActivity() {
    
    private var firstNameInput: TextInputEditText? = null
    private var lastNameInput: TextInputEditText? = null
    private var emailInput: TextInputEditText? = null
    private var phoneInput: TextInputEditText? = null
    private var pinInput: TextInputEditText? = null
    private var confirmPinInput: TextInputEditText? = null
    private var registerButton: MaterialButton? = null
    private var backButton: MaterialButton? = null
    private var isLoading = false
    private val TAG = "RegistrationActivity"
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        try {
            setContentView(R.layout.activity_registration)
            Log.d(TAG, "Layout set successfully")
            
            initializeViews()
            setupListeners()
            Log.d(TAG, "RegistrationActivity initialized successfully")
            
        } catch (e: Exception) {
            Log.e(TAG, "onCreate error: ${e.message}", e)
            e.printStackTrace()
            Toast.makeText(this, "Initialization error: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }
    
    private fun initializeViews() {
        try {
            firstNameInput = findViewById(R.id.et_first_name)
            lastNameInput = findViewById(R.id.et_last_name)
            emailInput = findViewById(R.id.et_email)
            phoneInput = findViewById(R.id.et_phone_number)
            pinInput = findViewById(R.id.et_pin)
            confirmPinInput = findViewById(R.id.et_confirm_pin)
            registerButton = findViewById(R.id.btn_register)
            backButton = findViewById(R.id.btn_back)
            
            Log.d(TAG, "Views initialized successfully")
            
        } catch (e: Exception) {
            Log.e(TAG, "initializeViews error: ${e.message}", e)
        }
    }
    
    private fun setupListeners() {
        try {
            registerButton?.setOnClickListener {
                val firstName = firstNameInput?.text?.toString()?.trim() ?: ""
                val lastName = lastNameInput?.text?.toString()?.trim() ?: ""
                val email = emailInput?.text?.toString()?.trim() ?: ""
                val phoneNumber = phoneInput?.text?.toString()?.trim() ?: ""
                val pin = pinInput?.text?.toString()?.trim() ?: ""
                val confirmPin = confirmPinInput?.text?.toString()?.trim() ?: ""
                
                // Validate all inputs
                when {
                    firstName.isEmpty() -> {
                        Toast.makeText(this, "Please enter first name", Toast.LENGTH_SHORT).show()
                        return@setOnClickListener
                    }
                    lastName.isEmpty() -> {
                        Toast.makeText(this, "Please enter last name", Toast.LENGTH_SHORT).show()
                        return@setOnClickListener
                    }
                    email.isEmpty() -> {
                        Toast.makeText(this, "Please enter email", Toast.LENGTH_SHORT).show()
                        return@setOnClickListener
                    }
                    !isValidEmail(email) -> {
                        Toast.makeText(this, "Please enter valid email", Toast.LENGTH_SHORT).show()
                        return@setOnClickListener
                    }
                    phoneNumber.isEmpty() -> {
                        Toast.makeText(this, "Please enter phone number", Toast.LENGTH_SHORT).show()
                        return@setOnClickListener
                    }
                    phoneNumber.length < 10 -> {
                        Toast.makeText(this, "Phone number must be at least 10 digits", Toast.LENGTH_SHORT).show()
                        return@setOnClickListener
                    }
                    pin.isEmpty() -> {
                        Toast.makeText(this, "Please enter PIN", Toast.LENGTH_SHORT).show()
                        return@setOnClickListener
                    }
                    pin.length < 4 || pin.length > 6 -> {
                        Toast.makeText(this, "PIN must be 4-6 digits", Toast.LENGTH_SHORT).show()
                        return@setOnClickListener
                    }
                    pin != confirmPin -> {
                        Toast.makeText(this, "PINs do not match", Toast.LENGTH_SHORT).show()
                        return@setOnClickListener
                    }
                }
                
                Log.d(TAG, "Register attempt for: $firstName $lastName")
                registerUser(firstName, lastName, email, phoneNumber, pin)
            }
            
            backButton?.setOnClickListener {
                Log.d(TAG, "Back button clicked")
                finish()
            }
            
            Log.d(TAG, "Click listeners setup complete")
        } catch (e: Exception) {
            Log.e(TAG, "setupListeners error: ${e.message}", e)
        }
    }
    
    private fun isValidEmail(email: String): Boolean {
        return android.util.Patterns.EMAIL_ADDRESS.matcher(email).matches()
    }
    
    private fun registerUser(firstName: String, lastName: String, email: String, phoneNumber: String, pin: String) {
        if (isLoading) return
        
        isLoading = true
        registerButton?.isEnabled = false
        
        lifecycleScope.launch {
            try {
                Log.d(TAG, "Calling backend API: POST /api/auth/register")
                
                // Create register request
                val registerRequest = RegisterRequest(
                    name = firstName,
                    last_name = lastName,
                    email = email,
                    phone_number = phoneNumber,
                    pin = pin
                )
                
                // Call backend
                val apiService = RetrofitClient.getInstance().getApiService()
                val response = apiService.register(registerRequest)
                
                if (response.isSuccessful && response.body() != null) {
                    val registerResponse = response.body()!!
                    Log.d(TAG, "Registration successful for user: ${registerResponse.name}")
                    
                    Toast.makeText(
                        this@RegistrationActivity, 
                        "Registration successful! Please login with your phone and PIN", 
                        Toast.LENGTH_LONG
                    ).show()
                    
                    // Navigate back to login
                    navigateToLogin()
                    
                } else {
                    // Handle error response
                    val errorMessage = when (response.code()) {
                        400 -> "Email or phone number already registered"
                        422 -> "Invalid input data"
                        500 -> "Server error. Please try again later"
                        else -> "Registration failed: ${response.code()} ${response.message()}"
                    }
                    Log.e(TAG, "Registration failed: $errorMessage")
                    Toast.makeText(this@RegistrationActivity, errorMessage, Toast.LENGTH_SHORT).show()
                }
                
            } catch (e: Exception) {
                Log.e(TAG, "Registration error: ${e.message}", e)
                Toast.makeText(this@RegistrationActivity, "Network error: ${e.message}", Toast.LENGTH_SHORT).show()
                
            } finally {
                isLoading = false
                registerButton?.isEnabled = true
            }
        }
    }
    
    private fun navigateToLogin() {
        try {
            Log.d(TAG, "Navigating back to LoginActivity")
            val intent = Intent(this, LoginActivity::class.java)
            startActivity(intent)
            finish()
        } catch (e: Exception) {
            Log.e(TAG, "navigateToLogin error: ${e.message}", e)
            Toast.makeText(this, "Navigation error: ${e.message}", Toast.LENGTH_SHORT).show()
        }
    }
}
