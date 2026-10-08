package com.example.trustshield.activities

import android.content.Intent
import android.os.Bundle
import android.text.Html
import android.text.method.PasswordTransformationMethod
import android.util.Log
import android.view.View
import android.widget.EditText
import android.widget.ImageView
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.example.trustshield.R
import com.example.trustshield.network.AuthStore
import com.example.trustshield.network.RetrofitClient
import com.example.trustshield.network.models.LoginRequest
import com.google.android.material.button.MaterialButton
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

    private var phoneInput: EditText? = null
    private var pinInput: EditText? = null
    private var loginButton: MaterialButton? = null
    private var registerButton: MaterialButton? = null
    private var progressBar: ProgressBar? = null
    private var togglePinButton: ImageView? = null
    private var countryCodeButton: View? = null
    private var countryCodeText: TextView? = null
    private var footerTermsText: TextView? = null

    private var isPinVisible = false
    private var selectedCountryCode = "+91"
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
            Toast.makeText(this, "Initialization error: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }

    private fun initializeViews() {
        try {
            phoneInput = findViewById(R.id.et_phone_number)
            pinInput = findViewById(R.id.et_pin)
            loginButton = findViewById(R.id.btn_login)
            registerButton = findViewById(R.id.btn_register)
            progressBar = findViewById(R.id.progress_bar)
            togglePinButton = findViewById(R.id.iv_toggle_pin)
            countryCodeButton = findViewById(R.id.btn_country_code)
            countryCodeText = findViewById(R.id.tv_country_code)
            footerTermsText = findViewById(R.id.tv_footer_terms)

            // Format footer with HTML underline for Terms and Privacy
            val footerHtml = "Secured by TrustShield Neural Protocol. By verifying,<br>you agree to the <u>Terms of Service</u> &amp; <u>Privacy Policy</u>."
            footerTermsText?.text = Html.fromHtml(footerHtml, Html.FROM_HTML_MODE_LEGACY)

            Log.d(TAG, "Views initialized successfully")
        } catch (e: Exception) {
            Log.e(TAG, "initializeViews error: ${e.message}", e)
        }
    }

    private fun setupListeners() {
        try {
            // Password visibility toggle
            togglePinButton?.setOnClickListener {
                isPinVisible = !isPinVisible
                if (isPinVisible) {
                    pinInput?.transformationMethod = null
                    togglePinButton?.setImageResource(R.drawable.ic_visibility)
                } else {
                    pinInput?.transformationMethod = PasswordTransformationMethod.getInstance()
                    togglePinButton?.setImageResource(R.drawable.ic_visibility_off)
                }
                pinInput?.setSelection(pinInput?.text?.length ?: 0)
            }

            // Country code selector dialog
            countryCodeButton?.setOnClickListener {
                showCountryCodePicker()
            }

            // Login / Authorize button
            loginButton?.setOnClickListener {
                val rawPhone = phoneInput?.text?.toString()?.trim() ?: ""
                val pin = pinInput?.text?.toString()?.trim() ?: ""

                if (rawPhone.isEmpty()) {
                    Toast.makeText(this, "Please enter phone number", Toast.LENGTH_SHORT).show()
                    return@setOnClickListener
                }

                if (pin.isEmpty()) {
                    Toast.makeText(this, "Please enter PIN", Toast.LENGTH_SHORT).show()
                    return@setOnClickListener
                }

                if (pin.length < 4 || pin.length > 6) {
                    Toast.makeText(this, "PIN must be 4-6 digits", Toast.LENGTH_SHORT).show()
                    return@setOnClickListener
                }

                Log.d(TAG, "Login attempt for phone: $rawPhone")
                loginUser(rawPhone, pin)
            }

            // Create Account / Register button
            registerButton?.setOnClickListener {
                Log.d(TAG, "Navigate to registration")
                navigateToRegistration()
            }

            // Footer terms click
            footerTermsText?.setOnClickListener {
                Toast.makeText(this, "TrustShield Neural Protocol v2.4 • Active", Toast.LENGTH_SHORT).show()
            }

            Log.d(TAG, "Click listeners setup complete")
        } catch (e: Exception) {
            Log.e(TAG, "setupListeners error: ${e.message}", e)
        }
    }

    private fun showCountryCodePicker() {
        val items = arrayOf(
            "United States (US +1)",
            "India (IN +91)",
            "United Kingdom (UK +44)",
            "Canada (CA +1)",
            "Australia (AU +61)",
            "Singapore (SG +65)",
            "UAE (AE +971)"
        )
        val codes = arrayOf("US +1", "IN +91", "UK +44", "CA +1", "AU +61", "SG +65", "AE +971")

        AlertDialog.Builder(this)
            .setTitle("Select Country Code")
            .setItems(items) { _, which ->
                val display = codes[which]
                countryCodeText?.text = display
                selectedCountryCode = display.substringAfter("+").let { "+$it" }
            }
            .show()
    }

    private fun loginUser(phoneNumber: String, pin: String) {
        if (isLoading) return

        isLoading = true
        loginButton?.isEnabled = false
        loginButton?.text = ""
        progressBar?.visibility = View.VISIBLE

        lifecycleScope.launch {
            try {
                Log.d(TAG, "Calling backend API: POST /api/auth/login")

                val loginRequest = LoginRequest(
                    phone_number = phoneNumber,
                    pin = pin
                )

                val apiService = RetrofitClient.getInstance().getApiService()
                var response = apiService.login(loginRequest)

                // If user registered with country code prefix and raw entry fails, attempt with selected code prefix
                if (!response.isSuccessful && !phoneNumber.startsWith("+")) {
                    val altPhone = "$selectedCountryCode$phoneNumber"
                    try {
                        val altResponse = apiService.login(LoginRequest(phone_number = altPhone, pin = pin))
                        if (altResponse.isSuccessful) {
                            response = altResponse
                        }
                    } catch (_: Exception) {
                        // Keep primary response error
                    }
                }

                if (response.isSuccessful && response.body() != null) {
                    val loginResponse = response.body()!!
                    Log.d(TAG, "Login successful for user: ${loginResponse.name}")

                    saveUserData(loginResponse.id, loginResponse.name, loginResponse.email, loginResponse.phone_number)
                    AuthStore.saveToken(this@LoginActivity, loginResponse.token)

                    Toast.makeText(this@LoginActivity, "Login successful! Welcome ${loginResponse.name}", Toast.LENGTH_SHORT).show()
                    navigateToHome()
                } else {
                    val errorMessage = when (response.code()) {
                        401 -> "Invalid phone number or PIN"
                        429 -> "Too many attempts. Try again in a few minutes"
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
                loginButton?.text = "AUTHORIZE & CONTINUE"
                progressBar?.visibility = View.GONE
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
            val permissionManager = com.example.trustshield.PermissionManager(this)
            if (!permissionManager.hasNotificationListenerAccess()) {
                Log.d(TAG, "Navigating to PermissionActivity")
                val intent = Intent(this, PermissionActivity::class.java)
                startActivity(intent)
                finish()
            } else {
                Log.d(TAG, "Navigating to HomeActivity")
                val intent = Intent(this, HomeActivity::class.java)
                startActivity(intent)
                finish()
            }
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
