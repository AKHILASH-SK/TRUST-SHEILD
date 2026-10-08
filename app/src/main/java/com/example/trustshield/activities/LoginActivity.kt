package com.example.trustshield.activities

import android.content.Intent
import android.os.Bundle
import android.text.SpannableString
import android.text.Spanned
import android.text.method.LinkMovementMethod
import android.text.method.PasswordTransformationMethod
import android.text.style.ClickableSpan
import android.text.style.ForegroundColorSpan
import android.text.style.UnderlineSpan
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
 * Styled according to the TrustShield modern neural authentication design system.
 * Calls backend API: POST /api/auth/login
 * Request: {phone_number, pin}
 * Response: {id, name, email, phone_number, message}
 */
class LoginActivity : AppCompatActivity() {

    private var phoneInput: EditText? = null
    private var pinInput: EditText? = null
    private var loginButton: MaterialButton? = null
    private var registerButton: TextView? = null
    private var progressBar: ProgressBar? = null
    private var tvCountryCode: TextView? = null
    private var llCountryCode: View? = null
    private var ivTogglePin: ImageView? = null
    private var tvFooterSecurity: TextView? = null

    private var isPinVisible = false
    private var isLoading = false
    private val TAG = "LoginActivity"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        try {
            setContentView(R.layout.activity_login)
            Log.d(TAG, "Layout set successfully")

            initializeViews()
            setupListeners()
            setupFooterSpannable()
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
            pinInput = findViewById(R.id.et_pin)
            loginButton = findViewById(R.id.btn_login)
            registerButton = findViewById(R.id.btn_register)
            progressBar = findViewById(R.id.progress_bar)
            tvCountryCode = findViewById(R.id.tv_country_code)
            llCountryCode = findViewById(R.id.ll_country_code)
            ivTogglePin = findViewById(R.id.iv_toggle_pin)
            tvFooterSecurity = findViewById(R.id.tv_footer_security)

            Log.d(TAG, "Views initialized successfully")
        } catch (e: Exception) {
            Log.e(TAG, "initializeViews error: ${e.message}", e)
        }
    }

    private fun setupListeners() {
        try {
            // Country Code Picker Dialog
            llCountryCode?.setOnClickListener {
                showCountryCodePicker()
            }

            // PIN Visibility Toggle
            ivTogglePin?.setOnClickListener {
                togglePinVisibility()
            }

            // Authorize & Continue Action
            loginButton?.setOnClickListener {
                val rawPhone = phoneInput?.text?.toString()?.trim() ?: ""
                val pin = pinInput?.text?.toString()?.trim() ?: ""

                // Validate phone number
                if (rawPhone.isEmpty()) {
                    Toast.makeText(this, "Please enter your phone number", Toast.LENGTH_SHORT).show()
                    return@setOnClickListener
                }

                // Clean phone number (strip spaces, hyphens, parentheses)
                val sanitizedPhone = rawPhone.replace(Regex("[^0-9+]"), "")
                if (sanitizedPhone.isEmpty()) {
                    Toast.makeText(this, "Please enter a valid phone number", Toast.LENGTH_SHORT).show()
                    return@setOnClickListener
                }

                // Validate PIN
                if (pin.isEmpty()) {
                    Toast.makeText(this, "Please enter your PIN", Toast.LENGTH_SHORT).show()
                    return@setOnClickListener
                }

                if (pin.length < 4 || pin.length > 6) {
                    Toast.makeText(this, "PIN must be 4-6 digits", Toast.LENGTH_SHORT).show()
                    return@setOnClickListener
                }

                Log.d(TAG, "Login attempt for phone: $sanitizedPhone")
                loginUser(sanitizedPhone, pin)
            }

            // Account Registration Navigation
            registerButton?.setOnClickListener {
                Log.d(TAG, "Navigate to registration")
                navigateToRegistration()
            }

            Log.d(TAG, "Click listeners setup complete")
        } catch (e: Exception) {
            Log.e(TAG, "setupListeners error: ${e.message}", e)
        }
    }

    private fun showCountryCodePicker() {
        val countryOptions = arrayOf(
            "US +1 (United States)",
            "IN +91 (India)",
            "UK +44 (United Kingdom)",
            "CA +1 (Canada)",
            "AU +61 (Australia)",
            "SG +65 (Singapore)",
            "AE +971 (UAE)",
            "DE +49 (Germany)"
        )
        val shortCodes = arrayOf("US +1", "IN +91", "UK +44", "CA +1", "AU +61", "SG +65", "AE +971", "DE +49")

        AlertDialog.Builder(this)
            .setTitle("Select Country Code")
            .setItems(countryOptions) { _, which ->
                tvCountryCode?.text = shortCodes[which]
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun togglePinVisibility() {
        isPinVisible = !isPinVisible
        if (isPinVisible) {
            pinInput?.transformationMethod = null
            ivTogglePin?.setImageResource(R.drawable.ic_visibility_eye)
            ivTogglePin?.setColorFilter(0xFF0066FF.toInt())
        } else {
            pinInput?.transformationMethod = PasswordTransformationMethod.getInstance()
            ivTogglePin?.setImageResource(R.drawable.ic_visibility_off_eye)
            ivTogglePin?.setColorFilter(0xFF94A3B8.toInt())
        }
        pinInput?.text?.let { pinInput?.setSelection(it.length) }
    }

    private fun setupFooterSpannable() {
        val fullText = "Secured by TrustShield Neural Protocol. By verifying,\nyou agree to the Terms of Service & Privacy Policy."
        val spannable = SpannableString(fullText)

        val termsStart = fullText.indexOf("Terms of Service")
        if (termsStart != -1) {
            val termsEnd = termsStart + "Terms of Service".length
            spannable.setSpan(UnderlineSpan(), termsStart, termsEnd, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
            spannable.setSpan(ForegroundColorSpan(0xFF0066FF.toInt()), termsStart, termsEnd, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
            spannable.setSpan(object : ClickableSpan() {
                override fun onClick(widget: View) {
                    Toast.makeText(this@LoginActivity, "TrustShield Terms of Service: Neural Threat Protection Protocol", Toast.LENGTH_SHORT).show()
                }
            }, termsStart, termsEnd, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
        }

        val privacyStart = fullText.indexOf("Privacy Policy")
        if (privacyStart != -1) {
            val privacyEnd = privacyStart + "Privacy Policy".length
            spannable.setSpan(UnderlineSpan(), privacyStart, privacyEnd, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
            spannable.setSpan(ForegroundColorSpan(0xFF0066FF.toInt()), privacyStart, privacyEnd, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
            spannable.setSpan(object : ClickableSpan() {
                override fun onClick(widget: View) {
                    Toast.makeText(this@LoginActivity, "TrustShield Privacy Policy: Zero Data Retention & On-Device Forensics", Toast.LENGTH_SHORT).show()
                }
            }, privacyStart, privacyEnd, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
        }

        tvFooterSecurity?.text = spannable
        tvFooterSecurity?.movementMethod = LinkMovementMethod.getInstance()
    }

    private fun loginUser(phoneNumber: String, pin: String) {
        if (isLoading) return

        isLoading = true
        loginButton?.isEnabled = false
        loginButton?.alpha = 0.7f
        progressBar?.visibility = View.VISIBLE

        lifecycleScope.launch {
            try {
                Log.d(TAG, "Calling backend API: POST /api/auth/login")

                val loginRequest = LoginRequest(
                    phone_number = phoneNumber,
                    pin = pin
                )

                val apiService = RetrofitClient.getInstance().getApiService()
                val response = apiService.login(loginRequest)

                if (response.isSuccessful && response.body() != null) {
                    val loginResponse = response.body()!!
                    Log.d(TAG, "Login successful for user: ${loginResponse.name}")

                    saveUserData(loginResponse.id, loginResponse.name, loginResponse.email, loginResponse.phone_number)
                    AuthStore.saveToken(this@LoginActivity, loginResponse.token)

                    Toast.makeText(this@LoginActivity, "Welcome back, ${loginResponse.name}!", Toast.LENGTH_SHORT).show()
                    navigateToHome()

                } else {
                    val errorMessage = when (response.code()) {
                        401 -> "Invalid phone number or PIN"
                        429 -> "Too many attempts. Try again in a few minutes"
                        400 -> "Missing required fields"
                        404 -> "User not found. Please register first."
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
                loginButton?.alpha = 1.0f
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
