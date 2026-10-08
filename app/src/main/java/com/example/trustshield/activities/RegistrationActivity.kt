package com.example.trustshield.activities

import android.content.Intent
import android.os.Bundle
import android.text.method.PasswordTransformationMethod
import android.util.Log
import android.view.View
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.text.HtmlCompat
import androidx.lifecycle.lifecycleScope
import com.example.trustshield.R
import com.example.trustshield.network.RetrofitClient
import com.example.trustshield.network.models.RegisterRequest
import com.google.android.material.button.MaterialButton
import kotlinx.coroutines.launch

/**
 * RegistrationActivity
 * User registration with first name, last name, email, phone, and PIN
 *
 * Calls backend API: POST /api/auth/register
 * Request: {name, last_name, email, phone_number, pin}
 * Response: {id, name, email, phone_number, created_at}
 */
class RegistrationActivity : AppCompatActivity() {

    private var firstNameInput: EditText? = null
    private var lastNameInput: EditText? = null
    private var emailInput: EditText? = null
    private var phoneInput: EditText? = null
    private var pinInput: EditText? = null
    private var confirmPinInput: EditText? = null

    private var togglePinButton: ImageView? = null
    private var toggleConfirmPinButton: ImageView? = null
    private var countryCodeButton: LinearLayout? = null
    private var countryCodeText: TextView? = null

    private var registerButton: MaterialButton? = null
    private var loginRedirectText: TextView? = null
    private var progressBar: ProgressBar? = null

    private var isPinVisible = false
    private var isConfirmPinVisible = false
    private var selectedCountryCode = "+91"
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

            togglePinButton = findViewById(R.id.iv_toggle_pin)
            toggleConfirmPinButton = findViewById(R.id.iv_toggle_confirm_pin)
            countryCodeButton = findViewById(R.id.btn_country_code)
            countryCodeText = findViewById(R.id.tv_country_code)

            registerButton = findViewById(R.id.btn_register)
            loginRedirectText = findViewById(R.id.btn_login_redirect)
            progressBar = findViewById(R.id.progress_bar)

            // Ensure PIN fields default to masked mode
            pinInput?.transformationMethod = PasswordTransformationMethod.getInstance()
            confirmPinInput?.transformationMethod = PasswordTransformationMethod.getInstance()

            // Styled link: "Already have an account? Login" (Login in bold blue)
            val loginPrompt = "Already have an account? <font color='#0D6EFD'><b>Login</b></font>"
            loginRedirectText?.text = HtmlCompat.fromHtml(loginPrompt, HtmlCompat.FROM_HTML_MODE_LEGACY)

            Log.d(TAG, "Views initialized successfully")

        } catch (e: Exception) {
            Log.e(TAG, "initializeViews error: ${e.message}", e)
        }
    }

    private fun setupListeners() {
        try {
            // PIN visibility toggle
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

            // Confirm PIN visibility toggle
            toggleConfirmPinButton?.setOnClickListener {
                isConfirmPinVisible = !isConfirmPinVisible
                if (isConfirmPinVisible) {
                    confirmPinInput?.transformationMethod = null
                    toggleConfirmPinButton?.setImageResource(R.drawable.ic_visibility)
                } else {
                    confirmPinInput?.transformationMethod = PasswordTransformationMethod.getInstance()
                    toggleConfirmPinButton?.setImageResource(R.drawable.ic_visibility_off)
                }
                confirmPinInput?.setSelection(confirmPinInput?.text?.length ?: 0)
            }

            // Country code selector dialog
            countryCodeButton?.setOnClickListener {
                showCountryCodePicker()
            }

            // Sign Up button
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

            // Redirect back to login
            loginRedirectText?.setOnClickListener {
                Log.d(TAG, "Login redirect clicked")
                navigateToLogin()
            }

            Log.d(TAG, "Listeners setup successfully")
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

    private fun isValidEmail(email: String): Boolean {
        return android.util.Patterns.EMAIL_ADDRESS.matcher(email).matches()
    }

    private fun registerUser(firstName: String, lastName: String, email: String, phoneNumber: String, pin: String) {
        if (isLoading) return

        isLoading = true
        registerButton?.isEnabled = false
        registerButton?.text = ""
        progressBar?.visibility = View.VISIBLE

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
                        400 -> "Please check the details you entered"
                        409 -> "An account with this email or phone number already exists"
                        429 -> "Too many attempts. Try again later"
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
                progressBar?.visibility = View.GONE
                registerButton?.isEnabled = true
                registerButton?.text = "SIGN UP"
            }
        }
    }

    private fun navigateToLogin() {
        try {
            Log.d(TAG, "Navigating back to LoginActivity")
            val intent = Intent(this, LoginActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
            }
            startActivity(intent)
            finish()
        } catch (e: Exception) {
            Log.e(TAG, "navigateToLogin error: ${e.message}", e)
            Toast.makeText(this, "Navigation error: ${e.message}", Toast.LENGTH_SHORT).show()
        }
    }
}
