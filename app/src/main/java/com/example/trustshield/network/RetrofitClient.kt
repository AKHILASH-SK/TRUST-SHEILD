package com.example.trustshield.network

import android.content.Context
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import java.util.concurrent.TimeUnit
import okhttp3.Interceptor
import okhttp3.Response
import com.example.trustshield.BuildConfig

/**
 * RetrofitClient
 * Singleton manager for Retrofit instance and API service
 * 
 * Usage:
 * val apiService = RetrofitClient.getInstance(context).getApiService()
 */
class RetrofitClient private constructor(private val baseUrl: String) {
    
    private lateinit var retrofit: Retrofit
    private lateinit var apiService: TrustShieldApiService
    
    init {
        buildRetrofit()
    }
    
    private fun buildRetrofit() {
        // Create logging interceptor for debugging
        val loggingInterceptor = HttpLoggingInterceptor().apply {
            level = HttpLoggingInterceptor.Level.BODY
        }
        
        // Create Retry Interceptor for Render cold starts
        val retryInterceptor = object : Interceptor {
            override fun intercept(chain: Interceptor.Chain): Response {
                val request = chain.request()
                var response: Response? = null
                var isSuccessful = false
                var tryCount = 0
                val maxRetries = 3

                while (!isSuccessful && tryCount < maxRetries) {
                    try {
                        response?.close()
                        response = chain.proceed(request)
                        // Render load balancer returns 502/503 while booting
                        isSuccessful = response.isSuccessful || (response.code != 502 && response.code != 503)
                    } catch (e: Exception) {
                        if (tryCount == maxRetries - 1) throw e
                    }
                    if (!isSuccessful) {
                        tryCount++
                        Thread.sleep(8000) // Wait 8 seconds before retrying
                    }
                }
                return response ?: chain.proceed(request)
            }
        }
        
        // Create OkHttp client with interceptors
        val okHttpClient = OkHttpClient.Builder()
            .addInterceptor(loggingInterceptor)
            .addInterceptor(retryInterceptor)
            .connectTimeout(90, TimeUnit.SECONDS)
            .readTimeout(90, TimeUnit.SECONDS)
            .writeTimeout(90, TimeUnit.SECONDS)
            .build()
        
        // Build Retrofit instance
        retrofit = Retrofit.Builder()
            .baseUrl(baseUrl)
            .client(okHttpClient)
            .addConverterFactory(GsonConverterFactory.create())
            .build()
        
        // Create API service
        apiService = retrofit.create(TrustShieldApiService::class.java)
    }
    
    fun getApiService(): TrustShieldApiService = apiService
    
    fun getBaseUrl(): String = baseUrl
    
    companion object {
        private var instance: RetrofitClient? = null
        
        /**
         * Get singleton instance of RetrofitClient
         */
        fun getInstance(baseUrl: String = "https://trust-sheild.onrender.com/"): RetrofitClient {
            if (instance == null) {
                instance = RetrofitClient(baseUrl)
            }
            return instance!!
        }
        
        /**
         * Update base URL (call this when you know the actual server IP)
         */
        fun updateBaseUrl(baseUrl: String) {
            instance = RetrofitClient(baseUrl)
        }
        
        /**
         * Reset instance (useful for testing)
         */
        fun reset() {
            instance = null
        }
    }
}
