package com.example.trustshield.network

import android.content.Context
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import java.util.concurrent.TimeUnit

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
        
        // Create OkHttp client with interceptors
        val okHttpClient = OkHttpClient.Builder()
            .addInterceptor(loggingInterceptor)
            .connectTimeout(30, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .writeTimeout(30, TimeUnit.SECONDS)
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
    
    companion object {
        private var instance: RetrofitClient? = null
        
        /**
         * Get singleton instance of RetrofitClient
         */
        fun getInstance(baseUrl: String = "http://10.177.26.61:8000"): RetrofitClient {
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
