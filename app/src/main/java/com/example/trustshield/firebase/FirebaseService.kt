package com.example.trustshield.firebase

import android.util.Log
import com.example.trustshield.models.LinkScan
import com.example.trustshield.models.User
import com.example.trustshield.models.UserStats
import com.google.firebase.auth.FirebaseAuth
import com.google.firebase.auth.PhoneAuthCredential
import com.google.firebase.database.FirebaseDatabase
import kotlinx.coroutines.tasks.await

/**
 * Firebase Service
 * Handles all Firebase Authentication and Database operations
 */
class FirebaseService {
    private val auth = FirebaseAuth.getInstance()
    private val database = FirebaseDatabase.getInstance()
    private val TAG = "FIREBASE_SERVICE"
    
    // Node references
    private val usersRef = database.getReference("users")
    private val linkScansRef = database.getReference("linkScans")
    private val statsRef = database.getReference("userStats")
    
    /**
     * Get current logged-in user ID
     */
    fun getCurrentUserId(): String? {
        return auth.currentUser?.uid
    }
    
    /**
     * Check if user is logged in
     */
    fun isUserLoggedIn(): Boolean {
        return auth.currentUser != null
    }
    
    /**
     * Get current user
     */
    suspend fun getCurrentUser(): User? {
        val userId = getCurrentUserId() ?: return null
        return try {
            val snapshot = usersRef.child(userId).get().await()
            snapshot.getValue(User::class.java) ?: User(userId = userId)
        } catch (e: Exception) {
            Log.e(TAG, "Error getting current user: ${e.message}", e)
            null
        }
    }
    
    /**
     * Sign up with phone number
     * This initiates the phone verification process
     */
    fun signUpWithPhone(
        phoneNumber: String,
        onCodeSent: (verificationId: String) -> Unit,
        onError: (String) -> Unit
    ) {
        Log.d(TAG, "Starting phone sign up: $phoneNumber")
        // Note: This requires PhoneAuthProvider setup
        // Implementation depends on how you want to handle phone auth
        // For now, this is a placeholder
    }
    
    /**
     * Verify phone OTP and create user
     */
    suspend fun verifyPhoneOTP(
        credential: PhoneAuthCredential,
        phoneNumber: String,
        name: String
    ): Boolean {
        return try {
            auth.signInWithCredential(credential).await()
            val userId = auth.currentUser?.uid ?: return false
            
            // Create user record in database
            val newUser = User(
                userId = userId,
                phoneNumber = phoneNumber,
                name = name,
                createdAt = System.currentTimeMillis(),
                lastLogin = System.currentTimeMillis(),
                deviceId = android.os.Build.DEVICE
            )
            
            usersRef.child(userId).setValue(newUser).await()
            Log.d(TAG, "User created successfully: $userId")
            true
        } catch (e: Exception) {
            Log.e(TAG, "Error verifying phone OTP: ${e.message}", e)
            false
        }
    }
    
    /**
     * Save a link scan to Firebase
     */
    suspend fun saveLinkScan(
        linkScan: LinkScan,
        userId: String? = getCurrentUserId()
    ): Boolean {
        val actualUserId = userId ?: return false
        return try {
            val scanId = linkScansRef.child(actualUserId).push().key ?: return false
            val scanWithId = linkScan.copy(scanId = scanId)
            
            linkScansRef.child(actualUserId).child(scanId).setValue(scanWithId).await()
            
            // Update user stats
            updateUserStats(actualUserId, linkScan)
            
            Log.d(TAG, "Link scan saved: $scanId for user $actualUserId")
            true
        } catch (e: Exception) {
            Log.e(TAG, "Error saving link scan: ${e.message}", e)
            false
        }
    }
    
    /**
     * Get all link scans for a user
     */
    suspend fun getUserLinkScans(userId: String? = getCurrentUserId()): List<LinkScan> {
        if (userId == null) return emptyList()
        
        return try {
            val snapshot = linkScansRef.child(userId).get().await()
            val scans = mutableListOf<LinkScan>()
            snapshot.children.forEach { child ->
                child.getValue(LinkScan::class.java)?.let { scans.add(it) }
            }
            // Sort by timestamp descending (newest first)
            scans.sortByDescending { it.timestamp }
            Log.d(TAG, "Retrieved ${scans.size} link scans for user $userId")
            scans
        } catch (e: Exception) {
            Log.e(TAG, "Error getting link scans: ${e.message}", e)
            emptyList()
        }
    }
    
    /**
     * Get a specific link scan
     */
    suspend fun getLinkScan(userId: String, scanId: String): LinkScan? {
        return try {
            val snapshot = linkScansRef.child(userId).child(scanId).get().await()
            snapshot.getValue(LinkScan::class.java)
        } catch (e: Exception) {
            Log.e(TAG, "Error getting link scan: ${e.message}", e)
            null
        }
    }
    
    /**
     * Delete a link scan
     */
    suspend fun deleteLinkScan(userId: String, scanId: String): Boolean {
        return try {
            linkScansRef.child(userId).child(scanId).removeValue().await()
            Log.d(TAG, "Link scan deleted: $scanId")
            true
        } catch (e: Exception) {
            Log.e(TAG, "Error deleting link scan: ${e.message}", e)
            false
        }
    }
    
    /**
     * Update link scan user action
     */
    suspend fun updateLinkScanAction(
        userId: String,
        scanId: String,
        userAction: String,
        isUserTrusted: Boolean = false,
        isUserBlocked: Boolean = false
    ): Boolean {
        return try {
            val updates = mutableMapOf<String, Any>()
            updates["userAction"] = userAction
            updates["reviewedAt"] = System.currentTimeMillis()
            updates["isUserTrusted"] = isUserTrusted
            updates["isUserBlocked"] = isUserBlocked
            
            linkScansRef.child(userId).child(scanId).updateChildren(updates).await()
            Log.d(TAG, "Link scan action updated: $scanId -> $userAction")
            true
        } catch (e: Exception) {
            Log.e(TAG, "Error updating link scan action: ${e.message}", e)
            false
        }
    }
    
    /**
     * Get user statistics
     */
    suspend fun getUserStats(userId: String? = getCurrentUserId()): UserStats {
        if (userId == null) return UserStats()
        
        return try {
            val scans = getUserLinkScans(userId)
            
            var safeCount = 0
            var suspiciousCount = 0
            var dangerousCount = 0
            var verifiedOfficialCount = 0
            
            scans.forEach { scan ->
                when (scan.riskLevel) {
                    "SAFE" -> safeCount++
                    "SUSPICIOUS" -> suspiciousCount++
                    "DANGEROUS" -> dangerousCount++
                }
                if (scan.verificationStatus == "VERIFIED_OFFICIAL") {
                    verifiedOfficialCount++
                }
            }
            
            UserStats(
                totalScans = scans.size,
                safeLinks = safeCount,
                suspiciousLinks = suspiciousCount,
                dangerousLinks = dangerousCount,
                verifiedOfficialCount = verifiedOfficialCount,
                lastUpdated = System.currentTimeMillis()
            )
        } catch (e: Exception) {
            Log.e(TAG, "Error getting user stats: ${e.message}", e)
            UserStats()
        }
    }
    
    /**
     * Update user stats in database
     */
    private suspend fun updateUserStats(userId: String, linkScan: LinkScan) {
        try {
            val stats = getUserStats(userId)
            val updated = stats.copy(lastUpdated = System.currentTimeMillis())
            statsRef.child(userId).setValue(updated).await()
        } catch (e: Exception) {
            Log.e(TAG, "Error updating user stats: ${e.message}", e)
        }
    }
    
    /**
     * Update user profile
     */
    suspend fun updateUserProfile(userId: String, name: String, email: String): Boolean {
        return try {
            val updates = mutableMapOf<String, Any>()
            updates["name"] = name
            if (email.isNotEmpty()) {
                updates["email"] = email
            }
            
            usersRef.child(userId).updateChildren(updates).await()
            Log.d(TAG, "User profile updated: $userId")
            true
        } catch (e: Exception) {
            Log.e(TAG, "Error updating user profile: ${e.message}", e)
            false
        }
    }
    
    /**
     * Log out user
     */
    fun logout() {
        auth.signOut()
        Log.d(TAG, "User logged out")
    }
}
