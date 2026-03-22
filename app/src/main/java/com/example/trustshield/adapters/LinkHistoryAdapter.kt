package com.example.trustshield.adapters

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.TextView
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.example.trustshield.R
import com.example.trustshield.network.models.LinkScanHistoryItem
import java.text.SimpleDateFormat
import java.util.Locale

/**
 * LinkHistoryAdapter
 * Displays list of scanned links from backend in RecyclerView
 */
class LinkHistoryAdapter : ListAdapter<LinkScanHistoryItem, LinkHistoryAdapter.LinkViewHolder>(
    LinkDiffCallback()
) {
    
    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): LinkViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_link_history, parent, false)
        return LinkViewHolder(view)
    }
    
    override fun onBindViewHolder(holder: LinkViewHolder, position: Int) {
        holder.bind(getItem(position))
    }
    
    class LinkViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        private val urlText: TextView = itemView.findViewById(R.id.tv_link_url)
        private val verdictIcon: ImageView = itemView.findViewById(R.id.iv_verdict_icon)
        private val verdictText: TextView = itemView.findViewById(R.id.tv_verdict)
        private val riskLevelText: TextView = itemView.findViewById(R.id.tv_risk_level)
        private val timestampText: TextView = itemView.findViewById(R.id.tv_timestamp)
        
        fun bind(scan: LinkScanHistoryItem) {
            val context = itemView.context
            
            // Display URL (truncated if too long)
            urlText.text = if (scan.url.length > 60) {
                scan.url.substring(0, 60) + "..."
            } else {
                scan.url
            }
            
            // Set verdict and colors
            when (scan.verdict?.uppercase()) {
                "SAFE" -> {
                    verdictText.text = "✓ Safe"
                    verdictText.setTextColor(ContextCompat.getColor(context, android.R.color.holo_green_dark))
                    verdictIcon.setImageResource(android.R.drawable.ic_dialog_info)
                    verdictIcon.setColorFilter(ContextCompat.getColor(context, android.R.color.holo_green_dark))
                    riskLevelText.text = "Risk: Safe"
                    riskLevelText.setTextColor(ContextCompat.getColor(context, android.R.color.holo_green_dark))
                }
                "SUSPICIOUS" -> {
                    verdictText.text = "⚠ Suspicious"
                    verdictText.setTextColor(ContextCompat.getColor(context, android.R.color.holo_orange_dark))
                    verdictIcon.setImageResource(android.R.drawable.ic_dialog_alert)
                    verdictIcon.setColorFilter(ContextCompat.getColor(context, android.R.color.holo_orange_dark))
                    riskLevelText.text = "Risk: ${scan.risk_level ?: "Medium"}"
                    riskLevelText.setTextColor(ContextCompat.getColor(context, android.R.color.holo_orange_dark))
                }
                "DANGEROUS" -> {
                    verdictText.text = "✕ Dangerous"
                    verdictText.setTextColor(ContextCompat.getColor(context, android.R.color.holo_red_dark))
                    verdictIcon.setImageResource(android.R.drawable.ic_dialog_alert)
                    verdictIcon.setColorFilter(ContextCompat.getColor(context, android.R.color.holo_red_dark))
                    riskLevelText.text = "Risk: ${scan.risk_level ?: "High"}"
                    riskLevelText.setTextColor(ContextCompat.getColor(context, android.R.color.holo_red_dark))
                }
                else -> {
                    verdictText.text = "? Unknown"
                    verdictText.setTextColor(ContextCompat.getColor(context, android.R.color.darker_gray))
                    verdictIcon.setImageResource(android.R.drawable.ic_dialog_info)
                    verdictIcon.setColorFilter(ContextCompat.getColor(context, android.R.color.darker_gray))
                    riskLevelText.text = "Risk: Unknown"
                    riskLevelText.setTextColor(ContextCompat.getColor(context, android.R.color.darker_gray))
                }
            }
            
            // Format timestamp
            try {
                val isoFormat = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss", Locale.getDefault())
                val displayFormat = SimpleDateFormat("MMM dd, yyyy HH:mm", Locale.getDefault())
                val date = isoFormat.parse(scan.analyzed_at)
                timestampText.text = if (date != null) displayFormat.format(date) else scan.analyzed_at
            } catch (e: Exception) {
                timestampText.text = scan.analyzed_at
            }
        }
    }
    
    class LinkDiffCallback : DiffUtil.ItemCallback<LinkScanHistoryItem>() {
        override fun areItemsTheSame(oldItem: LinkScanHistoryItem, newItem: LinkScanHistoryItem) =
            oldItem.id == newItem.id
        
        override fun areContentsTheSame(oldItem: LinkScanHistoryItem, newItem: LinkScanHistoryItem) =
            oldItem == newItem
    }
}
