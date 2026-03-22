package com.example.trustshield.adapters

import android.content.Context
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
import com.example.trustshield.models.LinkScan
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Adapter for displaying link scan history in RecyclerView
 */
class LinkScanAdapter(
    private val onItemClick: (LinkScan) -> Unit
) : ListAdapter<LinkScan, LinkScanAdapter.LinkScanViewHolder>(LinkScanDiffCallback()) {
    
    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): LinkScanViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_link_scan, parent, false)
        return LinkScanViewHolder(view, parent.context, onItemClick)
    }
    
    override fun onBindViewHolder(holder: LinkScanViewHolder, position: Int) {
        holder.bind(getItem(position))
    }
    
    class LinkScanViewHolder(
        itemView: View,
        private val context: Context,
        private val onItemClick: (LinkScan) -> Unit
    ) : RecyclerView.ViewHolder(itemView) {
        
        private val urlText: TextView = itemView.findViewById(R.id.tv_link_url)
        private val verdictText: TextView = itemView.findViewById(R.id.tv_verdict)
        private val verdictIcon: ImageView = itemView.findViewById(R.id.iv_verdict_icon)
        private val brandText: TextView = itemView.findViewById(R.id.tv_brand)
        private val timestampText: TextView = itemView.findViewById(R.id.tv_timestamp)
        
        fun bind(linkScan: LinkScan) {
            // Display URL (truncated if too long)
            val displayUrl = if (linkScan.url.length > 50) {
                linkScan.url.substring(0, 47) + "..."
            } else {
                linkScan.url
            }
            urlText.text = displayUrl
            
            // Display verdict with color and icon
            verdictText.text = linkScan.riskLevel
            when {
                linkScan.riskLevel.contains("SAFE") -> {
                    verdictText.setTextColor(ContextCompat.getColor(context, android.R.color.holo_green_dark))
                    verdictIcon.setImageResource(R.drawable.ic_check_circle)
                }
                linkScan.riskLevel.contains("SUSPICIOUS") -> {
                    verdictText.setTextColor(ContextCompat.getColor(context, android.R.color.holo_orange_dark))
                    verdictIcon.setImageResource(R.drawable.ic_warning_circle)
                }
                linkScan.riskLevel.contains("DANGEROUS") -> {
                    verdictText.setTextColor(ContextCompat.getColor(context, android.R.color.holo_red_dark))
                    verdictIcon.setImageResource(R.drawable.ic_error_circle)
                }
            }
            
            // Display brand info
            if (linkScan.verificationStatus == "VERIFIED_OFFICIAL" && linkScan.verifiedBrand != null) {
                brandText.text = "✅ Official ${linkScan.verifiedBrand}"
                brandText.visibility = View.VISIBLE
            } else {
                brandText.visibility = View.GONE
            }
            
            // Display timestamp
            val dateFormat = SimpleDateFormat("MMM dd, hh:mm a", Locale.getDefault())
            val formattedDate = dateFormat.format(Date(linkScan.timestamp))
            timestampText.text = formattedDate
            
            // Click listener
            itemView.setOnClickListener {
                onItemClick(linkScan)
            }
        }
    }
}

/**
 * DiffCallback for efficient list updates
 */
class LinkScanDiffCallback : DiffUtil.ItemCallback<LinkScan>() {
    override fun areItemsTheSame(oldItem: LinkScan, newItem: LinkScan): Boolean {
        return oldItem.scanId == newItem.scanId
    }
    
    override fun areContentsTheSame(oldItem: LinkScan, newItem: LinkScan): Boolean {
        return oldItem == newItem
    }
}
