from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey, Float
from sqlalchemy.orm import relationship
from datetime import datetime
from database import Base

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    last_name = Column(String(100), nullable=False)
    email = Column(String(255), unique=True, nullable=False, index=True)
    phone_number = Column(String(20), unique=True, nullable=False, index=True)
    pin = Column(String(10), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship
    link_scans = relationship("LinkScan", back_populates="user", cascade="all, delete-orphan")

class LinkScan(Base):
    __tablename__ = "link_scans"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    url = Column(String(2048), nullable=False)
    risk_level = Column(String(50))
    reasons = Column(Text)
    verdict = Column(Text)
    analyzed_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationship
    user = relationship("User", back_populates="link_scans")
    features = relationship("ScanFeature", back_populates="scan", cascade="all, delete-orphan")

class ScanFeature(Base):
    __tablename__ = "scan_features"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("link_scans.id"), nullable=False)
    feature_name = Column(String(255))
    feature_value = Column(Text)
    extracted_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationship
    scan = relationship("LinkScan", back_populates="features")

class ForensicCase(Base):
    __tablename__ = "forensic_cases"
    
    case_id = Column(String(50), primary_key=True, index=True)
    evidence_hash = Column(String(64), index=True)
    verdict = Column(String(100))
    threat_score = Column(Float)
    sender = Column(String(255))
    subject = Column(String(500))
    dossier_json = Column(Text, nullable=False)
    raw_eml = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

