#!/usr/bin/env python3
"""
Cyber Attack Detection System
ML-Based Network Security Monitor
Author: Nnamdi Victor Anyaorah
"""

import joblib
import pandas as pd
import numpy as np
import json
import os

class CyberAttackDetector:
    """Machine Learning Cyber Attack Detector"""
    
    def __init__(self, models_dir='models'):
        self.models_dir = models_dir
        self.models = {}
        self.scalers = {}
        self.features = {}
        
    def load_models(self):
        """Load all trained models"""
        print("🔄 Loading models...")
        print()
        
        try:
            # Load UNSW models
            self.models['rf_unsw'] = joblib.load(os.path.join(self.models_dir, 'random_forest_unsw.pkl'))
            print("✅ Random Forest (UNSW-NB15)")
            
            self.models['gb_unsw'] = joblib.load(os.path.join(self.models_dir, 'gradient_boosting_unsw.pkl'))
            print("✅ Gradient Boosting (UNSW-NB15)")
            
            self.scalers['unsw'] = joblib.load(os.path.join(self.models_dir, 'scaler_unsw.pkl'))
            print("✅ Scaler (UNSW-NB15)")
            
            # Load CICIDS models
            self.models['rf_cic'] = joblib.load(os.path.join(self.models_dir, 'random_forest_cicids.pkl'))
            print("✅ Random Forest (CICIDS2017)")
            
            self.models['gb_cic'] = joblib.load(os.path.join(self.models_dir, 'gradient_boosting_cicids.pkl'))
            print("✅ Gradient Boosting (CICIDS2017)")
            
            self.scalers['cic'] = joblib.load(os.path.join(self.models_dir, 'scaler_cic.pkl'))
            print("✅ Scaler (CICIDS2017)")
            
            # Load feature names
            with open(os.path.join(self.models_dir, 'feature_names_unsw.json'), 'r') as f:
                self.features['unsw'] = json.load(f)
            print(f"✅ Features (UNSW: {len(self.features['unsw'])} features)")
            
            with open(os.path.join(self.models_dir, 'feature_names_cic.json'), 'r') as f:
                self.features['cic'] = json.load(f)
            print(f"✅ Features (CICIDS: {len(self.features['cic'])} features)")
            
            print()
            print("="*70)
            print("🎉 ALL MODELS LOADED SUCCESSFULLY!")
            print("="*70)
            return True
            
        except Exception as e:
            print(f"❌ Error loading models: {e}")
            return False
    
    def detect_unsw(self, network_data):
        """Detect attacks using UNSW model"""
        # Scale data
        scaled = self.scalers['unsw'].transform(network_data)
        
        # Predict with both models
        rf_pred = self.models['rf_unsw'].predict(scaled)
        rf_prob = self.models['rf_unsw'].predict_proba(scaled)
        
        gb_pred = self.models['gb_unsw'].predict(scaled)
        gb_prob = self.models['gb_unsw'].predict_proba(scaled)
        
        return {
            'rf_prediction': 'ATTACK' if rf_pred[0] == 1 else 'NORMAL',
            'rf_confidence': rf_prob[0][rf_pred[0]] * 100,
            'gb_prediction': 'ATTACK' if gb_pred[0] == 1 else 'NORMAL',
            'gb_confidence': gb_prob[0][gb_pred[0]] * 100
        }
    
    def detect_cicids(self, network_data):
        """Detect attacks using CICIDS model"""
        # Scale data
        scaled = self.scalers['cic'].transform(network_data)
        
        # Predict with both models
        rf_pred = self.models['rf_cic'].predict(scaled)
        rf_prob = self.models['rf_cic'].predict_proba(scaled)
        
        gb_pred = self.models['gb_cic'].predict(scaled)
        gb_prob = self.models['gb_cic'].predict_proba(scaled)
        
        return {
            'rf_prediction': 'ATTACK' if rf_pred[0] == 1 else 'NORMAL',
            'rf_confidence': rf_prob[0][rf_pred[0]] * 100,
            'gb_prediction': 'ATTACK' if gb_pred[0] == 1 else 'NORMAL',
            'gb_confidence': gb_prob[0][gb_pred[0]] * 100
        }

def demo():
    """Run a demo"""
    print("\n" + "="*70)
    print("CYBER ATTACK DETECTION SYSTEM - DEMO")
    print("="*70)
    print()
    
    # Initialize
    detector = CyberAttackDetector(models_dir=r'C:\Users\nnamd\models')
    
    if not detector.load_models():
        return
    
    print("\n✅ System ready for detection!")
    print()
    print("Your models:")
    print("  • UNSW-NB15: Random Forest (79.78%) + Gradient Boosting (79.69%)")
    print("  • CICIDS2017: Random Forest (84.09%) + Gradient Boosting (84.92%)")
    print()
    print("="*70)

if __name__ == "__main__":
    demo()