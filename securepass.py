#!/usr/bin/env python3
"""
SecurePass - Password Breach & Strength Checker
A comprehensive tool to check password security using HaveIBeenPwned API
"""

import hashlib
import requests
import re
import sys
from typing import Dict, List, Tuple, Optional


class PasswordChecker:
    """Main class for password security analysis"""
    
    def __init__(self):
        self.hibp_api_url = "https://api.pwnedpasswords.com/range/"
        self.common_passwords = [
            "password", "123456", "password123", "admin", "qwerty",
            "letmein", "welcome", "monkey", "1234567890", "abc123",
            "password1", "12345", "dragon", "master", "hello"
        ]
    
    def check_breach(self, password: str) -> Tuple[bool, int]:
        """
        Check if password appears in HaveIBeenPwned database
        Returns (is_breached, breach_count)
        """
        try:
            # Hash the password with SHA-1
            password_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            prefix = password_hash[:5]
            suffix = password_hash[5:]
            
            # Make API request
            response = requests.get(f"{self.hibp_api_url}{prefix}")
            response.raise_for_status()
            
            # Check if our hash suffix is in the response
            for line in response.text.splitlines():
                if line.startswith(suffix):
                    breach_count = int(line.split(':')[1])
                    return True, breach_count
            
            return False, 0
            
        except requests.RequestException as e:
            print(f"⚠️  Warning: Could not check breach database: {e}")
            return False, 0
    
    def evaluate_strength(self, password: str) -> Dict[str, any]:
        """
        Evaluate password strength based on various criteria
        Returns comprehensive strength analysis
        """
        score = 0
        feedback = []
        
        # Length check
        if len(password) < 8:
            score -= 20
            feedback.append("❌ Too short (minimum 8 characters)")
        elif len(password) < 12:
            score += 10
            feedback.append("⚠️  Short length (12+ recommended)")
        else:
            score += 20
            feedback.append("✅ Good length")
        
        # Character variety checks
        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
        
        if has_upper:
            score += 10
            feedback.append("✅ Contains uppercase letters")
        else:
            feedback.append("❌ Missing uppercase letters")
        
        if has_lower:
            score += 10
            feedback.append("✅ Contains lowercase letters")
        else:
            feedback.append("❌ Missing lowercase letters")
        
        if has_digit:
            score += 10
            feedback.append("✅ Contains numbers")
        else:
            feedback.append("❌ Missing numbers")
        
        if has_special:
            score += 15
            feedback.append("✅ Contains special characters")
        else:
            feedback.append("❌ Missing special characters")
        
        # Check for common patterns
        if password.lower() in [p.lower() for p in self.common_passwords]:
            score -= 30
            feedback.append("❌ Common password detected")
        elif any(common in password.lower() for common in self.common_passwords):
            score -= 15
            feedback.append("⚠️  Contains common password elements")
        
        # Sequential characters check
        if self._has_sequential_chars(password):
            score -= 10
            feedback.append("⚠️  Contains sequential characters")
        
        # Repeated characters check
        if self._has_repeated_chars(password):
            score -= 5
            feedback.append("⚠️  Contains repeated characters")
        
        # Determine strength level
        if score >= 70:
            strength = "Strong"
            color = "🟢"
        elif score >= 40:
            strength = "Medium"
            color = "🟡"
        else:
            strength = "Weak"
            color = "🔴"
        
        return {
            "score": max(0, score),
            "strength": strength,
            "color": color,
            "feedback": feedback,
            "has_upper": has_upper,
            "has_lower": has_lower,
            "has_digit": has_digit,
            "has_special": has_special
        }
    
    def _has_sequential_chars(self, password: str) -> bool:
        """Check for sequential characters (abc, 123, etc.)"""
        for i in range(len(password) - 2):
            if (ord(password[i+1]) == ord(password[i]) + 1 and 
                ord(password[i+2]) == ord(password[i]) + 2):
                return True
        return False
    
    def _has_repeated_chars(self, password: str) -> bool:
        """Check for repeated characters (aaa, 111, etc.)"""
        for i in range(len(password) - 2):
            if password[i] == password[i+1] == password[i+2]:
                return True
        return False
    
    def generate_suggestions(self, strength_analysis: Dict[str, any]) -> List[str]:
        """Generate security improvement suggestions"""
        suggestions = []
        
        if strength_analysis["score"] < 50:
            suggestions.append("🔧 Consider using a password manager")
        
        if not strength_analysis["has_upper"]:
            suggestions.append("🔧 Add uppercase letters")
        
        if not strength_analysis["has_lower"]:
            suggestions.append("🔧 Add lowercase letters")
        
        if not strength_analysis["has_digit"]:
            suggestions.append("🔧 Add numbers")
        
        if not strength_analysis["has_special"]:
            suggestions.append("🔧 Add special characters (!@#$%^&*)")
        
        if "Too short" in str(strength_analysis["feedback"]):
            suggestions.append("🔧 Increase password length to 12+ characters")
        
        if "Common password" in str(strength_analysis["feedback"]):
            suggestions.append("🔧 Avoid dictionary words and common passwords")
        
        if not suggestions:
            suggestions.append("✅ Password meets most security requirements!")
        
        return suggestions
    
    def analyze_password(self, password: str) -> Dict[str, any]:
        """
        Complete password analysis
        Returns comprehensive security report
        """
        print("🔍 Analyzing password security...")
        
        # Check for breaches
        is_breached, breach_count = self.check_breach(password)
        
        # Evaluate strength
        strength_analysis = self.evaluate_strength(password)
        
        # Generate suggestions
        suggestions = self.generate_suggestions(strength_analysis)
        
        return {
            "password": password,
            "is_breached": is_breached,
            "breach_count": breach_count,
            "strength_analysis": strength_analysis,
            "suggestions": suggestions
        }
    
    def display_results(self, analysis: Dict[str, any]):
        """Display formatted security analysis results"""
        password = analysis["password"]
        is_breached = analysis["is_breached"]
        breach_count = analysis["breach_count"]
        strength = analysis["strength_analysis"]
        suggestions = analysis["suggestions"]
        
        print("\n" + "="*60)
        print("🔐 SECUREPASS - PASSWORD SECURITY REPORT")
        print("="*60)
        print(f"Password: {'*' * len(password)}")
        
        # Breach status
        if is_breached:
            print(f"❌ Found in {breach_count:,} data breaches!")
        else:
            print("✅ No breaches found in database")
        
        # Strength rating
        print(f"\n{strength['color']} Strength: {strength['strength']} (Score: {strength['score']}/100)")
        
        # Detailed feedback
        print("\n📊 Analysis Details:")
        for feedback in strength['feedback']:
            print(f"  {feedback}")
        
        # Suggestions
        print("\n💡 Security Suggestions:")
        for suggestion in suggestions:
            print(f"  {suggestion}")
        
        print("\n" + "="*60)


def main():
    """Main CLI interface"""
    print("🔐 Welcome to SecurePass - Password Security Checker")
    print("=" * 50)
    
    checker = PasswordChecker()
    
    while True:
        try:
            password = input("\nEnter password to check (or 'quit' to exit): ").strip()
            
            if password.lower() in ['quit', 'exit', 'q']:
                print("👋 Thanks for using SecurePass!")
                break
            
            if not password:
                print("⚠️  Please enter a password")
                continue
            
            # Analyze password
            analysis = checker.analyze_password(password)
            
            # Display results
            checker.display_results(analysis)
            
        except KeyboardInterrupt:
            print("\n\n👋 Thanks for using SecurePass!")
            break
        except Exception as e:
            print(f"❌ An error occurred: {e}")


if __name__ == "__main__":
    main()
