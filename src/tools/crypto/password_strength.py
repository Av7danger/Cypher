import re
import math


class PasswordStrengthChecker:
    """Tool for checking the strength of passwords based on length and complexity."""
    
    def __init__(self):
        # Define character sets
        self.lowercase_chars = "abcdefghijklmnopqrstuvwxyz"
        self.uppercase_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        self.digit_chars = "0123456789"
        self.special_chars = "!@#$%^&*()-_=+[]{}|;:',.<>/?`~"
        
        # Define common password patterns
        self.common_patterns = [
            r"^123456+$",
            r"^password+$",
            r"^qwerty+$",
            r"^admin+$",
            r"^welcome+$",
            r"^letmein+$",
            r"^monkey+$",
            r"^login+$",
            r"^abc123+$",
            r"^[0-9]{4,8}$",  # 4-8 digit numbers only
            r"^([a-zA-Z])\1+$",  # Repeated single character
        ]
        
        # Define common password list (abbreviated)
        self.common_passwords = {
            "123456", "password", "12345678", "qwerty", "123456789",
            "12345", "1234", "111111", "1234567", "dragon",
            "123123", "baseball", "abc123", "football", "monkey",
            "letmein", "696969", "shadow", "master", "666666",
            "qwertyuiop", "123321", "mustang", "1234567890", "michael",
            "654321", "superman", "1qaz2wsx", "7777777", "fuckyou",
            "121212", "000000", "qazwsx", "123qwe", "killer",
            "trustno1", "jordan", "jennifer", "hunter", "buster"
        }
    
    def check_strength(self, password):
        """
        Check the strength of a password.
        
        Args:
            password: The password to check
            
        Returns:
            Dictionary with strength assessment details
        """
        if not password:
            return {
                'score': 0,
                'strength': 'Very Weak',
                'feedback': ['Password is empty']
            }
            
        # Initialize results
        score = 0
        feedback = []
        
        # Check length
        length_score, length_feedback = self._check_length(password)
        score += length_score
        if length_feedback:
            feedback.append(length_feedback)
        
        # Check character variety
        variety_score, variety_feedback = self._check_character_variety(password)
        score += variety_score
        if variety_feedback:
            feedback.extend(variety_feedback)
        
        # Check for common patterns and passwords
        patterns_score, patterns_feedback = self._check_common_patterns(password)
        score += patterns_score
        if patterns_feedback:
            feedback.extend(patterns_feedback)
        
        # Check for entropy (randomness)
        entropy_score, entropy_feedback = self._calculate_entropy(password)
        score += entropy_score
        if entropy_feedback:
            feedback.append(entropy_feedback)
        
        # Calculate final score (max 100)
        final_score = min(100, score)
        
        # Determine strength category
        strength = self._get_strength_category(final_score)
        
        # Add general feedback based on score
        if final_score < 40 and not feedback:
            feedback.append("Password is too simple and easy to guess.")
        elif final_score > 80 and not feedback:
            feedback.append("Password has good complexity.")
        
        # If no specific feedback but score is medium
        if final_score >= 40 and final_score <= 80 and not feedback:
            feedback.append("Password has moderate complexity, consider adding more variety.")
        
        return {
            'score': final_score,
            'strength': strength,
            'feedback': feedback if feedback else ["Password meets all basic requirements."]
        }
    
    def _check_length(self, password):
        """Check the length of the password."""
        length = len(password)
        
        if length < 8:
            return 0, f"Password is too short ({length} characters). Use at least 8 characters."
        elif length < 10:
            return 10, f"Password length is acceptable ({length} characters), but using 12+ is recommended."
        elif length < 12:
            return 20, None
        elif length < 16:
            return 25, None
        else:
            return 30, None
    
    def _check_character_variety(self, password):
        """Check for variety of character types in the password."""
        score = 0
        feedback = []
        
        # Check for lowercase letters
        has_lower = any(c in self.lowercase_chars for c in password)
        if has_lower:
            score += 10
        else:
            feedback.append("Add lowercase letters (a-z).")
        
        # Check for uppercase letters
        has_upper = any(c in self.uppercase_chars for c in password)
        if has_upper:
            score += 10
        else:
            feedback.append("Add uppercase letters (A-Z).")
        
        # Check for digits
        has_digit = any(c in self.digit_chars for c in password)
        if has_digit:
            score += 10
        else:
            feedback.append("Add numbers (0-9).")
        
        # Check for special characters
        has_special = any(c in self.special_chars for c in password)
        if has_special:
            score += 10
        else:
            feedback.append("Add special characters (!@#$%...).")
        
        # Bonus for using all types
        if has_lower and has_upper and has_digit and has_special:
            score += 10
        
        return score, feedback
    
    def _check_common_patterns(self, password):
        """Check if the password uses common patterns or is a known common password."""
        score = 0
        feedback = []
        
        # Check against common password list
        if password.lower() in self.common_passwords:
            score -= 30
            feedback.append("Password is in the list of common passwords.")
        
        # Check for common patterns
        for pattern in self.common_patterns:
            if re.match(pattern, password):
                score -= 20
                feedback.append("Password uses a common pattern.")
                break
        
        # Check for sequences
        if self._contains_sequence(password):
            score -= 15
            feedback.append("Password contains sequential characters (like 'abc' or '123').")
        
        # Check for keyboard patterns (simplified)
        if self._contains_keyboard_pattern(password):
            score -= 15
            feedback.append("Password contains keyboard patterns (like 'qwerty').")
        
        # Check for repeated characters
        if self._contains_repeated_chars(password):
            score -= 10
            feedback.append("Password contains repeated characters (like 'aaa').")
        
        return score, feedback
    
    def _contains_sequence(self, password):
        """Check if the password contains sequential characters."""
        sequences = [
            "abcdefghijklmnopqrstuvwxyz",
            "0123456789"
        ]
        
        for seq in sequences:
            for i in range(len(seq) - 2):
                if seq[i:i+3].lower() in password.lower():
                    return True
        
        return False
    
    def _contains_keyboard_pattern(self, password):
        """Check if the password contains keyboard patterns."""
        keyboard_patterns = [
            "qwerty", "asdfgh", "zxcvbn", "qwertyuiop", "asdfghjkl", "zxcvbnm"
        ]
        
        for pattern in keyboard_patterns:
            if pattern in password.lower():
                return True
        
        return False
    
    def _contains_repeated_chars(self, password):
        """Check if the password contains repeated characters."""
        return re.search(r'(.)\1{2,}', password) is not None
    
    def _calculate_entropy(self, password):
        """Calculate password entropy (randomness)."""
        # Count character sets used
        char_sets = 0
        if any(c in self.lowercase_chars for c in password):
            char_sets += 26
        if any(c in self.uppercase_chars for c in password):
            char_sets += 26
        if any(c in self.digit_chars for c in password):
            char_sets += 10
        if any(c in self.special_chars for c in password):
            char_sets += 33
        
        # Calculate entropy in bits
        if char_sets == 0:  # Just in case
            char_sets = 26
            
        entropy = len(password) * math.log2(char_sets)
        
        if entropy < 40:
            return 0, f"Low entropy ({entropy:.1f} bits). Password isn't random enough."
        elif entropy < 60:
            return 5, f"Moderate entropy ({entropy:.1f} bits)."
        elif entropy < 80:
            return 10, None
        else:
            return 20, None
    
    def _get_strength_category(self, score):
        """Map score to a strength category."""
        if score < 20:
            return "Very Weak"
        elif score < 40:
            return "Weak"
        elif score < 60:
            return "Moderate"
        elif score < 80:
            return "Strong"
        else:
            return "Very Strong"
    
    def generate_improvement_suggestions(self, password):
        """
        Generate specific suggestions to improve a password.
        
        Args:
            password: The current password
            
        Returns:
            List of specific suggestions to improve the password
        """
        result = self.check_strength(password)
        
        if result['score'] >= 80:
            return ["Your password is already strong."]
        
        # Generate specific improvement suggestions
        suggestions = result['feedback'].copy()
        
        # If password is short, suggest a longer version
        if len(password) < 12:
            if len(suggestions) == 0 or not any("too short" in s for s in suggestions):
                suggestions.append(f"Consider using a longer password (current length: {len(password)}).")
        
        # Suggest adding character types that are missing
        chars_to_add = []
        if not any(c in self.uppercase_chars for c in password):
            chars_to_add.append("uppercase letters")
        if not any(c in self.lowercase_chars for c in password):
            chars_to_add.append("lowercase letters")
        if not any(c in self.digit_chars for c in password):
            chars_to_add.append("numbers")
        if not any(c in self.special_chars for c in password):
            chars_to_add.append("special characters")
        
        if chars_to_add:
            suggestions.append(f"Add {', '.join(chars_to_add)} to your password.")
        
        # Suggest avoiding common patterns
        if self._contains_sequence(password) or self._contains_keyboard_pattern(password):
            suggestions.append("Avoid sequences like '123' or 'abc' and keyboard patterns like 'qwerty'.")
        
        return suggestions

# Create an alias for compatibility with CLI code
PasswordStrength = PasswordStrengthChecker