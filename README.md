# PRODIGY_CS_03
A comprehensive password strength checking tool with a modern GUI built using Python, Tkinter, and ttkthemes. This application evaluates password security based on multiple criteria and provides detailed feedback and suggestions for improvement.

## Features

- **Password Strength Assessment:**
  - Length and complexity scoring
  - Character diversity analysis (uppercase, lowercase, numbers, special characters)
  - Entropy calculation
  - Common password detection
  - Keyboard pattern recognition
  - Personal information detection
  - Passphrase support
  - Optional zxcvbn integration for crack time estimation

- **GUI Features:**
  - Modern themed interface using ttkthemes
  - Real-time password analysis
  - Visual strength meter
  - Password visibility toggle
  - Password generator
  - Copy to clipboard functionality
  - Detailed feedback display
  - Optional user context input (name, birth year)

- **Security Analysis:**
  - Levenshtein distance for similarity checking
  - Common word detection
  - Repetition pattern detection
  - Customizable common password list
 
## Requirements

- Python 3.6+
- Required packages:
  - `tkinter` (usually included with Python)
  - `ttkthemes`
- Optional packages:
  - `zxcvbn` (for enhanced crack time estimation)
 

## Technical Details
- **PasswordStrengthChecker Class:**
  - Implements core password analysis logic
  - Uses regex for pattern matching
  - Calculates Shannon entropy
  - Implements Levenshtein distance for similarity checking
- **PasswordCheckerGUI Class:**
  - Built with Tkinter and ttkthemes
  - Responsive layout
  - Color-coded strength indicators
  - Formatted feedback display
- **Performance:**
  - Efficient analysis with timing metrics
  - Memory-efficient common password storage
  - Thread-safe operations
 
## Customization
- Modify `common_passwords.txt` to update the common password list
- Adjust scoring parameters in `PasswordStrengthChecker`:
  - `min_length` (default: 8)
  - `max_length` (default: 128)
  - Scoring weights for different criteria
- Update `keyboard_patterns` and `common_words` sets
- Modify GUI theme by changing `set_theme("arc")`
