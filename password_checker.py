import re
import time
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from ttkthemes import ThemedTk
from typing import Dict, List, Set
from pathlib import Path
from collections import Counter
from math import log2
try:
    import zxcvbn
except ImportError:
    zxcvbn = None


class PasswordStrengthChecker:
    def __init__(self, common_passwords_file: str = "common_passwords.txt"):
        self.min_length = 8
        self.max_length = 128
        self.common_passwords: Set[str] = self._load_common_passwords(common_passwords_file)
        self.keyboard_patterns = ['qwerty', 'asdfgh', '123456', 'zxcvbn', 'poiuyt']
        self.common_words = {'the', 'and', 'you', 'that', 'for', 'password', 'admin'}
        self.personal_info_patterns = [
            r"\d{4}",  # Year-like patterns
            r"(19|20)\d{2}",  # Specific years
            r"\d{2}[-/]\d{2}",  # Date-like (MM-DD or DD-MM)
        ]

    def _load_common_passwords(self, file_path: str) -> Set[str]:
        common_passwords = set()
        try:
            file = Path(file_path)
            if file.exists():
                with file.open('r', encoding='utf-8') as f:
                    common_passwords = {line.strip().lower() for line in f if line.strip()}
            else:
                common_passwords = {'password', '123456', 'qwerty', 'admin', 'letmein'}
        except Exception as e:
            common_passwords = {'password', '123456', 'qwerty', 'admin', 'letmein'}
        return common_passwords

    def _calculate_entropy(self, password: str) -> float:
        if not password:
            return 0.0
        char_count = Counter(password)
        length = len(password)
        entropy = -sum((count / length) * log2(count / length) for count in char_count.values())
        return round(entropy * length, 2)

    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        return previous_row[-1]

    def _is_similar_to_common(self, password: str) -> bool:
        lower_pwd = password.lower()
        for common in self.common_passwords:
            if len(common) > 3 and self._levenshtein_distance(lower_pwd, common) <= 2:
                return True
        return False

    def _detect_passphrase(self, password: str) -> bool:
        words = re.split(r'[\W_]+', password)
        return len([w for w in words if w]) >= 3

    def assess_password_strength(self, password: str, user_info: Dict[str, str] = None) -> Dict[str, any]:
        start_time = time.time()
        if not password:
            return {
                "score": 0, "strength": "Invalid", 
                "feedback": ["Password cannot be empty"], 
                "entropy": 0, "analysis_time": 0, "improvement_tips": []
            }

        if len(password) > self.max_length:
            return {
                "score": 0, "strength": "Invalid",
                "feedback": [f"Password exceeds max length ({self.max_length} characters)"],
                "entropy": 0, "analysis_time": 0, "improvement_tips": []
            }

        score = 0
        feedback: List[str] = []
        user_info = user_info or {}

        length = len(password)
        is_passphrase = self._detect_passphrase(password)
        if is_passphrase:
            length_score = min(50, length * 2)
            feedback.append(f"Length: {length} characters (Passphrase detected)")
        else:
            length_score = min(40, length * 3) if length >= self.min_length else length * 2
            feedback.append(f"Length: {length} characters ({'Good' if length >= self.min_length else 'Too short'})")
        score += length_score

        char_checks = [
            (r"[A-Z]", 20, "uppercase letters"),
            (r"[a-z]", 20, "lowercase letters"),
            (r"\d", 15, "numbers"),
            (r"[!@#$%^&*(),.?\":{}|<>[\]-_=+;]", 25, "special characters")
        ]
        char_diversity = 0
        for pattern, points, desc in char_checks:
            if re.search(pattern, password):
                score += points
                char_diversity += 1
                feedback.append(f"Contains {desc}")
            else:
                feedback.append(f"Missing {desc}")

        lower_pwd = password.lower()
        if lower_pwd in self.common_passwords:
            score = min(score, 30)
            feedback.append("Warning: Exact match with common password!")
        elif self._is_similar_to_common(password):
            score -= 15
            feedback.append("Warning: Too similar to a common password!")

        if re.search(r"(.)\1{3,}", password):
            score -= 20
            feedback.append("Warning: Excessive character repetition")

        if any(pattern in lower_pwd for pattern in self.keyboard_patterns):
            score -= 15
            feedback.append("Warning: Contains keyboard pattern")

        if user_info:
            for key, value in user_info.items():
                if value and value.lower() in lower_pwd:
                    score -= 25
                    feedback.append(f"Warning: Contains personal info ({key})!")

        for pattern in self.personal_info_patterns:
            if re.search(pattern, password):
                score -= 10
                feedback.append("Warning: Contains date-like pattern")

        words = re.split(r'[\W_]+', lower_pwd)
        if any(word in self.common_words for word in words if word):
            score -= 10
            feedback.append("Warning: Contains common dictionary words")

        if zxcvbn:
            try:
                zxcvbn_result = zxcvbn.zxcvbn(password)
                crack_time = zxcvbn_result['crack_times_display']['offline_slow_hashing_1e4_per_second']
                feedback.append(f"Estimated crack time: {crack_time}")
                score += min(20, int(zxcvbn_result['score'] * 5))
            except Exception:
                feedback.append("zxcvbn unavailable")

        entropy = self._calculate_entropy(password)
        entropy_bonus = min(20, int(entropy / 10))
        score += entropy_bonus

        if is_passphrase and char_diversity >= 3:
            score += 10
            feedback.append("Bonus: Strong passphrase detected")

        score = min(max(0, score), 100)

        strength_levels = [(40, "Weak"), (60, "Moderate"), (80, "Strong"), (100, "Very Strong")]
        strength = next((level for threshold, level in strength_levels if score <= threshold), "Very Strong")

        improvement_tips = []
        if score < 80:
            if length < 12:
                improvement_tips.append("Increase length to 12+ characters")
            if char_diversity < 3:
                improvement_tips.append("Add more character types (upper, lower, numbers, special)")
            if is_passphrase:
                improvement_tips.append("Use less predictable words in your passphrase")
            else:
                improvement_tips.append("Consider a passphrase with 3+ unique words")
            if any(f.startswith("Warning") for f in feedback):
                improvement_tips.append("Avoid common patterns or personal info")

        analysis_time = time.time() - start_time
        return {
            "score": score,
            "strength": strength,
            "feedback": feedback,
            "entropy": entropy,
            "analysis_time": analysis_time,
            "improvement_tips": improvement_tips
        }


class PasswordCheckerGUI:
    def __init__(self, root):
        self.checker = PasswordStrengthChecker("common_passwords.txt")
        self.root = root
        self.root.title("Password Strength Analyzer")
        self.root.geometry("800x650")
        self.root.resizable(True, True)
        
        # Apply modern theme
        self.root.set_theme("arc")
        self.style = ttk.Style()
        self.style.configure("TLabel", font=("Helvetica", 10))
        self.style.configure("TButton", font=("Helvetica", 10))
        
        # Main container with padding
        self.main_frame = ttk.Frame(root, padding="15")
        self.main_frame.grid(row=0, column=0, sticky="nsew")
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        # Header
        header = ttk.Label(self.main_frame, text="Password Strength Analyzer", 
                         font=("Helvetica", 16, "bold"), anchor="center")
        header.grid(row=0, column=0, pady=(0, 15))

        # Input Section
        self.create_input_section()
        
        # Results Section
        self.create_results_section()
        
        # Bind Enter key to check password
        self.root.bind("<Return>", lambda e: self.check_password())

    def create_input_section(self):
        input_container = ttk.Frame(self.main_frame)
        input_container.grid(row=1, column=0, sticky="ew", pady=5)
        
        # Password Input
        pwd_frame = ttk.LabelFrame(input_container, text="Password", padding="10")
        pwd_frame.grid(row=0, column=0, sticky="ew", pady=5)
        pwd_frame.grid_columnconfigure(1, weight=1)
        
        self.password_entry = ttk.Entry(pwd_frame, width=40, show="•")
        self.password_entry.grid(row=0, column=0, padx=5, pady=5, sticky="ew")
        
        self.show_var = tk.BooleanVar()
        show_check = ttk.Checkbutton(pwd_frame, text="Show", variable=self.show_var,
                                   command=self.toggle_password, style="Toggle.TButton")
        show_check.grid(row=0, column=1, padx=5)
        
        # Buttons
        btn_frame = ttk.Frame(input_container)
        btn_frame.grid(row=1, column=0, pady=10)
        ttk.Button(btn_frame, text="Analyze", command=self.check_password,
                  style="Accent.TButton").grid(row=0, column=0, padx=5)
        ttk.Button(btn_frame, text="Generate", command=self.generate_password).grid(row=0, column=1, padx=5)
        self.copy_button = ttk.Button(btn_frame, text="Copy", command=self.copy_to_clipboard,
                                    state="disabled")
        self.copy_button.grid(row=0, column=2, padx=5)
        
        # User Info
        user_frame = ttk.LabelFrame(input_container, text="Optional Context", padding="10")
        user_frame.grid(row=2, column=0, sticky="ew", pady=5)
        user_frame.grid_columnconfigure(1, weight=1)
        
        ttk.Label(user_frame, text="Name:").grid(row=0, column=0, padx=5, pady=2)
        self.name_entry = ttk.Entry(user_frame)
        self.name_entry.grid(row=0, column=1, padx=5, pady=2, sticky="ew")
        
        ttk.Label(user_frame, text="Birth Year:").grid(row=1, column=0, padx=5, pady=2)
        self.year_entry = ttk.Entry(user_frame)
        self.year_entry.grid(row=1, column=1, padx=5, pady=2, sticky="ew")

    def create_results_section(self):
        result_frame = ttk.LabelFrame(self.main_frame, text="Analysis Results", padding="10")
        result_frame.grid(row=2, column=0, sticky="nsew", pady=5)
        result_frame.grid_rowconfigure(1, weight=1)
        result_frame.grid_columnconfigure(0, weight=1)
        
        # Strength Meter
        meter_frame = ttk.Frame(result_frame)
        meter_frame.grid(row=0, column=0, pady=5, sticky="ew")
        
        self.strength_label = ttk.Label(meter_frame, text="Strength: N/A",
                                      font=("Helvetica", 12, "bold"))
        self.strength_label.grid(row=0, column=0, padx=5)
        
        self.score_progress = ttk.Progressbar(meter_frame, length=300, maximum=100,
                                            style="green.Horizontal.TProgressbar")
        self.score_progress.grid(row=0, column=1, padx=5, sticky="ew")
        meter_frame.grid_columnconfigure(1, weight=1)
        
        # Results Display
        self.result_text = scrolledtext.ScrolledText(result_frame, width=80, height=20,
                                                   wrap=tk.WORD, font=("Consolas", 10))
        self.result_text.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")
        
        self.main_frame.grid_rowconfigure(2, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)

    def toggle_password(self):
        self.password_entry.config(show="" if self.show_var.get() else "•")

    def set_strength_color(self, strength: str):
        colors = {
            "Weak": "#ff4444",
            "Moderate": "#ffbb33",
            "Strong": "#00C851",
            "Very Strong": "#007E33",
            "Invalid": "#aaaaaa"
        }
        self.strength_label.config(text=f"Strength: {strength}",
                                 foreground=colors.get(strength, "black"))
        style_name = f"{strength}.Horizontal.TProgressbar"
        self.style.configure(style_name, troughcolor="#e0e0e0",
                           background=colors.get(strength, "black"))
        self.score_progress.configure(style=style_name)

    def check_password(self):
        password = self.password_entry.get()
        user_info = {
            "name": self.name_entry.get().strip(),
            "birthyear": self.year_entry.get().strip()
        }
        user_info = {k: v for k, v in user_info.items() if v}
        
        result = self.checker.assess_password_strength(password, user_info)
        self.display_result(result)
        self.copy_button.config(state="normal" if password else "disabled")

    def generate_password(self):
        import secrets
        import string
        chars = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
        pwd = ''.join(secrets.choice(chars) for _ in range(16))
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, pwd)
        self.check_password()

    def copy_to_clipboard(self):
        password = self.password_entry.get()
        if password:
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            messagebox.showinfo("Success", "Password copied to clipboard!", parent=self.root)

    def display_result(self, result: Dict[str, any]):
        self.set_strength_color(result["strength"])
        self.score_progress["value"] = result["score"]
        self.result_text.delete(1.0, tk.END)
        
        # Format output with better readability
        self.result_text.insert(tk.END, f"Score: {result['score']}/100\n", "header")
        self.result_text.insert(tk.END, f"Entropy: {result['entropy']} bits\n", "header")
        self.result_text.insert(tk.END, f"Analysis Time: {result['analysis_time']:.3f}s\n\n", "header")
        
        self.result_text.insert(tk.END, "Feedback:\n", "section")
        for item in result['feedback']:
            tag = "warning" if item.startswith("Warning") else "info"
            self.result_text.insert(tk.END, f"• {item}\n", tag)
        
        if result['improvement_tips']:
            self.result_text.insert(tk.END, "\nImprovement Tips:\n", "section")
            for tip in result['improvement_tips']:
                self.result_text.insert(tk.END, f"• {tip}\n", "tip")
        
        # Configure tags for styling
        self.result_text.tag_configure("header", font=("Consolas", 10, "bold"))
        self.result_text.tag_configure("section", font=("Consolas", 10, "bold"), foreground="#0066cc")
        self.result_text.tag_configure("warning", foreground="#cc0000")
        self.result_text.tag_configure("info", foreground="#333333")
        self.result_text.tag_configure("tip", foreground="#006600")

def main():
    root = ThemedTk(theme="arc")
    app = PasswordCheckerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()