import re

class SafeSpacesEngine:
    def __init__(self):
        # Localized risk dictionary capturing Nigerian slang context & predatory behaviors
        self.abuse_patterns = [
            r"(?i)\b(send|drop|share)\b.*\b(nudes|picha|pic|photo|image)\b",
            r"(?i)\b(pay|send money|naira|transfer)\b.*\b(else|expose|post|leak)\b",
            r"(?i)\b(don't tell)\b.*\b(anyone|your mom|your parents|teacher)\b"
        ]
        # PII Protection: Matches common Nigerian mobile structures (+234, 080, 090, 070)
        self.phone_pattern = r"(\+234|0)\d{8}"

    def audit_message(self, text: str) -> dict:
        risk_score = 0.0
        flags = []
        
        # 1. Evaluate Contextual Abuse & Extortion
        for pattern in self.abuse_patterns:
            if re.search(pattern, text):
                risk_score += 0.50
                flags.append("Predatory/Harassment Pattern Detected")
                
        # 2. Prevent Private Metrics and Data Leakage
        if re.search(self.phone_pattern, text):
            risk_score += 0.40
            flags.append("Sensitive PII Exposure Intercepted")
            text = re.sub(self.phone_pattern, "[PROTECTED PHONE NUMBER]", text)

        return {
            "sanitized_text": text,
            "risk_score": min(risk_score, 1.0),
            "threats_flagged": flags,
            "action_required": "BLOCK_AND_FLAG" if risk_score >= 0.40 else "ALLOW"
        }

if __name__ == "__main__":
    guard = SafeSpacesEngine()
    test_chat = "Send me your pic or I will leak it to everyone. Call me on 08031234567"
    result = guard.audit_message(test_chat)
    print(f"Sanitized Outputs: {result['sanitized_text']}")
    print(f"Calculated Threat Level: {result['risk_score']}")
