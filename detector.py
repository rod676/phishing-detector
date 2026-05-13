import json
from openai import OpenAI
from dotenv import load_dotenv
import os
from analyzer import analyze_url, analyze_email_text

load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

SYSTEM_PROMPT = """
You are an expert cybersecurity analyst specializing in phishing detection.
You analyze URLs and email content to identify phishing attempts.

Your analysis must be:
- Precise and technical
- Actionable (what should the user do?)
- Clear for non-technical users

Always respond in English.
"""

def gpt_analyze(technical_data: dict, input_type: str) -> dict:
    """GPT analyzes the technical data and produces a final verdict."""
    
    prompt = f"""
Analyze this {input_type} for phishing indicators:

Technical analysis results:
{json.dumps(technical_data, indent=2)}

Return ONLY this JSON without backticks:
{{
    "verdict": "SAFE | SUSPICIOUS | DANGEROUS",
    "confidence": 85,
    "risk_score": 7,
    "summary": "One sentence verdict for non-technical users",
    "main_threats": ["threat1", "threat2"],
    "recommended_action": "What the user should do right now",
    "technical_explanation": "Detailed explanation for security professionals"
}}
"""
    
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt}
        ],
        temperature=0.2,
        max_tokens=600
    )
    
    raw = response.choices[0].message.content.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    
    return json.loads(raw)


def detect_phishing_url(url: str) -> dict:
    """Pipeline complet : analyse URL + verdict GPT."""
    
    print(f"🔍 Analyzing URL: {url}")
    technical = analyze_url(url)
    verdict = gpt_analyze(technical, "URL")
    
    return {
        "input": url,
        "type": "URL",
        "technical": technical,
        "verdict": verdict
    }


def detect_phishing_email(email_text: str) -> dict:
    """Pipeline complet : analyse email + verdict GPT."""
    
    print(f"🔍 Analyzing email content...")
    technical = analyze_email_text(email_text)
    verdict = gpt_analyze(technical, "email")
    
    return {
        "input": email_text[:100] + "...",
        "type": "Email",
        "technical": technical,
        "verdict": verdict
    }