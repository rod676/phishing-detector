import streamlit as st
from detector import detect_phishing_url, detect_phishing_email

st.set_page_config(
    page_title="Phishing Detector",
    page_icon="🛡️",
    layout="centered"
)

st.title("🛡️ AI Phishing Detector")
st.caption("Analyze URLs and emails for phishing attempts — Powered by GPT-4o")
st.divider()

tab1, tab2 = st.tabs(["🔗 Analyze URL", "📧 Analyze Email"])

# Tab URL
with tab1:
    url_input = st.text_input(
        "Enter URL to analyze",
        placeholder="https://suspicious-site.com/login"
    )
    
    if st.button("Analyze URL", type="primary"):
        if url_input:
            with st.spinner("🔍 Analyzing..."):
                result = detect_phishing_url(url_input)
                verdict = result["verdict"]
                technical = result["technical"]
                
                # Verdict principal
                color_map = {
                    "SAFE": "✅",
                    "SUSPICIOUS": "⚠️",
                    "DANGEROUS": "🚨"
                }
                emoji = color_map.get(verdict["verdict"], "❓")
                
                st.subheader(f"{emoji} Verdict: {verdict['verdict']}")
                st.write(verdict["summary"])
                
                # Métriques
                col1, col2, col3 = st.columns(3)
                col1.metric("Risk Score", f"{verdict['risk_score']}/10")
                col2.metric("Confidence", f"{verdict['confidence']}%")
                col3.metric("HTTPS", "✅" if technical["uses_https"] else "❌")
                
                # Action recommandée
                st.info(f"**Recommended Action:** {verdict['recommended_action']}")
                
                # Détails techniques
                with st.expander("🔧 Technical Details"):
                    if technical["risk_indicators"]:
                        st.error("Risk indicators found:")
                        for indicator in technical["risk_indicators"]:
                            st.write(f"• {indicator}")
                    
                    st.write(f"**Domain:** {technical['domain']}")
                    st.write(f"**IP Address:** {technical.get('ip_address', 'Unknown')}")
                    
                    if technical["redirects"]:
                        st.write(f"**Redirects:** {' → '.join(technical['redirects'])}")
                
                with st.expander("📖 Technical Explanation"):
                    st.write(verdict["technical_explanation"])
        else:
            st.warning("Please enter a URL")

# Tab Email
with tab2:
    email_input = st.text_area(
        "Paste email content",
        placeholder="Paste the full email text here...",
        height=200
    )
    
    if st.button("Analyze Email", type="primary"):
        if email_input:
            with st.spinner("🔍 Analyzing email..."):
                result = detect_phishing_email(email_input)
                verdict = result["verdict"]
                technical = result["technical"]
                
                color_map = {
                    "SAFE": "✅",
                    "SUSPICIOUS": "⚠️",
                    "DANGEROUS": "🚨"
                }
                emoji = color_map.get(verdict["verdict"], "❓")
                
                st.subheader(f"{emoji} Verdict: {verdict['verdict']}")
                st.write(verdict["summary"])
                
                col1, col2 = st.columns(2)
                col1.metric("Risk Score", f"{verdict['risk_score']}/10")
                col2.metric("Confidence", f"{verdict['confidence']}%")
                
                st.info(f"**Recommended Action:** {verdict['recommended_action']}")
                
                with st.expander("🔧 Detected Patterns"):
                    if technical["urgency_indicators"]:
                        st.warning(f"Urgency words: {', '.join(technical['urgency_indicators'])}")
                    if technical["threat_indicators"]:
                        st.error(f"Threat words: {', '.join(technical['threat_indicators'])}")
                    if technical["urls_found"]:
                        st.write(f"URLs found: {len(technical['urls_found'])}")
                        for url in technical["urls_found"]:
                            st.code(url)
        else:
            st.warning("Please paste email content")

st.divider()
st.caption("Built by Olade Roland Sagbo · Cybersecurity & AI · Hamburg 🇩🇪")