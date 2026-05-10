from google import genai

# 2. Choose the model (Flash is fast and free)
client = genai.Client(api_key="")

# 3. Create a fake, suspicious email to test
fake_email = """
SUBJECT: URGENT: Your HDFC Bank Account is LOCKED
Body: Dear Customer, we noticed suspicious activity on your account. 
Please click here immediately to verify your identity or your funds will be frozen in 24 hours: 
http://secure-login-hdfc-update.com/login
"""

prompt = f"""
You are an expert cybersecurity analyst. Read the following email and tell me if it is a phishing scam.
Keep your answer to exactly two sentences.

Email:
{fake_email}
"""

print("Thinking...")
# 2. Use the new syntax to generate content
response = client.models.generate_content(
    model='gemini-2.5-flash',
    contents=prompt
)

print("\n--- AI VERDICT ---")
print(response.text)