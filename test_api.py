from openai import OpenAI

key = "sk-4d3bda6826c24abe85bdfd5035350201"

print("Testing DeepSeek API directly...")
try:
    client = OpenAI(base_url="https://api.deepseek.com", api_key=key)
    response = client.chat.completions.create(
        model="deepseek-chat",
        messages=[{"role": "user", "content": "Hello"}],
        max_tokens=5
    )
    print("SUCCESS deepseek-chat:", response.choices[0].message.content)
except Exception as e:
    print("ERROR deepseek-chat:", e)
    
print("Testing DeepSeek API with deepseek-reasoner...")
try:
    client = OpenAI(base_url="https://api.deepseek.com", api_key=key)
    response = client.chat.completions.create(
        model="deepseek-reasoner",
        messages=[{"role": "user", "content": "Hello"}],
        max_tokens=5
    )
    print("SUCCESS deepseek-reasoner:", response.choices[0].message.content)
except Exception as e:
    print("ERROR deepseek-reasoner:", e)
