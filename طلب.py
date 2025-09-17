import requests
import json

# الإعدادات
USER_ID = "2306259016"  # غير هذا إلى الأيدي المطلوب
URL = "http://localhost:5000/spam"

# إرسال الطلب
try:
    response = requests.post(
        URL,
        json={"user_id": USER_ID},
        headers={"Content-Type": "application/json"}
    )
    
    print(f"كود الحالة: {response.status_code}")
    print(f"الرد: {response.json()}")
    
except Exception as e:
    print(f"خطأ: {e}")