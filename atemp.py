import streamlit as st
import imaplib
import email
import re
import smtplib
from email.header import decode_header
from bs4 import BeautifulSoup
import requests
import machine_learning as ml
import feature_extraction as fe
import matplotlib.pyplot as plt

# ==================== Cấu hình Email ====================
st.sidebar.header("Cấu hình Email")
EMAIL = st.sidebar.text_input("Email của bạn")
PASSWORD = st.sidebar.text_input("Mật khẩu ứng dụng", type="password")
ALERT_EMAIL = st.sidebar.text_input("Email nhận cảnh báo")
IMAP_SERVER = "imap.gmail.com"
SMTP_SERVER = "smtp.gmail.com"

# ==================== Phần chính ứng dụng ====================
st.title('Phishing Detection System')
tab1, tab2 = st.tabs(["Website Check", "Email Scan"])

with tab1:
    # ... (Giữ nguyên phần giao diện website check của bạn) ...

with tab2:
    st.header("Email Phishing Scanner")
    
    if st.button("Start Email Scan"):
        if not all([EMAIL, PASSWORD, ALERT_EMAIL]):
            st.error("Vui lòng điền đầy đủ thông tin cấu hình email!")
        else:
            with st.spinner("Đang quét email..."):
                try:
                    # Kết nối IMAP
                    mail = imaplib.IMAP4_SSL(IMAP_SERVER)
                    mail.login(EMAIL, PASSWORD)
                    mail.select("inbox")

                    # Tìm email chưa đọc
                    status, messages = mail.search(None, 'UNSEEN')
                    phishing_count = 0

                    if status == 'OK' and messages[0]:
                        for mail_id in messages[0].split():
                            status, msg_data = mail.fetch(mail_id, '(RFC822)')
                            email_msg = email.message_from_bytes(msg_data[0][1])
                            
                            urls = []
                            for part in email_msg.walk():
                                content_type = part.get_content_type()
                                body = part.get_payload(decode=True)
                                
                                if body and content_type in ["text/html", "text/plain"]:
                                    decoded_body = body.decode(errors='ignore')
                                    urls += re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', decoded_body)
                                    
                                    if content_type == "text/html":
                                        soup = BeautifulSoup(decoded_body, 'html.parser')
                                        urls += [link['href'] for link in soup.find_all('a', href=True)]

                            # Kiểm tra từng URL
                            for url in set(urls):
                                try:
                                    response = requests.get(url, verify=False, timeout=5)
                                    if response.status_code == 200:
                                        soup = BeautifulSoup(response.content, "html.parser")
                                        vector = [fe.create_vector(soup)]
                                        result = ml.rf_model.predict(vector)  # Sử dụng model Random Forest
                                        
                                        if result[0] == 1:
                                            phishing_count += 1
                                            # Gửi cảnh báo
                                            with smtplib.SMTP(SMTP_SERVER, 587) as server:
                                                server.starttls()
                                                server.login(EMAIL, PASSWORD)
                                                message = f"""Subject: PHISHING ALERT!
                                                Phishing URL detected: {url}
                                                From email: {email_msg['From']}
                                                """
                                                server.sendmail(EMAIL, ALERT_EMAIL, message)
                                            
                                            # Đánh dấu email
                                            mail.store(mail_id, '+FLAGS', '\\Seen')
                                            mail.copy(mail_id, 'Phishing')
                                            mail.store(mail_id, '+FLAGS', '\\Deleted')
                                            
                                except Exception as e:
                                    st.error(f"Lỗi khi kiểm tra URL {url}: {str(e)}")

                        st.success(f"Quét hoàn tất! Phát hiện {phishing_count} URL phishing.")
                        mail.expunge()
                        mail.close()
                        mail.logout()
                        
                    else:
                        st.info("Không có email mới cần kiểm tra.")

                except Exception as e:
                    st.error(f"Lỗi kết nối email: {str(e)}")

# ==================== Phần còn lại của ứng dụng ====================
# ... (Giữ nguyên các phần khác của ứng dụng) ...