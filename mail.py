import smtplib
from email.message import EmailMessage

# Your email credentials
sender_email = "projectassignemntcmp@gmail.com"
sender_password = "idsgehkptunfmqww"  # Use an App Password if 2FA is enabled

# Receiver and message
receiver_email = "ahmedyasser200211@gmail.com"
subject = "Test Email"
body = "Hello! This is a test email sent using Python."

# Compose email
msg = EmailMessage()
msg['Subject'] = subject
msg['From'] = sender_email
msg['To'] = receiver_email
msg.set_content(body)

# Send email
try:
    with smtplib.SMTP("smtp.gmail.com", 587) as smtp:
        smtp.starttls()
        smtp.login(sender_email, sender_password)
        smtp.send_message(msg)
    print("Email sent successfully!")
except Exception as e:
    print("Error sending email:", e)
