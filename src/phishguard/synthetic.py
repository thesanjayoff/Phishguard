"""Original synthetic test data: GoPhish-style phishing campaigns, India-specific SMS/chat scams and
realistic legitimate mail (including hard negatives that mention accounts, security and links).

Templates carry a `variant`: 0 = used for training augmentation, 1 = held out for evaluation, so
evaluation measures generalisation to unseen wording rather than memorised templates.
All domains are invented; nothing here is real phishing content."""
from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import format_datetime

from .models import Message
from .parsing.email_parser import from_sms, from_text, parse_email

TLDS = ["xyz", "top", "click", "info", "online", "site", "icu", "live", "support", "work", "co", "cc", "buzz", "shop"]
NAMES = ["Rahul", "Priya", "Amit", "Sneha", "Vikram", "Anita", "John", "Maria", "David", "Neha"]
BRANDS = [
    ("PayPal", "paypal.com", "paypal"), ("Microsoft", "microsoft.com", "microsoft"), ("Apple", "apple.com", "apple"),
    ("Amazon", "amazon.in", "amazon"), ("Netflix", "netflix.com", "netflix"), ("HDFC Bank", "hdfcbank.com", "hdfcbank"),
    ("State Bank of India", "sbi.co.in", "sbi"), ("ICICI Bank", "icicibank.com", "icicibank"), ("Google", "google.com", "google"),
    ("DHL", "dhl.com", "dhl"), ("Axis Bank", "axisbank.com", "axisbank"), ("Dropbox", "dropbox.com", "dropbox"),
]
WORDS = ["secure", "login", "verify", "update", "account", "support", "service", "alert", "id", "portal", "kyc", "billing"]


@dataclass
class Sample:
    msg: Message
    label: int  # 1 phishing, 0 legitimate
    family: str
    variant: int
    channel: str  # email | sms | chat


def lookalike(rng: random.Random, key: str) -> str:
    tld = rng.choice(TLDS)
    w = rng.choice(WORDS)
    style = rng.randrange(5)
    if style == 0:
        return f"{key}-{w}.{tld}"
    if style == 1:
        return f"{w}-{key}.{tld}"
    if style == 2:
        k = key.replace("l", "1", 1) if "l" in key else key.replace("o", "0", 1) if "o" in key else key + "s"
        return f"{k}.{tld}"
    if style == 3:
        return f"{key}.{w}-{rng.randrange(10, 99)}.{tld}"
    return f"{key}{w}.{tld}"


def _auth(kind: str, domain: str) -> str:
    return {
        "pass": f"mx.google.com; spf=pass smtp.mailfrom={domain}; dkim=pass header.d={domain}; dmarc=pass header.from={domain}",
        "fail": f"mx.google.com; spf=fail smtp.mailfrom={domain}; dkim=none; dmarc=fail header.from={domain}",
        "softfail": f"mx.google.com; spf=softfail smtp.mailfrom={domain}; dkim=none; dmarc=none header.from={domain}",
        "none": f"mx.google.com; spf=none; dkim=none; dmarc=none header.from={domain}",
    }[kind]


def make_email(*, from_name: str, from_addr: str, subject: str, text: str, html: str | None = None, reply_to: str = "",
               return_path: str = "", auth: str = "none", attachments: list[tuple[str, str, bytes]] | None = None,
               to: str = "me@example.org", in_reply_to: str = "") -> Message:
    m = EmailMessage()
    m["From"] = f"{from_name} <{from_addr}>" if from_name else from_addr
    m["To"] = to
    m["Subject"] = subject
    m["Date"] = format_datetime(datetime(2026, 10, 20, 9, 30, tzinfo=timezone.utc))
    m["Message-ID"] = f"<{random.Random(subject).randrange(10**9)}@{from_addr.split('@')[-1]}>"
    if reply_to:
        m["Reply-To"] = reply_to
    if return_path:
        m["Return-Path"] = f"<{return_path}>"
    if in_reply_to:
        m["In-Reply-To"] = in_reply_to
    if auth != "missing":
        m["Authentication-Results"] = _auth(auth, from_addr.split("@")[-1])
    m.set_content(text)
    if html:
        m.add_alternative(html, subtype="html")
    for fname, ctype, data in attachments or []:
        mt, st = ctype.split("/")
        m.add_attachment(data, maintype=mt, subtype=st, filename=fname)
    return parse_email(m.as_bytes(), source="synthetic")


# ---------------------------------------------------------------------------------------------
# Phishing emails (GoPhish-style campaigns)
# ---------------------------------------------------------------------------------------------
def _p_password_expiry(rng, v):
    brand = rng.choice([b for b in BRANDS if b[0] in ("Microsoft", "Google", "Apple", "Dropbox")])
    dom = lookalike(rng, brand[2])
    name = rng.choice(NAMES)
    if v == 0:
        text = f"Hello {name},\n\nYour {brand[0]} password will expire in 24 hours. To keep the same password, confirm your account now.\n\nKeep my password: https://{dom}/signin?u={name.lower()}\n\n{brand[0]} IT Support"
        subj = f"Action required: your {brand[0]} password expires today"
    else:
        text = f"Dear user,\n\nOur records show the password for {name.lower()}@yourcompany.com is about to lapse. Failure to verify within 12 hours will lead to the suspension of your mailbox.\n\nVerify now -> https://{dom}/auth/verify\n\nThanks,\nHelpdesk"
        subj = "Mailbox password expiration notice"
    html = f"<p>{text.splitlines()[0]}</p><p><a href='https://{dom}/signin'>https://login.{brand[1]}/keep-password</a></p>" if rng.random() < 0.5 else None
    return make_email(from_name=f"{brand[0]} Support", from_addr=f"it-support@{dom}" if rng.random() < .5 else f"noreply@{rng.choice(['gmail.com','outlook.com'])}",
                      subject=subj, text=text, html=html, auth=rng.choice(["fail", "none", "softfail", "pass"]))


def _p_unusual_signin(rng, v):
    brand = rng.choice([b for b in BRANDS if b[0] in ("Google", "Microsoft", "Apple", "Netflix", "Amazon")])
    dom = lookalike(rng, brand[2])
    if v == 0:
        text = f"We detected an unusual sign-in to your {brand[0]} account from a new device (Moscow, Russia).\nIf this was not you, secure your account immediately: https://{dom}/secure-account\nIf you do not respond within 24 hours your account will be locked."
        subj = f"Security alert: unusual sign-in on your {brand[0]} account"
    else:
        text = f"Suspicious activity has been noticed on your {brand[0]} ID. Your account has been temporarily restricted. Please review and confirm your identity to restore access: https://{dom}/restore\n\nThis is an automated message."
        subj = f"Your {brand[0]} account has been limited"
    return make_email(from_name=f"{brand[0]} Security", from_addr=f"security@{dom}", subject=subj, text=text, auth=rng.choice(["fail", "none", "pass"]))


def _p_invoice_callback(rng, v):
    brand = rng.choice([b for b in BRANDS if b[0] in ("PayPal", "Amazon", "Apple", "Microsoft")])
    amt = rng.choice(["$499.99", "$289.00", "Rs. 24,999", "$1,249.50"])
    if v == 0:
        text = f"Thank you for your purchase. An amount of {amt} has been charged to your account for your {brand[0]} subscription (Invoice #{rng.randrange(10**6, 10**7)}).\n\nIf you did not authorise this transaction, call our billing department immediately on +1 (888) 555-01{rng.randrange(10, 99)} to cancel and get a refund."
        subj = f"Invoice {rng.randrange(10**6, 10**7)} - payment received"
    else:
        text = f"Your order has been processed and {amt} will be debited today. To dispute this charge please contact our support helpline at 1-800-555-01{rng.randrange(10, 99)} within 24 hours."
        subj = f"Receipt: {brand[0]} renewal"
    return make_email(from_name=f"{brand[0]} Billing", from_addr=f"billing{rng.randrange(100)}@{rng.choice(['gmail.com', 'outlook.com', lookalike(rng, brand[2])])}",
                      subject=subj, text=text, auth=rng.choice(["none", "softfail", "fail"]),
                      attachments=[("invoice.pdf", "application/pdf", b"%PDF-1.4 synthetic")] if rng.random() < 0.3 else None)


def _p_shared_doc(rng, v):
    dom = lookalike(rng, rng.choice(["sharepoint", "onedrive", "docusign", "dropbox"]))
    name = rng.choice(NAMES)
    if v == 0:
        text = f"{name} has shared a document with you: 'Q4 Payment Advice.pdf'\nOpen the file here: https://{dom}/view/{rng.randrange(10**8)}\nThis link will expire in 48 hours."
        subj = f"{name} shared 'Q4 Payment Advice' with you"
    else:
        text = f"You have received a secure message with an attached invoice from {name}. Review and sign the document online below.\nhttps://{dom}/sign\nTo protect your privacy the message will be deleted soon."
        subj = "Please review and sign: payment remittance"
    html = f"<html><body><p>{text.splitlines()[0]}</p><a href='https://{dom}/x' style='background:#0078d4;color:#fff'>https://onedrive.live.com/view</a></body></html>"
    return make_email(from_name=f"{name} (via OneDrive)", from_addr=f"share@{dom}", subject=subj, text=text, html=html, auth=rng.choice(["none", "fail", "pass"]))


def _p_bank_kyc_email(rng, v):
    brand = rng.choice([b for b in BRANDS if b[0] in ("HDFC Bank", "State Bank of India", "ICICI Bank", "Axis Bank")])
    dom = lookalike(rng, brand[2])
    if v == 0:
        text = f"Dear Customer,\n\nYour {brand[0]} account KYC has expired. As per RBI guidelines your account will be blocked within 24 hours if you do not update your KYC. Update now: https://{dom}/kyc\n\nPAN and Aadhaar details are required.\n\nRegards,\n{brand[0]}"
        subj = f"{brand[0]} KYC update required - account will be suspended"
    else:
        text = f"Dear Valued Customer, your netbanking access has been deactivated due to incomplete KYC. Re-activate your account immediately by confirming your card number, PIN and OTP at https://{dom}/reactivate. Avoid penalty.\n"
        subj = f"Important: Net banking blocked - {brand[0]}"
    return make_email(from_name=brand[0], from_addr=f"alerts@{dom}", subject=subj, text=text, auth=rng.choice(["fail", "none", "softfail"]))


def _p_delivery_fee(rng, v):
    brand = rng.choice([b for b in BRANDS if b[0] == "DHL"] + [("India Post", "indiapost.gov.in", "indiapost"), ("FedEx", "fedex.com", "fedex")])
    dom = lookalike(rng, brand[2])
    if v == 0:
        text = f"Your parcel {rng.randrange(10**9, 10**10)} could not be delivered because the address is incomplete. A redelivery fee of Rs 49 is required. Pay here: https://{dom}/pay\nThe parcel will be returned in 48 hours."
        subj = f"{brand[0]}: delivery attempt failed"
    else:
        text = f"Customs clearance is pending for your shipment. Please pay the import duty of $2.99 to release the package: https://{dom}/customs. Unpaid shipments are destroyed after 3 days."
        subj = f"Your {brand[0]} package is on hold"
    return make_email(from_name=f"{brand[0]} Express", from_addr=f"tracking@{dom}", subject=subj, text=text, auth=rng.choice(["none", "fail"]))


def _p_hr_benefits(rng, v):
    dom = rng.choice([lookalike(rng, "payroll"), "hr-benefits-portal." + rng.choice(TLDS)])
    if v == 0:
        text = "Hi,\n\nHR has published the updated employee benefits and salary revision for 2026. All staff must log in with their network credentials to acknowledge the policy by end of day.\nhttps://" + dom + "/staff\nHuman Resources"
        subj = "Updated salary & benefits - action required"
    else:
        text = "Team,\n\nThe annual compensation statement is ready. Sign in with your corporate username and password to view your bonus: https://" + dom + "/bonus\n\nPlease do it today, access closes tonight."
        subj = "Your 2026 bonus statement"
    return make_email(from_name="HR Department", from_addr=f"hr@{dom}", subject=subj, text=text, auth=rng.choice(["none", "pass", "fail"]))


def _p_crypto_wallet(rng, v):
    dom = lookalike(rng, rng.choice(["binance", "coinbase", "metamask"]))
    if v == 0:
        text = f"Your wallet has been flagged for unusual activity. Verify your wallet and enter your recovery phrase to prevent suspension: https://{dom}/validate"
        subj = "Wallet verification required"
    else:
        text = f"You are eligible for an exclusive airdrop of 2,000 tokens. Connect your wallet to claim before it expires: https://{dom}/claim"
        subj = "Claim your airdrop"
    return make_email(from_name="Support Team", from_addr=f"support@{dom}", subject=subj, text=text, auth="none")


def _p_bec_giftcards(rng, v):
    name = rng.choice(NAMES)
    if v == 0:
        text = f"Hi,\n\nAre you available? I need you to handle a quick task for me. I am in a meeting and cannot take calls. I need 5 Amazon gift cards of $100 each for clients. Keep this between us, I will reimburse you.\n\n{name}"
        subj = "Quick favor"
    else:
        text = f"Please change the bank account for our next vendor payment to the new details attached. It is urgent, the wire must go out today. Do not call, I am travelling.\n\n{name}\nCEO"
        subj = "Urgent payment request"
    return make_email(from_name=f"{name} Kumar", from_addr=f"{name.lower()}.ceo{rng.randrange(99)}@{rng.choice(['gmail.com','outlook.com','yahoo.com'])}",
                      reply_to=f"{name.lower()}{rng.randrange(99)}@{rng.choice(['gmail.com','proton.me'])}", subject=subj, text=text, auth="none")


def _p_html_attachment(rng, v):
    text = "Please find the attached remittance. Open in your browser and log in with your email to view the payment details.\nPassword: 1234" if v == 0 else "Your voicemail is attached. Open the file and sign in to listen."
    return make_email(from_name="Accounts", from_addr=f"accounts@{lookalike(rng, 'billing')}", subject="Payment remittance advice" if v == 0 else "New voicemail",
                      text=text, auth="none", attachments=[("remittance.html", "text/html", b"<html><form action='http://x.example/p'><input type=password></form></html>")])


# ---------------------------------------------------------------------------------------------
# Phishing SMS / chat (India-focused)
# ---------------------------------------------------------------------------------------------
def _s_kyc(rng, v):
    b = rng.choice([x for x in BRANDS if x[0] in ("HDFC Bank", "State Bank of India", "ICICI Bank", "Axis Bank")])
    dom = lookalike(rng, b[2])
    t = (f"Dear customer, your {b[0]} account will be blocked today. Update your PAN/KYC immediately: http://{dom}/kyc"
         if v == 0 else f"{b[0]}: KYC pending. Your a/c is suspended. Complete e-KYC now http://{dom} or visit branch. Ignore if done.")
    return from_sms(t, rng.choice(["+91" + str(rng.randrange(7 * 10**9, 10**10)), "VK-" + b[2].upper()[:6], ""]))


def _s_upi_refund(rng, v):
    t = ("Rs 4,999 was credited to your UPI by mistake. Please accept the collect request and enter your UPI PIN to return the amount."
         if v == 0 else "Your PhonePe cashback refund of Rs 1,250 is pending. Scan the QR code and enter PIN to receive money now: bit.ly/3x" + str(rng.randrange(999)))
    return from_sms(t, "+91" + str(rng.randrange(7 * 10**9, 10**10)))


def _s_courier(rng, v):
    dom = lookalike(rng, rng.choice(["indiapost", "delhivery", "bluedart", "dtdc"]))
    t = (f"India Post: your parcel is held, address incomplete. Pay Rs 25 redelivery fee at {dom}/track to avoid return."
         if v == 0 else f"Delhivery: delivery failed. Customs fee of Rs 89 pending. Reschedule and pay: http://{dom}/in")
    return from_sms(t, rng.choice(["", "AX-DLHVRY", "+91" + str(rng.randrange(7 * 10**9, 10**10))]))


def _s_electricity(rng, v):
    t = ("Dear consumer, your electricity connection will be disconnected tonight at 9:30 PM because the last month bill was not updated. Call officer 98" + str(rng.randrange(10**8)).zfill(8) + " immediately."
         if v == 0 else "BESCOM: power supply to your meter will be cut today as bill unpaid. Contact electricity officer on WhatsApp 70" + str(rng.randrange(10**8)).zfill(8) + " to update.")
    return from_sms(t, "+91" + str(rng.randrange(7 * 10**9, 10**10)))


def _s_job(rng, v):
    t = (f"Part time job offer! Earn Rs {rng.choice([3000, 5000, 8000])} per day by liking YouTube videos. No investment. Message HR on WhatsApp wa.me/91{rng.randrange(7 * 10**9, 10**10)}"
         if v == 0 else "Hiring work from home data entry, salary 25,000/- per month, daily payment, registration fee Rs 500 refundable. Join our Telegram group t.me/jobs" + str(rng.randrange(999)))
    return from_text(t, kind="chat")


def _s_tax_refund(rng, v):
    dom = lookalike(rng, "incometax")
    t = (f"Income Tax Dept: your ITR refund of Rs 15,490 is approved. Verify your bank account at http://{dom} to claim."
         if v == 0 else f"You are eligible for tax refund Rs 23,200. Click http://{dom}/refund and update account details today.")
    return from_sms(t, "")


def _s_sim_telecom(rng, v):
    t = ("Your SIM will be blocked in 2 hours as per TRAI KYC rules. Call 98" + str(rng.randrange(10**8)).zfill(8) + " immediately to avoid disconnection."
         if v == 0 else "Mobile number deactivated soon due to incomplete verification. Update now to continue service: http://" + lookalike(rng, "airtel") + "/kyc")
    return from_sms(t, rng.choice(["", "+91" + str(rng.randrange(7 * 10**9, 10**10))]))


def _s_fastag_challan(rng, v):
    dom = lookalike(rng, rng.choice(["fastag", "echallan", "parivahan"]))
    t = (f"Your FASTag is blocked due to pending KYC. Update immediately http://{dom}/fastag"
         if v == 0 else f"Traffic e-challan of Rs 500 pending for your vehicle. Pay within 24 hours to avoid court notice: {dom}/pay")
    return from_sms(t, "")


def _s_loan_rewards(rng, v):
    dom = lookalike(rng, rng.choice(["hdfcbank", "sbi", "icicibank"]))
    t = (f"Dear customer your credit card reward points worth Rs {rng.choice([4500, 9850, 12400])} will expire today. Redeem now: http://{dom}/redeem"
         if v == 0 else f"Pre-approved instant loan of Rs 2,00,000 sanctioned. No CIBIL, no documents, approved in 5 minutes. Apply: http://{dom}/loan")
    return from_sms(t, rng.choice(["", "VM-" + "HDFCBK"]))


def _s_digital_arrest(rng, v):
    t = ("This is Mumbai Police cyber cell. A parcel in your name containing drugs was seized by customs. A warrant has been issued, you are under digital arrest. Join the video call on Skype immediately."
         if v == 0 else "CBI notice: your Aadhaar is linked to a money laundering case. Do not disconnect. Contact officer on WhatsApp now to avoid arrest.")
    return from_text(t, kind="chat")


def _s_investment(rng, v):
    t = ("Join our VIP stock tips group on Telegram. Guaranteed returns, SEBI registered analyst, double your money in 30 days. t.me/vipstocks" + str(rng.randrange(999))
         if v == 0 else "Free IPO allotment tips and daily profit of Rs 20,000 with our trading signals channel. Join WhatsApp group now: chat.whatsapp.com/Abc" + str(rng.randrange(999)))
    return from_text(t, kind="chat")


def _s_otp_phish(rng, v):
    t = ("Bank security alert: someone tried to login to your account. Share the OTP you received with our executive to cancel the request."
         if v == 0 else "Your account will be locked. Reply with your OTP and ATM PIN to verify your identity.")
    return from_sms(t, "+91" + str(rng.randrange(7 * 10**9, 10**10)))


PHISH_EMAIL = [_p_password_expiry, _p_unusual_signin, _p_invoice_callback, _p_shared_doc, _p_bank_kyc_email, _p_delivery_fee,
               _p_hr_benefits, _p_crypto_wallet, _p_bec_giftcards, _p_html_attachment]
PHISH_MSG = [_s_kyc, _s_upi_refund, _s_courier, _s_electricity, _s_job, _s_tax_refund, _s_sim_telecom, _s_fastag_challan,
             _s_loan_rewards, _s_digital_arrest, _s_investment, _s_otp_phish]


# ---------------------------------------------------------------------------------------------
# Legitimate mail (including hard negatives)
# ---------------------------------------------------------------------------------------------
def _l_order(rng, v):
    n = rng.randrange(10**6, 10**7)
    text = (f"Hello {rng.choice(NAMES)},\n\nThank you for your order #{n}. We'll send you a confirmation when your item ships.\n\nView or manage your order: https://www.amazon.in/gp/your-account/order-details?orderID={n}\n\nAmazon.in"
            if v == 0 else f"Your order has shipped! Order {n} will arrive on Friday. Track your package: https://www.amazon.in/progress-tracker/package?orderId={n}\nReturns are free within 30 days.")
    return make_email(from_name="Amazon.in", from_addr="auto-confirm@amazon.in", subject=f"Your Amazon.in order #{n}", text=text, auth="pass")


def _l_newsletter(rng, v):
    text = ("This week in tech: new Python release, a deep dive into SQLite internals and our favourite open source tools.\n\nRead online: https://news.example-tech.com/issue/142\nUnsubscribe: https://news.example-tech.com/unsub?id=991\n"
            if v == 0 else "Hi there, our October roundup is out. Highlights include a guide to database indexing, the community spotlight, and upcoming meetups.\n\nRead more: https://go.sendgrid.net/track/abc\nTo stop receiving these emails, unsubscribe here: https://blog.example-dev.org/unsubscribe")
    html = f"<p>{text.splitlines()[0]}</p><p><a href='https://u123.ct.sendgrid.net/ls/click?upn=abc'>https://blog.example-dev.org/october-roundup</a></p>"
    return make_email(from_name="Dev Weekly", from_addr="news@mail.example-dev.org", return_path="bounce@sendgrid.net", subject="Dev Weekly #142" if v == 0 else "October roundup", text=text, html=html, auth="pass")


def _l_github(rng, v):
    text = ("@octocat commented on pull request #482: Fix flaky test in cache module\n\nLooks good to me, merging after CI is green.\n\nView it on GitHub: https://github.com/example/proj/pull/482#issuecomment-1\n"
            if v == 0 else "A new sign-in to your GitHub account\n\nWe noticed a new sign in from Chrome on Windows. If this was you, no action is needed. If not, review your security settings at https://github.com/settings/security\n")
    return make_email(from_name="GitHub", from_addr="notifications@github.com", subject="Re: [example/proj] Fix flaky test (#482)" if v == 0 else "[GitHub] A new device signed in to your account", text=text, auth="pass")


def _l_bank_statement(rng, v):
    text = ("Dear Customer,\n\nYour HDFC Bank credit card statement for October is now available. Total amount due: Rs 12,450. Due date: 05-Nov-2026.\nLog in to NetBanking at https://netbanking.hdfcbank.com to view or pay. We never ask for your PIN or OTP over email.\n"
            if v == 0 else "Dear Customer, your account statement for the month ending 31-Oct is attached. Password is your date of birth in DDMMYYYY. For queries contact us at https://www.hdfcbank.com/contact. Please do not share your OTP with anyone.")
    return make_email(from_name="HDFC Bank", from_addr="emailstatements.cc@hdfcbank.net", subject="HDFC Bank Credit Card Statement - October", text=text, auth="pass",
                      attachments=[("statement.pdf", "application/pdf", b"%PDF-1.4 synthetic statement")] if v == 1 else None)


def _l_password_reset(rng, v):
    text = ("We received a request to reset your Google password. Use this link within an hour: https://accounts.google.com/signin/recovery?token=abc\n\nIf you didn't request this, you can safely ignore this email."
            if v == 0 else "Someone (hopefully you) asked to reset the password for your Spotify account. Reset it here: https://accounts.spotify.com/password-reset?t=xyz. If it wasn't you, nothing will change.")
    return make_email(from_name="Google" if v == 0 else "Spotify", from_addr="no-reply@accounts.google.com" if v == 0 else "no-reply@spotify.com",
                      subject="Reset your password", text=text, auth="pass")


def _l_security_alert(rng, v):
    text = ("Security alert\n\nYour Google Account was just signed in to from a new Windows device. If this was you, you don't need to do anything. If not, we'll help you secure your account: https://myaccount.google.com/notifications\n"
            if v == 0 else "We noticed a login to your Microsoft account from a new location. If this was you, ignore this message. Otherwise review recent activity at https://account.microsoft.com/activity.")
    return make_email(from_name="Google" if v == 0 else "Microsoft account team", from_addr="no-reply@accounts.google.com" if v == 0 else "account-security-noreply@accountprotection.microsoft.com",
                      subject="Security alert" if v == 0 else "Microsoft account security info", text=text, auth="pass")


def _l_colleague(rng, v):
    name = rng.choice(NAMES)
    text = (f"Hi,\n\nCan we move tomorrow's standup to 10:30? I have a clash with the vendor call. Notes from last week are in the shared drive.\n\nThanks,\n{name}"
            if v == 0 else f"Hey, quick update on the migration: staging is up, I've shared the runbook in Confluence. Let's review it Thursday afternoon and decide on the cutover date.\n\n{name}")
    return make_email(from_name=f"{name} Sharma", from_addr=f"{name.lower()}.sharma@company-example.com", subject="Re: standup tomorrow" if v == 0 else "Migration update", text=text, auth="pass", in_reply_to="<abc@company-example.com>")


def _l_travel(rng, v):
    pnr = rng.randrange(10**9, 10**10)
    text = (f"Your e-ticket is confirmed. PNR {pnr}. Train 12627 Karnataka Express, 12 Nov, sleeper class. Download your ticket from https://www.irctc.co.in/nget/booking/ticket. Wish you a happy journey."
            if v == 0 else f"Booking confirmed! Your flight 6E 554 on 14 Nov. PNR {pnr}. Web check-in opens 48 hours before departure: https://www.goindigo.in/web-check-in.html")
    return make_email(from_name="IRCTC" if v == 0 else "IndiGo", from_addr="ticketadmin@irctc.co.in" if v == 0 else "booking@goindigo.in", subject=f"E-ticket PNR {pnr}", text=text, auth="pass")


def _l_receipt(rng, v):
    text = ("Thanks for your payment of $9.99 to Netflix. Your next billing date is 4 Dec 2026. Manage your membership: https://www.netflix.com/youraccount"
            if v == 0 else "Receipt from Dropbox: your Plus subscription renewed for $11.99. You can view the invoice at https://www.dropbox.com/account/billing. Questions? Reply to this email.")
    return make_email(from_name="Netflix" if v == 0 else "Dropbox", from_addr="info@mailer.netflix.com" if v == 0 else "no-reply@dropbox.com", subject="Your Netflix payment receipt" if v == 0 else "Your Dropbox receipt", text=text, auth="pass")


def _l_calendar(rng, v):
    text = "Invitation: Project review @ Thu Nov 5, 2026 3pm - 4pm (IST)\nJoining info: https://meet.google.com/abc-defg-hij\nOrganiser: priya@company-example.com" if v == 0 else "You have been invited to a Zoom meeting.\nTopic: Quarterly planning\nJoin: https://zoom.us/j/9876543210\nMeeting ID: 987 654 3210"
    return make_email(from_name="Priya" if v == 0 else "Zoom", from_addr="priya@company-example.com" if v == 0 else "no-reply@zoom.us", subject="Invitation: Project review" if v == 0 else "Quarterly planning meeting", text=text, auth="pass")


def _l_university(rng, v):
    text = ("Dear students, the library will remain open until 10 pm during exam week. Please carry your ID card. Timetable: https://www.example-university.edu/exams\n\nRegistrar's office"
            if v == 0 else "Reminder: the guest lecture on machine learning is on Friday at 4 pm in Hall B. All are welcome. Slides will be posted on the course page afterwards.")
    return make_email(from_name="Registrar Office", from_addr="registrar@example-university.edu", subject="Exam week library timings" if v == 0 else "Guest lecture on Friday", text=text, auth="pass")


def _l_utility_bill(rng, v):
    text = ("Dear consumer, your electricity bill for October is Rs 1,842, due on 12-Nov. Pay online at https://www.bescom.co.in or through your preferred UPI app. Ignore if already paid."
            if v == 0 else "Your Tata Power bill of Rs 2,310 is ready. Pay by the due date to avoid late fee. Download the bill from the consumer portal at https://www.tatapower.com/ddl/.")
    return make_email(from_name="BESCOM" if v == 0 else "Tata Power", from_addr="noreply@bescom.co.in" if v == 0 else "ddlcare@tatapower.com", subject="Electricity bill for October" if v == 0 else "Your bill is ready", text=text, auth="pass")


def _l_marketing(rng, v):
    text = ("Big Billion Sale starts tomorrow! Up to 70% off on electronics. Limited time offers - hurry, deals end Sunday.\nShop now: https://www.flipkart.com/sale\nUnsubscribe: https://www.flipkart.com/unsub"
            if v == 0 else "Last chance: your cart is waiting! Items in your bag are selling fast. Complete your order today: https://www.myntra.com/checkout\nYou are receiving this because you signed up at myntra.com.")
    html = f"<p>{text.splitlines()[0]}</p><a href='https://email.flipkart.com/click?id=1'>Shop now</a>"
    return make_email(from_name="Flipkart" if v == 0 else "Myntra", from_addr="offers@flipkart.com" if v == 0 else "newsletter@myntra.com", subject="Sale starts tomorrow" if v == 0 else "Your cart is waiting", text=text, html=html, auth="pass")


def _l_sms_otp(rng, v):
    otp = rng.randrange(100000, 999999)
    t = (f"{otp} is your OTP for transaction of Rs.{rng.randrange(100, 9999)} at AMAZON. OTP valid for 10 minutes. Do not share OTP with anyone. -HDFC Bank"
         if v == 0 else f"Your SBI OTP is {otp}. Never share this OTP with anyone, including bank staff. -SBI")
    return from_sms(t, rng.choice(["VM-HDFCBK", "AX-SBIINB", "JD-ICICIB"]))


def _l_sms_txn(rng, v):
    t = (f"Rs {rng.randrange(100, 9999)}.00 debited from A/c XX{rng.randrange(1000, 9999)} on 03-Nov-26 to VPA friend@oksbi. UPI Ref {rng.randrange(10**11, 10**12)}. Avl Bal Rs {rng.randrange(1000, 90000)}. Not you? Call 1800 1080 -SBI"
         if v == 0 else f"INR {rng.randrange(100, 9999)}.00 credited to A/c XX{rng.randrange(1000, 9999)} on 03-11-26 by NEFT. Avl bal INR {rng.randrange(1000, 90000)}. -ICICI Bank")
    return from_sms(t, rng.choice(["AX-SBIINB", "VM-ICICIB", "VK-HDFCBK"]))


def _l_sms_courier_otp(rng, v):
    t = (f"Your Delhivery package will be delivered today. Share OTP {rng.randrange(1000, 9999)} with the delivery partner only. Track: https://www.delhivery.com/track"
         if v == 0 else f"Swiggy: your order is out for delivery, arriving in 15 mins. Delivery partner: Ravi 98{rng.randrange(10**8)}. Track on the Swiggy app.")
    return from_sms(t, "VM-DLHVRY" if v == 0 else "AD-SWIGGY")


def _l_sms_misc(rng, v):
    personal = "+91" + str(rng.randrange(7 * 10**9, 10**10))
    if v == 0:
        t = rng.choice(["Hey, are we still on for lunch tomorrow at 1?", "Mom: please call me when you are free", "Reminder: dentist appointment on Thursday at 4:30 pm at Smile Clinic."])
        return from_sms(t, personal)
    t, sender = rng.choice([("Your Jio recharge of Rs 299 is successful. Validity till 02-Dec. Thank you.", "JM-JIOPAY"),
                            ("Your EPF passbook updated. Check the UMANG app for details. -EPFO", "VK-EPFOHO"),
                            ("Meeting moved to 3 pm, same room.", personal)])
    return from_sms(t, sender)


def _l_chat(rng, v):
    t = ("Check out this article on the new RBI guidelines about digital lending: https://www.rbi.org.in/Scripts/NotificationUser.aspx?Id=1 - useful for the team"
         if v == 0 else "Here is the doc we talked about, https://docs.google.com/document/d/abc123/edit - let me know your comments by Friday")
    return from_text(t, kind="chat")


LEGIT_EMAIL = [_l_order, _l_newsletter, _l_github, _l_bank_statement, _l_password_reset, _l_security_alert, _l_colleague, _l_travel,
               _l_receipt, _l_calendar, _l_university, _l_utility_bill, _l_marketing]
LEGIT_MSG = [_l_sms_otp, _l_sms_txn, _l_sms_courier_otp, _l_sms_misc, _l_chat]


def generate(n_per_family: int = 6, variants: tuple[int, ...] = (0, 1), seed: int = 1337) -> list[Sample]:
    rng = random.Random(seed)
    out: list[Sample] = []
    for fams, label, ch_for in ((PHISH_EMAIL, 1, "email"), (PHISH_MSG, 1, None), (LEGIT_EMAIL, 0, "email"), (LEGIT_MSG, 0, None)):
        for fn in fams:
            for v in variants:
                for _ in range(n_per_family):
                    msg = fn(rng, v)
                    out.append(Sample(msg, label, fn.__name__.lstrip("_"), v, ch_for or msg.kind))
    return out
