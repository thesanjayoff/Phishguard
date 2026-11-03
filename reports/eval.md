# PhishGuard evaluation (offline, held-out)

generated 2026-11-03 19:29; thresholds: suspicious>=35, phishing>=70
No network lookups (domain age, feeds, Safe Browsing) and no containers were used, so these numbers cover the static layers only.

NOTE: the OS refused to open 3 Nazario file(s) (20051114.mbox, phishing-2015, phishing-2023) - most likely blocked by antivirus real-time protection. They were skipped, not worked around; results use the remaining files.

## real corpora: Nazario phishing vs SpamAssassin ham
702 phishing / 1164 legitimate

**rules only (no classifier)**
- flagged (suspicious or phishing): precision 0.934  recall 0.745  F1 0.829  FP 37/1164 (3.18%)  FN 179/702   [TP 523 FP 37 FN 179 TN 1127]
- phishing verdict only        : precision 0.994  recall 0.224  F1 0.365  FP 1/1164 (0.09%)  FN 545/702   [TP 157 FP 1 FN 545 TN 1163]
- worst false positives: 73 '[Lockergnome Windows Daily] Dignity Shakedown' [url.brand_combosquat; url.brand_subdomain; content.lure_prize] | 66 'Terry Pratchett - AuthorTracker News from HarperCollins' [hdr.display_name_email; url.email_in_link; url.http_login] | 64 '[Lockergnome Windows Daily] Deeper Uplink' [url.brand_combosquat; url.brand_subdomain; content.urgency] | 61 '[Lockergnome Windows Daily] Medieval Mocha' [url.brand_combosquat; url.brand_subdomain; content.form_in_email] | 60 'THE WEEK IN REVIEW: Harvest at Macworld' [content.account_threat; url.text_mismatch_other; url.email_in_link] | 59 'The ISO17799 Newsletter - Issue 4' [content.credential_request; content.account_threat; url.generated_domain] | 59 'How Microsoft plans to take over your living room [ANCHORDES' [content.payment_request; url.text_mismatch_other; url.email_in_link] | 58 '[Lockergnome Windows Daily] Beefier Vinyl' [url.brand_combosquat; url.brand_subdomain; content.click_cta]
- sample misses: 0 'DON'T DELETE THIS MESSAGE -- FOLDER INTERNAL DATA' [nazario] | 0 'Review your Document' [nazario] | 0 'Attention: Email Account Holder Kindly View Your Attached Fi' [nazario] | 0 '=?utf-8?Q?Por=20favor=2c=20atualize=20suas=20informa=c3=a7=c' [nazario] | 0 'We could not complete your transaction.' [nazario] | 0 'Confirmation' [nazario] | 0 'New enterprise notification' [nazario] | 0 'George Lancaster shared an Onshape folder with you' [nazario]

**rules + classifier**
- flagged (suspicious or phishing): precision 0.974  recall 0.979  F1 0.977  FP 18/1164 (1.55%)  FN 15/702   [TP 687 FP 18 FN 15 TN 1146]
- phishing verdict only        : precision 1.000  recall 0.858  F1 0.923  FP 0/1164 (0.00%)  FN 100/702   [TP 602 FP 0 FN 100 TN 1164]
- worst false positives: 61 '[Lockergnome Windows Daily] Dignity Shakedown' [url.brand_combosquat; url.brand_subdomain; content.lure_prize] | 60 'Terry Pratchett - AuthorTracker News from HarperCollins' [hdr.display_name_email; url.email_in_link; url.http_login] | 52 '[Lockergnome Windows Daily] Deeper Uplink' [url.brand_combosquat; url.brand_subdomain; content.urgency] | 50 'Delayed Mail (still being retried)' [hdr.display_name_typo] | 49 '[Lockergnome Windows Daily] Medieval Mocha' [url.brand_combosquat; url.brand_subdomain; content.form_in_email] | 48 'The ISO17799 Newsletter - Issue 4' [content.credential_request; content.account_threat; url.generated_domain] | 48 'THE WEEK IN REVIEW: Harvest at Macworld' [content.account_threat; url.text_mismatch_other; url.email_in_link] | 48 'How Microsoft plans to take over your living room [ANCHORDES' [content.payment_request; url.text_mismatch_other; url.email_in_link]
- sample misses: 0 'DON'T DELETE THIS MESSAGE -- FOLDER INTERNAL DATA' [nazario] | 0 'Extend your account for free' [nazario] | 9 'Invitation to join 4Ny9gvu MEETING WITH WITTHH 39tmvz4' [nazario] | 10 'Order Confirmation 26189 to Charles King on 2025-September-1' [nazario] | 17 'Your order has shipped!' [nazario] | 19 'Confirmation' [nazario] | 19 'Extend your account for free' [nazario] | 22 'Disputed debit card transactions' [nazario]

## synthetic held-out wording (GoPhish-style email, India SMS/chat scams, hard-negative legit mail)
220 phishing / 180 legitimate

**rules only (no classifier)**
- flagged (suspicious or phishing): precision 1.000  recall 1.000  F1 1.000  FP 0/180 (0.00%)  FN 0/220   [TP 220 FP 0 FN 0 TN 180]
- phishing verdict only        : precision 1.000  recall 0.714  F1 0.833  FP 0/180 (0.00%)  FN 63/220   [TP 157 FP 0 FN 63 TN 180]

**rules + classifier**
- flagged (suspicious or phishing): precision 0.957  recall 1.000  F1 0.978  FP 10/180 (5.56%)  FN 0/220   [TP 220 FP 10 FN 0 TN 170]
- phishing verdict only        : precision 1.000  recall 0.850  F1 0.919  FP 0/180 (0.00%)  FN 33/220   [TP 187 FP 0 FN 33 TN 180]
- worst false positives: 43 '[GitHub] A new device signed in to your account' [content.ml_classifier; content.credential_request; hdr.auth_pass_brand] | 43 '[GitHub] A new device signed in to your account' [content.ml_classifier; content.credential_request; hdr.auth_pass_brand] | 43 '[GitHub] A new device signed in to your account' [content.ml_classifier; content.credential_request; hdr.auth_pass_brand] | 43 '[GitHub] A new device signed in to your account' [content.ml_classifier; content.credential_request; hdr.auth_pass_brand] | 43 '[GitHub] A new device signed in to your account' [content.ml_classifier; content.credential_request; hdr.auth_pass_brand] | 43 '[GitHub] A new device signed in to your account' [content.ml_classifier; content.credential_request; hdr.auth_pass_brand] | 43 '[GitHub] A new device signed in to your account' [content.ml_classifier; content.credential_request; hdr.auth_pass_brand] | 43 '[GitHub] A new device signed in to your account' [content.ml_classifier; content.credential_request; hdr.auth_pass_brand]

## synthetic India SMS/chat only
120 phishing / 50 legitimate

**rules only (no classifier)**
- flagged (suspicious or phishing): precision 1.000  recall 1.000  F1 1.000  FP 0/50 (0.00%)  FN 0/120   [TP 120 FP 0 FN 0 TN 50]
- phishing verdict only        : precision 1.000  recall 0.750  F1 0.857  FP 0/50 (0.00%)  FN 30/120   [TP 90 FP 0 FN 30 TN 50]

**rules + classifier**
- flagged (suspicious or phishing): precision 1.000  recall 1.000  F1 1.000  FP 0/50 (0.00%)  FN 0/120   [TP 120 FP 0 FN 0 TN 50]
- phishing verdict only        : precision 1.000  recall 0.833  F1 0.909  FP 0/50 (0.00%)  FN 20/120   [TP 100 FP 0 FN 20 TN 50]
