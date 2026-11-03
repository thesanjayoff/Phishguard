# PhishGuard evaluation (offline, held-out)

generated 2026-11-03 20:13; thresholds: suspicious>=35, phishing>=70
No network lookups (domain age, feeds, Safe Browsing) and no containers were used, so these numbers cover the static layers only.

NOTE: the OS refused to open 3 Nazario file(s) (20051114.mbox, phishing-2015, phishing-2023) - most likely blocked by antivirus real-time protection. They were skipped, not worked around; results use the remaining files.

## real corpora: Nazario phishing vs SpamAssassin ham
699 phishing / 1163 legitimate

**rules only (no classifier)**
- flagged (suspicious or phishing): precision 0.935  recall 0.744  F1 0.829  FP 36/1163 (3.10%)  FN 179/699   [TP 520 FP 36 FN 179 TN 1127]
- phishing verdict only        : precision 0.993  recall 0.217  F1 0.357  FP 1/1163 (0.09%)  FN 547/699   [TP 152 FP 1 FN 547 TN 1162]
- worst false positives: 73 '[Lockergnome Windows Daily] Dignity Shakedown' [url.brand_combosquat; url.brand_subdomain; content.lure_prize] | 66 'Terry Pratchett - AuthorTracker News from HarperCollins' [hdr.display_name_email; url.email_in_link; url.http_login] | 64 '[Lockergnome Windows Daily] Deeper Uplink' [url.brand_combosquat; url.brand_subdomain; content.urgency] | 61 '[Lockergnome Windows Daily] Medieval Mocha' [url.brand_combosquat; url.brand_subdomain; content.form_in_email] | 60 'THE WEEK IN REVIEW: Harvest at Macworld' [content.account_threat; url.text_mismatch_other; url.email_in_link] | 59 'The ISO17799 Newsletter - Issue 4' [content.credential_request; content.account_threat; url.generated_domain] | 59 'How Microsoft plans to take over your living room [ANCHORDES' [content.payment_request; url.text_mismatch_other; url.email_in_link] | 58 '[Lockergnome Windows Daily] Beefier Vinyl' [url.brand_combosquat; url.brand_subdomain; content.click_cta]
- sample misses: 0 'DON'T DELETE THIS MESSAGE -- FOLDER INTERNAL DATA' [nazario] | 0 'Review your Document' [nazario] | 0 'Attention: Email Account Holder Kindly View Your Attached Fi' [nazario] | 0 'Sie wurden für eine Spende von Warren BUFFETT CHARITABLE FOU' [nazario] | 0 '您有（4）条未送达的邮件' [nazario] | 0 'We could not complete your transaction.' [nazario] | 0 'Confirmation' [nazario] | 0 'New enterprise notification' [nazario]

**rules + classifier**
- flagged (suspicious or phishing): precision 0.976  recall 0.977  F1 0.976  FP 17/1163 (1.46%)  FN 16/699   [TP 683 FP 17 FN 16 TN 1146]
- phishing verdict only        : precision 1.000  recall 0.850  F1 0.919  FP 0/1163 (0.00%)  FN 105/699   [TP 594 FP 0 FN 105 TN 1163]
- worst false positives: 61 '[Lockergnome Windows Daily] Dignity Shakedown' [url.brand_combosquat; url.brand_subdomain; content.lure_prize] | 60 'Terry Pratchett - AuthorTracker News from HarperCollins' [hdr.display_name_email; url.email_in_link; url.http_login] | 52 '[Lockergnome Windows Daily] Deeper Uplink' [url.brand_combosquat; url.brand_subdomain; content.urgency] | 49 '[Lockergnome Windows Daily] Medieval Mocha' [url.brand_combosquat; url.brand_subdomain; content.form_in_email] | 48 'The ISO17799 Newsletter - Issue 4' [content.credential_request; content.account_threat; url.generated_domain] | 48 'THE WEEK IN REVIEW: Harvest at Macworld' [content.account_threat; url.text_mismatch_other; url.email_in_link] | 48 'How Microsoft plans to take over your living room [ANCHORDES' [content.payment_request; url.text_mismatch_other; url.email_in_link] | 46 '[Lockergnome Windows Daily] Beefier Vinyl' [url.brand_combosquat; url.brand_subdomain; content.click_cta]
- sample misses: 0 'DON'T DELETE THIS MESSAGE -- FOLDER INTERNAL DATA' [nazario] | 0 'Extend your account for free' [nazario] | 3 'Sie wurden für eine Spende von Warren BUFFETT CHARITABLE FOU' [nazario] | 10 'Invitation to join 4Ny9gvu MEETING WITH WITTHH 39tmvz4' [nazario] | 14 'Order Confirmation 26189 to Charles King on 2025-September-1' [nazario] | 17 'Your order has shipped!' [nazario] | 19 'Confirmation' [nazario] | 19 'Extend your account for free' [nazario]

## URL only: OpenPhish community feed (300 live phishing URLs, never used for tuning) vs links found in legitimate mail
300 phishing / 461 legitimate

**rules only (no classifier)**
- flagged (suspicious or phishing): precision 0.875  recall 0.047  F1 0.089  FP 2/461 (0.43%)  FN 286/300   [TP 14 FP 2 FN 286 TN 459]
- phishing verdict only        : precision nan  recall 0.000  F1 nan  FP 0/461 (0.00%)  FN 300/300   [TP 0 FP 0 FN 300 TN 461]
- worst false positives: 44 'http://216.239.39.100/search?q=cache:usJnd2dwCDQC:' [url.ip_host; url.very_long] | 40 'http://64.78.49.204/' [url.ip_host]
- sample misses: 0 'https://portuil.my/11/#YW50amUuc2NobGl0emt1c0BiZXJ' [openphish] | 0 'https://s.team-qs.com/p/kma-mhc/bwjejeij' [openphish] | 0 'https://webasdhf.com/' [openphish] | 0 'https://lumen-ba.com/10302026.html' [openphish] | 0 'https://sso-security.com/E.Cq7P94af46KqmA?=userid&' [openphish] | 0 'https://rbcode.net/v/a411129f0d1c60749a84f448852e7' [openphish] | 0 'http://regularizeseunomegov.discloud.dev/' [openphish] | 0 'http://poshmarkusashop.com/' [openphish]

**rules + classifier**
- flagged (suspicious or phishing): precision 0.986  recall 0.477  F1 0.643  FP 2/461 (0.43%)  FN 157/300   [TP 143 FP 2 FN 157 TN 459]
- phishing verdict only        : precision 1.000  recall 0.030  F1 0.058  FP 0/461 (0.00%)  FN 291/300   [TP 9 FP 0 FN 291 TN 461]
- worst false positives: 44 'http://216.239.39.100/search?q=cache:usJnd2dwCDQC:' [url.ip_host; url.very_long] | 40 'http://64.78.49.204/' [url.ip_host]
- sample misses: 0 'http://regularizeseunomegov.discloud.dev/' [openphish] | 0 'http://poshmarkusashop.com/' [openphish] | 0 'http://nqhzofzx7b.hdply.com/' [openphish] | 0 'https://radiowavesokc.homedns.org/cgi-bin/index.ha' [openphish] | 0 'http://roblox.com.et/users/727220164/profile' [openphish] | 0 'http://quintessential-magenta-iu9wrbhh-dph50c8lhhl' [openphish] | 0 'http://methodical-labeling-017677.framer.app/' [openphish] | 0 'http://py-login-site.onrender.com/' [openphish]

## synthetic held-out wording (GoPhish-style email, India SMS/chat scams, hard-negative legit mail)
220 phishing / 180 legitimate

**rules only (no classifier)**
- flagged (suspicious or phishing): precision 1.000  recall 1.000  F1 1.000  FP 0/180 (0.00%)  FN 0/220   [TP 220 FP 0 FN 0 TN 180]
- phishing verdict only        : precision 1.000  recall 0.714  F1 0.833  FP 0/180 (0.00%)  FN 63/220   [TP 157 FP 0 FN 63 TN 180]

**rules + classifier**
- flagged (suspicious or phishing): precision 0.957  recall 1.000  F1 0.978  FP 10/180 (5.56%)  FN 0/220   [TP 220 FP 10 FN 0 TN 170]
- phishing verdict only        : precision 1.000  recall 0.850  F1 0.919  FP 0/180 (0.00%)  FN 33/220   [TP 187 FP 0 FN 33 TN 180]
- worst false positives: 44 '[GitHub] A new device signed in to your account' [content.ml_classifier; content.credential_request; hdr.auth_pass_brand] | 44 '[GitHub] A new device signed in to your account' [content.ml_classifier; content.credential_request; hdr.auth_pass_brand] | 44 '[GitHub] A new device signed in to your account' [content.ml_classifier; content.credential_request; hdr.auth_pass_brand] | 44 '[GitHub] A new device signed in to your account' [content.ml_classifier; content.credential_request; hdr.auth_pass_brand] | 44 '[GitHub] A new device signed in to your account' [content.ml_classifier; content.credential_request; hdr.auth_pass_brand] | 44 '[GitHub] A new device signed in to your account' [content.ml_classifier; content.credential_request; hdr.auth_pass_brand] | 44 '[GitHub] A new device signed in to your account' [content.ml_classifier; content.credential_request; hdr.auth_pass_brand] | 44 '[GitHub] A new device signed in to your account' [content.ml_classifier; content.credential_request; hdr.auth_pass_brand]

## synthetic India SMS/chat only
120 phishing / 50 legitimate

**rules only (no classifier)**
- flagged (suspicious or phishing): precision 1.000  recall 1.000  F1 1.000  FP 0/50 (0.00%)  FN 0/120   [TP 120 FP 0 FN 0 TN 50]
- phishing verdict only        : precision 1.000  recall 0.750  F1 0.857  FP 0/50 (0.00%)  FN 30/120   [TP 90 FP 0 FN 30 TN 50]

**rules + classifier**
- flagged (suspicious or phishing): precision 1.000  recall 1.000  F1 1.000  FP 0/50 (0.00%)  FN 0/120   [TP 120 FP 0 FN 0 TN 50]
- phishing verdict only        : precision 1.000  recall 0.833  F1 0.909  FP 0/50 (0.00%)  FN 20/120   [TP 100 FP 0 FN 20 TN 50]
