"""Regenerates src/phishguard/data/brands.json and lists.json (hand-curated knowledge)."""
import json
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "src" / "phishguard" / "data"
B = []


def b(n, c, d, a=None, k=None, region="global"):
    keys = (k.split("|") if isinstance(k, str) else k) if k is not None else [n.lower().replace(" ", "")]
    B.append({
        "n": n, "c": c, "d": d.split(),
        "a": a.split("|") if a else [n.lower()],
        "k": [x for x in keys if x], "r": region,
    })


# ---- global
b("PayPal", "payment", "paypal.com paypal.me paypal-communications.com paypal.co.uk paypal.de paypal.fr paypal.in paypalobjects.com")
b("Apple", "tech", "apple.com icloud.com me.com itunes.com apple.news appleid.com", a="apple|apple id|icloud|itunes|apple support", k="apple|icloud|appleid|itunes")
b("Microsoft", "tech", "microsoft.com microsoftonline.com live.com outlook.com office.com office365.com sharepoint.com onedrive.com azure.com windows.com xbox.com msn.com hotmail.com skype.com bing.com", a="microsoft|office 365|office365|microsoft 365|onedrive|outlook|sharepoint|microsoft account|microsoft support|xbox|skype", k="microsoft|office365|onedrive|outlook|sharepoint|hotmail")
b("Google", "tech", "google.com gmail.com googlemail.com youtube.com goog.gle google.co.in withgoogle.com googleusercontent.com", a="google|gmail|google drive|google docs|google security|youtube", k="google|gmail|gooogle")
b("Amazon", "retail", "amazon.com amazon.in amazon.co.uk amazon.de amazon.co.jp amazon.ca amazon.fr amazon.it amazon.es amazon.com.au amazon.ae amazonaws.com amazonses.com amazon.jobs primevideo.com audible.com", a="amazon|amazon prime|amazon pay|prime video|amazon web services|aws", k="amazon|amazn|amzon")
b("Netflix", "media", "netflix.com nflxext.com", k="netflix")
b("Facebook / Meta", "social", "facebook.com facebookmail.com fb.com meta.com instagram.com whatsapp.com messenger.com fb.me", a="facebook|meta|instagram|whatsapp|messenger", k="facebook|instagram|whatsapp")
b("LinkedIn", "social", "linkedin.com lnkd.in", k="linkedin")
b("X (Twitter)", "social", "twitter.com x.com t.co", a="twitter|x corp", k="twitter")
b("Telegram", "social", "telegram.org t.me telegram.me", k="telegram")
b("Dropbox", "tech", "dropbox.com dropboxmail.com dropboxusercontent.com", k="dropbox")
b("DocuSign", "tech", "docusign.com docusign.net", k="docusign")
b("Adobe", "tech", "adobe.com adobesign.com echosign.com", a="adobe|adobe sign|adobe acrobat", k="adobe")
b("Zoom", "tech", "zoom.us zoom.com", a="zoom|zoom video", k="zoom")
b("WeTransfer", "tech", "wetransfer.com we.tl", k="wetransfer")
b("Chase", "bank", "chase.com jpmorgan.com jpmorganchase.com", a="chase|jpmorgan|jp morgan", k="chasebank|jpmorgan")
b("Bank of America", "bank", "bankofamerica.com bofa.com ml.com", a="bank of america|bofa", k="bankofamerica|bofa")
b("Wells Fargo", "bank", "wellsfargo.com wf.com", a="wells fargo", k="wellsfargo")
b("Citibank", "bank", "citi.com citibank.com citigroup.com citibank.co.in", a="citi|citibank|citigroup", k="citibank")
b("HSBC", "bank", "hsbc.com hsbc.co.in hsbc.co.uk hsbc.com.hk", k="hsbc")
b("Barclays", "bank", "barclays.com barclays.co.uk", k="barclays")
b("Standard Chartered", "bank", "sc.com standardchartered.com", a="standard chartered", k="standardchartered")
b("American Express", "payment", "americanexpress.com aexp.com amex.com", a="american express|amex", k="americanexpress")
b("Visa", "payment", "visa.com", a="visa", k="visacard")
b("Mastercard", "payment", "mastercard.com", k="mastercard")
b("Coinbase", "crypto", "coinbase.com", k="coinbase")
b("Binance", "crypto", "binance.com binance.us", k="binance")
b("Spotify", "media", "spotify.com", k="spotify")
b("Steam", "gaming", "steampowered.com steamcommunity.com valvesoftware.com", a="steam|steam support", k="steampowered|steamcommunity")
b("eBay", "retail", "ebay.com ebay.in ebay.co.uk ebay.de", a="ebay", k="ebay")
b("Walmart", "retail", "walmart.com", k="walmart")
b("DHL", "courier", "dhl.com dhl.de dhl.co.uk dhl.com.hk dhl.co.in", k="dhl")
b("FedEx", "courier", "fedex.com fedex.co.in", a="fedex|fed ex", k="fedex")
b("UPS", "courier", "ups.com", a="ups|united parcel service", k="upsdelivery|upsparcel")
b("USPS", "courier", "usps.com usps.gov", a="usps|us postal service|united states postal service", k="usps")
b("Royal Mail", "courier", "royalmail.com", a="royal mail", k="royalmail")
b("Wise", "payment", "wise.com transferwise.com", a="wise|transferwise", k="transferwise")
b("Intuit", "tech", "intuit.com quickbooks.com turbotax.com", a="intuit|quickbooks|turbotax", k="intuit|quickbooks")
b("Yahoo", "tech", "yahoo.com ymail.com yahoodns.net", a="yahoo", k="yahoo")
b("Cloudflare", "tech", "cloudflare.com", k="cloudflare")
b("GitHub", "tech", "github.com githubusercontent.com", k="github")
b("Booking.com", "travel", "booking.com", a="booking.com|booking", k="booking")
b("Airbnb", "travel", "airbnb.com airbnb.co.in", k="airbnb")
b("Uber", "travel", "uber.com", k="uber")

# ---- India
R = "india"
b("State Bank of India", "bank", "sbi.co.in onlinesbi.sbi onlinesbi.com sbicard.com sbilife.co.in sbimf.com sbi.bank.in yonosbi.com sbiepay.sbi sbi.in", a="sbi|state bank of india|yono|yono sbi|sbi card|sbi bank", k="sbi|sbibank|onlinesbi|yonosbi|statebankofindia|sbiyono|sbikyc", region=R)
b("HDFC Bank", "bank", "hdfcbank.com hdfcbank.net hdfc.com hdfclife.com hdfcsec.com hdfcergo.com hdfcfund.com hdfcbankoffers.com hdfcsales.com", a="hdfc|hdfc bank|hdfc credit card|hdfc netbanking", k="hdfcbank|hdfc", region=R)
b("ICICI Bank", "bank", "icicibank.com icici.com icicidirect.com iciciprulife.com icicilombard.com icicipruamc.com icicibank.co.in", a="icici|icici bank|icici pru|icici lombard|icici direct", k="icicibank|icicidirect|icici", region=R)
b("Axis Bank", "bank", "axisbank.com axis.bank.in axismf.com axisdirect.in", a="axis|axis bank", k="axisbank", region=R)
b("Kotak Mahindra Bank", "bank", "kotak.com kotakbank.com kotaksecurities.com kotak811.com", a="kotak|kotak mahindra|kotak bank|kotak811", k="kotakbank|kotakmahindra|kotak811", region=R)
b("Punjab National Bank", "bank", "pnbindia.in netpnb.com pnbcard.in pnb.co.in", a="pnb|punjab national bank", k="pnb|pnbindia|netpnb|punjabnationalbank", region=R)
b("Bank of Baroda", "bank", "bankofbaroda.in bankofbaroda.com barodacreditcard.com bobfinancial.com bobcard.co.in", a="bank of baroda|bob|baroda|bobcard", k="bankofbaroda", region=R)
b("Canara Bank", "bank", "canarabank.com canarabank.in", a="canara|canara bank", k="canarabank", region=R)
b("Union Bank of India", "bank", "unionbankofindia.co.in unionbankofindia.bank.in", a="union bank|union bank of india", k="unionbankofindia", region=R)
b("IDFC FIRST Bank", "bank", "idfcfirstbank.com idfcbank.com", a="idfc|idfc first|idfc first bank", k="idfcfirst|idfcbank", region=R)
b("Yes Bank", "bank", "yesbank.in yesbank.com", a="yes bank", k="yesbank", region=R)
b("IndusInd Bank", "bank", "indusind.com", a="indusind|indusind bank", k="indusind", region=R)
b("Bank of India", "bank", "bankofindia.co.in", a="bank of india|boi", k="bankofindia", region=R)
b("Indian Bank", "bank", "indianbank.in indianbank.net.in", a="indian bank", k="indianbank", region=R)
b("Central Bank of India", "bank", "centralbankofindia.co.in", a="central bank of india", k="centralbankofindia", region=R)
b("RBI", "gov", "rbi.org.in", a="rbi|reserve bank of india", k="rbiindia", region=R)
b("NPCI / BHIM UPI", "payment", "npci.org.in bhimupi.org.in upichalega.com", a="npci|bhim|bhim upi|upi", k="npci|bhimupi", region=R)
b("Paytm", "payment", "paytm.com paytmbank.com paytmmoney.com paytmpayments.com", a="paytm|paytm payments bank|paytm bank", k="paytm", region=R)
b("PhonePe", "payment", "phonepe.com", a="phonepe|phone pe", k="phonepe", region=R)
b("Google Pay India", "payment", "pay.google.com gpay.app.goo.gl", a="google pay|gpay|g pay", k="googlepay|gpay", region=R)
b("CRED", "payment", "cred.club", a="cred", k="credclub", region=R)
b("Flipkart", "retail", "flipkart.com flipkartmail.com fkrt.it", a="flipkart", k="flipkart", region=R)
b("Myntra", "retail", "myntra.com", k="myntra", region=R)
b("Swiggy", "retail", "swiggy.com swiggy.in", k="swiggy", region=R)
b("Zomato", "retail", "zomato.com", k="zomato", region=R)
b("Meesho", "retail", "meesho.com", k="meesho", region=R)
b("Reliance Jio", "telecom", "jio.com ril.com jiomart.com jiopay.com", a="jio|reliance jio|jiofiber|jiomart", k="jiofiber|reliancejio|jiorecharge|jiomart", region=R)
b("Airtel", "telecom", "airtel.in airtel.com airtelbank.com wynk.in", a="airtel|bharti airtel|airtel payments bank", k="airtel", region=R)
b("Vi (Vodafone Idea)", "telecom", "myvi.in vodafone.in vodafoneidea.com", a="vi|vodafone|vodafone idea|myvi", k="vodafone|myvi", region=R)
b("BSNL", "telecom", "bsnl.co.in", a="bsnl", k="bsnl", region=R)
b("TRAI / DoT", "gov", "trai.gov.in dot.gov.in", a="trai|dot|department of telecommunications|telecom regulatory", k="traigov|dotgov", region=R)
b("India Post", "courier", "indiapost.gov.in indiapost.in", a="india post|indiapost|speed post|postal department|department of posts", k="indiapost|speedpost", region=R)
b("Delhivery", "courier", "delhivery.com", k="delhivery", region=R)
b("Blue Dart", "courier", "bluedart.com", a="blue dart|bluedart", k="bluedart", region=R)
b("DTDC", "courier", "dtdc.in dtdc.com", a="dtdc", k="dtdc", region=R)
b("Ecom Express", "courier", "ecomexpress.in", a="ecom express", k="ecomexpress", region=R)
b("Xpressbees", "courier", "xpressbees.com", k="xpressbees", region=R)
b("Income Tax Department", "gov", "incometax.gov.in incometaxindiaefiling.gov.in tin-nsdl.com", a="income tax|income tax department|incometax|cbdt|itr", k="incometax|incometaxindia|incometaxrefund", region=R)
b("UIDAI / Aadhaar", "gov", "uidai.gov.in myaadhaar.uidai.gov.in", a="uidai|aadhaar|aadhar", k="uidai|aadhaar|aadhar", region=R)
b("EPFO", "gov", "epfindia.gov.in epfindia.com", a="epfo|epf|provident fund|pf office", k="epfindia|epfo", region=R)
b("IRCTC", "travel", "irctc.co.in irctc.com", a="irctc|indian railways", k="irctc", region=R)
b("NHAI / FASTag", "gov", "nhai.gov.in ihmcl.com netc.org.in fastag.ihmcl.com", a="fastag|nhai|ihmcl|netc fastag", k="fastag|nhai|ihmcl", region=R)
b("Parivahan / Transport", "gov", "parivahan.gov.in echallan.parivahan.gov.in morth.nic.in", a="parivahan|e-challan|echallan|mparivahan|rto|transport department|traffic police|vahan", k="parivahan|echallan|mparivahan", region=R)
b("Digilocker", "gov", "digilocker.gov.in", a="digilocker", k="digilocker", region=R)
b("NSDL / PAN", "gov", "nsdl.com tin-nsdl.com utiitsl.com", a="nsdl|pan card|utiitsl", k="nsdl|utiitsl", region=R)
b("MSEDCL (Mahavitaran)", "utility", "mahadiscom.in mahavitaran.com", a="msedcl|mahavitaran|mahadiscom|mseb", k="mahadiscom|msedcl", region=R)
b("BESCOM", "utility", "bescom.karnataka.gov.in bescom.co.in", a="bescom", k="bescom", region=R)
b("BSES", "utility", "bsesdelhi.com bsesdelhi.net", a="bses", k="bsesdelhi", region=R)
b("Tata Power", "utility", "tatapower.com tatapowerddl.com tatapower-ddl.com", a="tata power|tatapower", k="tatapower", region=R)
b("Adani Electricity", "utility", "adanielectricity.com adani.com", a="adani electricity|adani", k="adanielectricity", region=R)
b("Electricity Board", "utility", "", a="electricity board|electricity department|power corporation|discom|vidyut vitran|electricity bill", k=[], region=R)
b("CIBIL", "finance", "cibil.com transunion.com tucibil.com", a="cibil|transunion cibil", k="cibil", region=R)
b("LIC of India", "finance", "licindia.in licindia.com", a="lic|lic of india|life insurance corporation", k="lic|licindia", region=R)
b("Zerodha", "finance", "zerodha.com zerodha.net kite.trade", a="zerodha|kite", k="zerodha", region=R)
b("Groww", "finance", "groww.in", a="groww", k="groww", region=R)
b("Upstox", "finance", "upstox.com", a="upstox", k="upstox", region=R)
b("Naukri", "jobs", "naukri.com infoedge.in", a="naukri|naukri.com", k="naukri", region=R)
b("Indeed", "jobs", "indeed.com indeed.co.in", a="indeed", k="indeed")
b("Aarogya Setu / CoWIN", "gov", "cowin.gov.in aarogyasetu.gov.in", a="aarogya setu|cowin", k="cowin|aarogyasetu", region=R)

LISTS = {
    "suspicious_tlds": "zip mov top xyz click cfd sbs icu cyou buzz rest work support tk ml ga cf gq monster surf quest bond lol fit date loan men party review stream trade webcam win download racing accountant science cricket faith gdn kim country bid vip pw cc ws su uno beauty hair makeup skin yachts autos boats homes mom pics lat rocks fun space site online website store shop live today life link ink wang xin ooo fyi help cam".split(),
    "shorteners": "s.free.fr bit.ly tinyurl.com t.co goo.gl ow.ly is.gd buff.ly adf.ly bit.do cutt.ly rb.gy shorturl.at tiny.cc t.ly rebrand.ly s.id v.gd lnkd.in soo.gd clck.ru qr.ae urlz.fr 1url.com shorte.st bc.vc mcaf.ee x.co po.st tr.im snip.ly short.io ouo.io gg.gg l.ead.me bl.ink han.gl u.to chilp.it kutt.it spoo.me 0rz.tw 2.gp tny.im lc.cx cli.re clk.im wa.link".split(),
    "free_hosting": "weebly.com wixsite.com blogspot.com wordpress.com appspot.com bplaced.net byethost7.com epizy.com infinityfreeapp.com rf.gd x10.mx x10host.com atwebpages.com ukit.me jimdosite.com jotform.com formspree.io wufoo.com 000webhostapp.com herokuapp.com firebaseapp.com web.app pages.dev workers.dev github.io netlify.app vercel.app glitch.me repl.co ngrok.io ngrok-free.app duckdns.org no-ip.org no-ip.com ddns.net hopto.org zapto.org serveo.net trycloudflare.com myshopify.com sites.google.com forms.gle storage.googleapis.com s3.amazonaws.com blob.core.windows.net web.core.windows.net azurewebsites.net r2.dev notion.site carrd.co strikingly.com yolasite.com webflow.io godaddysites.com mailchimpsites.com square.site typedream.app onrender.com fly.dev surge.sh".split(),
    "freemail": "gmail.com googlemail.com yahoo.com yahoo.in yahoo.co.in ymail.com outlook.com hotmail.com live.com msn.com aol.com icloud.com me.com protonmail.com proton.me gmx.com gmx.net mail.com zoho.com rediffmail.com yandex.com yandex.ru mail.ru qq.com 163.com 126.com tutanota.com tuta.io fastmail.com hushmail.com inbox.com".split(),
    "esp_domains": "amazonses.com sendgrid.net sendgrid.com mailchimp.com mcsv.net mcdlv.net rsgsv.net mandrillapp.com mailgun.org mailgun.com sparkpostmail.com sparkpost.com postmarkapp.com pstmrk.it constantcontact.com cmail19.com cmail20.com createsend.com exacttarget.com salesforce.com force.com marketo.net mktomail.com hubspotemail.net hs-send.com sendinblue.com brevo.com klaviyomail.com klaviyo.com sailthru.com intercom-mail.com customeriomail.com mailjet.com mjt.lu emarsys.net cheetahmail.com responsys.net rsys2.com rsys3.com sfmc-content.com eloqua.com googlegroups.com".split(),
}

if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "brands.json").write_text(json.dumps(B, indent=0, separators=(",", ":")), encoding="utf-8")
    (OUT / "lists.json").write_text(json.dumps(LISTS, indent=0), encoding="utf-8")
    print(len(B), "brands;", {k: len(v) for k, v in LISTS.items()})
