from flask import Flask , jsonify , request
import requests 
import os
import uuid
from playwright.sync_api import sync_playwright

app = Flask(__name__)

API_KEY = "0dabff120b09c5bf795801159af98b0032aa7d44ea04664f1ea311dd64ee08dc"
HEADERS = {"x-apikey": API_KEY}
SCAN_URL= "https://www.virustotal.com/api/v3/urls"


SCREENSHOT_DIR = os.path.join("static", "screenshots")
os.makedirs(SCREENSHOT_DIR, exist_ok=True)

@app.route("/Free" , methods=["GET" , "POST"])
def api_f():
    url_f = None
    
    if request.method == "GET":
        url_f = request.args.get("url")
    if request.method == "POST": 
        data_f = request.get_json()
        if data_f:
            url_f = data_f.get("url")
    
    if not url_f:
        return jsonify({"ERROR" : "Not Found Url...."}),400
    
    scan_response = requests.post(SCAN_URL , headers=HEADERS , data={"url" : url_f})
    if scan_response.status_code != 200:
        return jsonify({"ERROR" : "The Link was not sent"})
      
    scan_data = scan_response.json()
    scan_id = scan_data["data"]["id"]
    
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
    analysis_response = requests.get(analysis_url , headers=HEADERS)
    
    analysis_result = analysis_response.json()
    stats = analysis_result["data"]["attributes"]["stats"] 
    
    malicious = stats ["malicious"]
    harmless = stats  ["harmless"]
    suspicious = stats ["suspicious"]
    
    free = "Free"
    
    if malicious > 0 : 
        status = "The  Link is Malicious"            
    elif suspicious > 0 : 
        status = "The Link is Suspicious"
    else :
        status = "The Link is Safe"
    
    return jsonify({
        "This is the plan." :free ,
        "Status " : status , 
        "Url" : url_f , 
        "Number of times detected as Safe " : harmless,
        "Number of times detected  as malicious" : malicious,
        "Number of times detected as suspicious" : suspicious
    })


@app.route("/" , methods=["GET" , "POST"])
def api_p():
    url = None 
    if request.method == "GET":
        url = request.args.get("url")
    elif request.method == "POST":
        data_p = request.get_json()
        if data_p:
            url = data_p.get("url")

    if not url :
        return jsonify({"ERROR" : "No found url"}),400
    
    SCAN_respnse = requests.post(SCAN_URL , headers=HEADERS , data={"url" : url})
    if SCAN_respnse.status_code  != 200 :
        return jsonify({"ERROR"  : "The Link was not send"})
    
    SCAN_data= SCAN_respnse.json()
    scan_id = SCAN_data ["data"]["id"]
    
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
    analysis_response = requests.get(analysis_url , headers=HEADERS)
    analysis_result = analysis_response.json()
    stats = analysis_result["data"]["attributes"]["stats"] 
    
    attrs = analysis_result["data"]["attributes"]
    results =attrs["results"]
    
    engines = []
    for eng, data  in results.items():
        engines.append({
              "engine_name": data.get("engine_name", eng),
            "category": data.get("category", "unknown"),
            "result": data.get("result", None),
            "method": data.get("method", None)
        })

    malicious_engines  = [e for e in engines if e.get("result" , "").lower() == "malicious"]
    phishing_engines   = [e for e in engines if e.get("result" , "").lower() == "phishing"]
    suspicious_engines = [e for e in engines if e.get("result" , "").lower() == "suspicious"]
    clean_enginens     = [e for e in engines if e.get("result" , "").lower() == "clean"]
    
    
    malicious =  stats["malicious"]
    harmless =   stats["harmless"]
    suspicious = stats["suspicious"]
    timeout =   stats["timeout"] 
    
    premium = "Premium"
    if malicious > 0 :
        status = "The Link is malicious"
    elif suspicious > 0 :
        status  = "The Link is Suspicious"
    elif timeout > 0 :
        status = "The Link is timeout"   
    else:
        status = "The Link is harmless"

    file_name = f"{uuid.uuid4().hex}.png"
    filepath = os.path.join(SCREENSHOT_DIR, file_name)
    screenshot_url = f"/static/screenshots/{file_name}"
    
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True) 
            page = browser.new_page()
            page.goto(url, timeout=60000)
            page.screenshot(path=filepath, full_page=True)
            browser.close()

    except Exception as e:
        screenshot_url = f"Screenshot failed: {str(e)}"

    return jsonify({
     "The condition" : status ,
     "Url" : url ,
     "Number of times detected as harmless: " : harmless, 
     "Number of times detected as malicious: " : malicious,
     "Number of times detected as Suspicious: " : suspicious, 
     "Number of times detected as timeout: " : timeout ,
     "Screenshot": screenshot_url,
     "malicious_engines" : malicious_engines,
     "suspicious_engines" : suspicious_engines,
     "clean_engines" : clean_enginens,
     "phishing_engines" : phishing_engines
     
     }),200

if __name__ == "__main__":
    app.run(debug=True , port=5000)