"""
    BlackDir-Framework Project
    author:RedVirus Twitter:Je_1r insta:redvirus_0 
    author:Ali Twitter:bc_zQ

    Thx for all use this project


"""
import argparse
import json
import pathlib

from constants import result_dict
from paths import LIST_TXT_PATH, SUB_TXT_PATH
from scan_functions import dorks, spider, sub, xss, sql, list_dorks, update, ip_reverse, scanports, html_injection, \
    hash_identifier, hash_en, wordpress


def main():
    parser = argparse.ArgumentParser()
    """
        --spider            : Url to find Directory
        --list              : If you have list
        --dork              : Dump all sites by dork
        --country           : find Dork By Country
        --text              : Dump site text if in site
        --subdomain         : find SubDomain of site
        --xss               : Scan Site if vulnerable [Xss] url must be between double citation
        --sql               : Scan Site if vulnerable [Sql] url must be between double citation
        --HTMLinj           : Scan site if vulnerable [html injection] url must be between double citation
        --listDork          : Scan list Dorks if Vulnerable [Sql]
        --RevIP             : Dump all site by ip
        --port              : Scan ports by ip
        --update            : Update Tool ex: --update check
        --word              : word you want encrypt
        --type              : select hash type like:md5,sha1,sha256,sha512
        --hash_type         : find Type of hash
        --wordpress         : link the site for BruteForce
        --ListPassword      : Directory For Your Password List
        --ListUsername      : Directory For Your Username List
        --enum              : Wordpress User Enumerate 

        ex:
        python3 BlackDir.py --spider http://google.com
        python3 BlackDir.py --dork inurl:admin/login.php --country sa --text product
        python3 BlackDir.py --xss "paste url here"
        python3 BlackDir.py --sql "paste url here"
        python3 BlackDir.py --subdomain google.com
        python3 BlackDir.py --RevIP [ip address of server]
        python3 BlackDir.py --word redvirus --type md4
        python3 BlackDir.py --word redvirus --type md5
        python3 BlackDir.py --word redvirus --type sha1
        python3 BlackDir.py --word redvirus --type sha256
        python3 BlackDir.py --word redvirus --type sha512
        python3 BlackDir.py --hash_type 5f4dcc3b5aa765d61d8327deb882cf99
        python3 BlackDir.py --wordpress http://ebase.com/
        python3 BlackDir.py --wordpress http://ebase.com/ --ListUsername /root/Desktop/users.txt --ListPassowrd /root/Desktop/pass.txt
        python3 BlackDir.py --wordpress http://ebase.com/ --ListUsername /root/Desktop/users.txt 
        python3 BlackDir.py --wordpress http://ebase.com/ --ListPassword /root/Desktop/pass.txt
        python3 BlackDir.py --wordpress https://everythingrevelstoke.com --enum use
    """

    parser.add_argument("-spider", "--spider", help="Url")
    parser.add_argument('-output', '--output-file', required=True, help='Path to output file',
                        type=pathlib.Path)
    parser.add_argument("-list", "--list")
    parser.add_argument("-dork", "--dork")
    parser.add_argument("-country", "--country")
    parser.add_argument("-subdomain", "--subdomain")
    parser.add_argument("-xss", "--xss")
    parser.add_argument("-text", "--text")
    parser.add_argument("-sql", "--sql")
    parser.add_argument("-HTMLinj", "--HTMLinj")
    parser.add_argument("-listDork", "--listDork")
    parser.add_argument("-update", "--update")
    parser.add_argument("-RevIP", "--RevIP")
    parser.add_argument("-port", "--port")
    parser.add_argument("-type", "--type")
    parser.add_argument("-word", "--word")
    parser.add_argument("-hash_type", "--hash_type")
    parser.add_argument("-wordpress", "--wordpress")
    parser.add_argument("-ListUsername", "--ListUsername")
    parser.add_argument("-ListPassword", "--ListPassword")
    parser.add_argument("-enum", "--enum")

    args = parser.parse_args()
    secure = None
    listuser = args.list

    if listuser is not None:
        listuser = args.list
        secure = None

    elif listuser is None:
        listuser = open(LIST_TXT_PATH, "r")
        secure = "list.txt"

    output_file = args.output_file
    ip = args.RevIP
    portscan = args.port
    dork = args.dork
    country = args.country
    url = args.spider

    # in script "/" will be added
    if url and '/' in url[-1]:
        url = url[:-1]
    subdomains = args.subdomain
    scanner = args.xss
    text = args.text
    sql_inection = args.sql
    list_dork = args.listDork
    updates = args.update
    html = args.HTMLinj
    sublist = open(SUB_TXT_PATH, "r")
    site = args.country
    hash_type = args.type
    user_word = args.word
    hash_ide = args.hash_type
    url_wordpress = args.wordpress
    usernames = args.ListUsername
    passwords = args.ListPassword
    enumx = args.enum

    if (dork and not url and not subdomains and not scanner and not sql_inection and not list_dork
            and not updates and not ip and not portscan and not html and not hash_type and not user_word
            and not hash_ide and not url_wordpress):
        dorks(dork, site, text)
    elif (url and not dork and not subdomains and not scanner and not sql_inection and not list_dork
          and not updates and not ip and not portscan and not html and not hash_type and not user_word
          and not hash_ide and not url_wordpress):
        spider(url, listuser, secure)
    elif (subdomains and not url and not dork and not scanner and not sql_inection and not list_dork
          and not updates and not ip and not portscan and not html and not hash_type and not user_word
          and not hash_ide and not url_wordpress):
        sub(subdomains, sublist)
    elif (scanner and not url and not dork and not subdomains and not sql_inection and not list_dork
          and not updates and not ip and not portscan and not html and not hash_type and not user_word
          and not hash_ide and not url_wordpress):
        xss(scanner)
    elif (sql_inection and not scanner and not url and not dork and not subdomains and not list_dork
          and not updates and not ip and not portscan and not html and not hash_type and not user_word
          and not hash_ide and not url_wordpress):
        sql(sql_inection)
    elif (not sql_inection and not scanner and not url and not dork and not subdomains and list_dork
          and not updates and not ip and not portscan and not html and not hash_type and not user_word
          and not hash_ide and not url_wordpress):
        list_dorks(list_dork)
    elif (not sql_inection and not scanner and not url and not dork and not subdomains and not list_dork
          and updates and not ip and not portscan and not html and not hash_type and not user_word
          and not hash_ide and not url_wordpress):
        if updates == "check" or updates == "Check":
            update()
        else:
            print("Error ! Please Enter --update check")

    elif (not sql_inection and not scanner and not url and not dork and not subdomains and not list_dork
          and not updates and ip and not portscan and not html and not hash_type and not user_word
          and not hash_ide and not url_wordpress):
        print("ip_reverse")
        ip_reverse(ip)
    elif (not sql_inection and not scanner and not url and not dork and not subdomains and not list_dork
          and not updates and not ip and portscan and not html and not hash_type and not user_word
          and not hash_ide and not url_wordpress):
        print("scanports")
        scanports(portscan)
    elif (not sql_inection and not scanner and not url and not dork and not subdomains and not list_dork
          and not updates and not ip and not portscan and html and not hash_type and not user_word
          and not hash_ide and not url_wordpress):
        html_injection(html)
    elif (not sql_inection and not scanner and not url and not dork and not subdomains and not list_dork
          and not updates and not ip and not portscan and not html and hash_type and user_word
          and not hash_ide and not url_wordpress):
        hash_en(user_word, hash_type)
    elif (not sql_inection and not scanner and not url and not dork and not subdomains and not list_dork
          and not updates and not ip and not portscan and not html and not hash_type and not user_word
          and hash_ide and not url_wordpress):
        hash_identifier(hash_ide)
    elif (not sql_inection and not scanner and not url and not dork and not subdomains and not list_dork
          and not updates and not ip and not portscan and not html and not hash_type and not user_word
          and not hash_ide and url_wordpress):
        wordpress(url_wordpress, usernames, passwords, enumx)

    for key, value in result_dict.items():
        if not value:
            result_dict["message"] = "Nothing found"
            break

    json_data = json.dumps(result_dict)
    output_file.write_text(json_data)
    print(f"Final results save to {output_file.absolute().as_uri()}")


if __name__ == "__main__":
    main()
