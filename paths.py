import pathlib

ROOT_PATH = pathlib.Path(__file__).parent.absolute()

LIST_TXT_PATH = ROOT_PATH.joinpath('list.txt')
SUB_TXT_PATH = ROOT_PATH.joinpath('sub.txt')
LINK_TXT_PATH = ROOT_PATH.joinpath('link.txt')
XSS_PAYLOADS_PATH = ROOT_PATH.joinpath('xss_payloads.txt')
HTML_PAYLOADS_PATH = ROOT_PATH.joinpath('html_payloads.txt')
SITE_FROM_DORK_PATH = ROOT_PATH.joinpath('Site_From_Dork.txt')
PASSWORD_TXT_PATH = ROOT_PATH.joinpath('password.txt')
USERNAME_TXT_PATH = ROOT_PATH.joinpath('username.txt')