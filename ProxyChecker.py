import ssl
import socket
import requests
import threading
from bs4 import BeautifulSoup

     #############################################
    ###   Super Proxy Checker Code By GogoZin   ###
   ### This script can check a proxy list of 50k ###
  ####       in less than one minute,            ####
   ### make it the most efficient proxy checker  ###
    ###           on the Internet               ###
     #############################################

conns = 0
delay = 5 # timeout for proxy check
pro = [] # proxy list by scraper
target_port = 443 # you can change it for your target port which used
thread_pool = [] # active threading list
alive_proxy = [] # Alive HTTP Proxy List
alive_proxy_ssl = [] # Alive HTTP Proxy TLS/SSL Supported
threading.Semaphore(100) # thread limit, do not change it if your system is windows !

URL = ['https://www.free-proxy-list.net/', # proxy page for Scraper_2
        'https://www.sslproxies.org/', 
        'https://www.us-proxy.org/']



def checkingBySocket(proxy): # Check HTTP Proxy's Connection Using Socket, Credit&Logic By GogoZin
    global conns
    try:
        proxy_ip, proxy_port = proxy.split(":") # Try split proxy_ip&port
        proxy_port = int(proxy_port) # change proxy_port to int
    except ValueError: 
        return # if some lines got Error Just return
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # create socket
        s.settimeout(5) # socket timeout
        s.connect((proxy_ip, proxy_port)) # try to connect http proxy
        if target_port == 443: # if your target use TLS/SSL proto, need this
            connect_request = f"CONNECT www.google.com:443 HTTP/1.1\r\n" # If proto is TLS/SSL,
            connect_request += f"Host: www.google.com:443\r\n"           # Http Proxy need to create tunnel to target,
            connect_request += f"Proxy-Connection: Keep-Alive\r\n\r\n"   # all requests will go through http proxy tunnel to target
            try:
                s.send(connect_request.encode()) # Send tunnel create request
                res = s.recv(4096).decode() # Recv data
                if "200" in res: # Tunnel create successfully if there is a "200" in response code
                    context = ssl.create_default_context() # create default context "better than SSLContext()"
                    context.check_hostname = False # when use proxy for request, Do not check hostname
                    context.verify_mode = ssl.CERT_NONE # and do not verify, you'll get more alive proxy
                    s = context.wrap_socket(s, server_hostname="www.google.com") # Wrap socket after context created
                    s.send("GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: Close\r\n\r\n".encode()) # and send HTTP Request
                    alive_proxy.append(proxy) 
                    alive_proxy_ssl.append(proxy)
                    s.close() # After Sent, no matter what in response, just close socket and put this proxy in alive list
                    conns += 1
                    print(f"Connected \033[35m{proxy_ip:<15s}\033[0m Conns [\033[34m{conns}\033[0m]")
                    print(f'\33]0;[{conns}] Proxies Connected | ProxyChecker Code By GogoZin\a',end='')
                    return
                else:
                    pass # If there is no "200" in response, just pass it
            except:
                pass # If Proxy didn't accept CONNECT Request also pass it
        try: # Also can try to send a normal request if TLS/SSL not supported
            s.send("GET http://www.google.com/ HTTP/1.1\r\nHost: www.google.com\r\nConnection: Close\r\n\r\n".encode())
            s.close()
            alive_proxy.append(proxy)
            conns += 1
            print(f"Connected \033[35m{proxy_ip:<15s}\033[0m Conns [\033[34m{conns}\033[0m]")
            print(f'\33]0;[{conns}] Proxies Connected | ProxyChecker Code By GogoZin\a',end='')
            return
        except:
            s.close()
            return
    except:
        return


def checkProxies(): 
    # The logic for this function was provided by Leeon123, 
    # who is a well-known developer of the CC attack, and I made some modifications.
    # Using threading's senaphore to limit the maximum number of thread,
    # and remove the original setting (time.sleep) to improve detection efficiency.
    for lines in pro:
        lines = lines.strip()
        t = threading.Thread(target=checkingBySocket, args=(lines, ))
        t.start()
        thread_pool.append(t)
    for th in thread_pool:
        th.join()


def proxyScrape(): # Scraper_1
    r = requests.get("https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all")
    lst = r.text.split("\r\n")
    for lines in lst:
        if len(lines) < 10:
            pass
        else:
            pro.append(lines)
    print(f"Fetch Proxy From https://api.proxyscrape.com/")


def fetch_proxies(url): # Scraper_2 Code By GogoZin
    try:
        # send request to proxy website
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')

        # find proxy table
        table = soup.find('table', {'class': 'table'})
        if not table:
            print('Table Not Found !')
            return pro
        
        # find all proxy and add to list
        for row in table.find_all('tr')[1:]:
            cols = row.find_all('td')
            if len(cols) >= 2:
                ip = cols[0].text.strip()
                port = cols[1].text.strip()
                proxy = f"{ip}:{port}"
                pro.append(proxy)

    except Exception as e:
        print(f"Error : {e}")
    print(f"Fetch Proxy From {url}")


def fetch_github(): # Scraper_3
    git_proxy_list = [
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
            "https://raw.githubusercontent.com/mmpx12/proxy-list/refs/heads/master/http.txt",
            "https://raw.githubusercontent.com/mmpx12/proxy-list/refs/heads/master/https.txt",
            "https://raw.githubusercontent.com/zevtyardt/proxy-list/refs/heads/main/http.txt",
            "https://raw.githubusercontent.com/ALIILAPRO/Proxy/refs/heads/main/http.txt",
            "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/http.txt",
            "https://raw.githubusercontent.com/sunny9577/proxy-scraper/refs/heads/master/generated/http_proxies.txt",
            "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/refs/heads/master/http.txt",
            "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/refs/heads/master/https.txt",
            "https://raw.githubusercontent.com/roosterkid/openproxylist/refs/heads/main/HTTPS_RAW.txt",
            "https://raw.githubusercontent.com/elliottophellia/proxylist/refs/heads/master/results/http/global/http_checked.txt",
    ]

    for u in git_proxy_list:
        r = requests.get(u)
        lst = r.text.split("\n")
        for lines in lst:
            if len(lines) < 10:
                pass
            else:
                pro.append(lines)
        u_path = u.split(".com/")[1]
        print(f"Fetch From Github:{u_path}")


def save_proxies(): # for saving alive proxies to .txt
    with open("online_http.txt", 'w') as f:
        for p in alive_proxy:
            f.write(p + '\n')
    print(f"Alive Proxies Save As online_http.txt")

    with open("online_https.txt", 'w') as fs:
        for ps in alive_proxy_ssl:
            fs.write(ps + '\n')
    print(f"TLS/SSL Proxies Save As online_https.txt")


if __name__ == "__main__":
    proxyScrape() # Scraper_1
    fetch_github() # Scraper_3
    for u in URL:
        fetch_proxies(u) # Scraper_2
    pro = sorted(set(pro))
    checkProxies()
    print(f"Fetch Proxies : {len(pro)}") # total downloaded proxy 
    print(f"Alive Proxies : {len(alive_proxy)}") # total alive proxy
    print(f"TLS/SSL Proxies : {len(alive_proxy_ssl)}") # total alive proxy that support TLS/SSL proto
    save_proxies() # save proxies to .txt list

    # Python Fast Http Proxy Checker, Code By GogoZin 
