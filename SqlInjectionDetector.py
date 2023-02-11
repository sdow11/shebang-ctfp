import requests
from urllib import parse
from bs4 import BeautifulSoup


# What can be detected? <a href="/somelink?id=1">, <form action="/someformlink" method="post">
# What cannot be detected? <a href="/" click=someJavascriptMethod()>.
# However, this can still be logged for investigation

def detect(address, port):
    sub_addresses = []

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
        sub_address = full_address + ":" + port + tag['href']
        sub_addresses.append('[GET][HREF] ' + sub_address)
        # check wether the link has request param
        url_splits = parse.urlsplit()
        params = dict(url_splits.query)
        # TODO: try to inject data into param such as id=1' or 1==1&
        # TBD

    # Find all forms with action attribute
    forms = soup.find_all('form')
    for form in forms:
        sub_address = full_address + ":" + port + form['action']
        sub_addresses.append('[' + form['method'] + '][FORM] ' + sub_address)
        # TODO: ty to get all name under form and inject sql
        # TBD

    if len(sub_addresses) > 0:
        f = open("sql_injection.txt", "w")
        for sub_address in sub_addresses:
            f.write(sub_address + "\n")
        f.close()


if __name__ == "__main__":
    detect("192.168.0.15", "80")
