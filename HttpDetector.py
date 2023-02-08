import requests


# Purpose: to detect whether a port is a web server or not
# Idea: if a port accepts http protocol, that means a port is a web server.
# Then, we can launch further attack dedicated for web server such as SQL Injection,

def detecthttpserver(address, port):
    if not address.startswith("http://"):
        address = "http://" + address

    full_address = address + ":" + port
    # Make a request to the website
    try:
        response = requests.get(full_address)
        response.raise_for_status()
        print(f"{full_address} is a web server.")
        f = open("web_servers.txt", "w")
        f.write(full_address + "\n")
        f.close()
    except requests.exceptions.RequestException as e:
        pass


# for testing purpose
if __name__ == "__main__":
    detecthttpserver("192.168.0.15", "80")
