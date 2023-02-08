import requests

# Purpose: To detect whether a port is a backdoor or not
# Idea: Try to match if a port has a backdoor matched with certain patterns

BACK_DOOR_PATTERN = "/exec/ls -la"


def detect(address, port):
    backdoors = []

    if not address.startswith("http://"):
        address = "http://" + address

    full_address = address + ":" + port + BACK_DOOR_PATTERN
    # Make a request to the website
    response = requests.get(full_address)

    # Parse the HTML content of the page
    if response.status_code == 200:
        print("DETECTED a backdoor at: " + full_address)
        backdoors.append(full_address)

    if len(backdoors) > 0:
        f = open("backdoor.txt", "w")
        for backdoor in backdoors:
            f.write(backdoor + "\n")
        f.close()


# for testing purpose
if __name__ == "__main__":
    detect("192.168.0.15", "80")
