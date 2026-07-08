import urllib.request
import re

with open('frontend/index.html', 'r') as f:
    html = f.read()

# Extract all src= and href=
urls = re.findall(r'href="(/frontend/[^"]+)"', html) + re.findall(r'src="(/frontend/[^"]+)"', html)

all_good = True
for url in urls:
    full_url = f"http://127.0.0.1:5000{url}"
    try:
        req = urllib.request.Request(full_url, method='HEAD')
        with urllib.request.urlopen(req) as response:
            if response.status == 200:
                print(f"OK: {url}")
            else:
                print(f"ERROR: {url} returned {response.status}")
                all_good = False
    except Exception as e:
        print(f"FAILED: {url} - {e}")
        all_good = False

if all_good:
    print("All assets resolved successfully with 0 404 errors.")
else:
    print("Some assets failed to load.")
