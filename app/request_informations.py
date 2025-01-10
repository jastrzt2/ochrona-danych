import requests
import re

def is_valid_string(value, max_length=100):
    if not isinstance(value, str):
        return False
    if len(value) > max_length:
        return False
    if not re.match(r'^[a-zA-Z0-9 ]*$', value):
        return False
    return True

def get_ip_info(ip_address, timeout=0.5):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=timeout)
        response.raise_for_status()

        data = response.json()
        country_name = data.get("country_name", "Unknown")
        country_code2 = data.get("country_code2", "Unknown")
        isp = data.get("isp", "Unknown")
        city = data.get("city", "Unknown")

        if is_valid_string(country_name, 100) and is_valid_string(country_code2, 2) and is_valid_string(isp, 100) and is_valid_string(city, 100):
            return {
                "country_name": country_name,
                "country_code2": country_code2,
                "isp": isp,
                "city": city,
            }

    except (requests.exceptions.RequestException, ValueError) as e:
        print(f"Error fetching IP information: {e}")

    return {
        "country_name": "Unknown",
        "country_code2": "Unknown",
        "isp": "Unknown",
        "city": "Unknown",
    }
