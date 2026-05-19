import requests

def get_ip_info(target):
    try:
        response = requests.get(
            f"http://ip-api.com/json/{target}",
            timeout=5
        )

        data = response.json()

        return {
            "country": data.get("country"),
            "city": data.get("city"),
            "isp": data.get("isp"),
            "lat": data.get("lat"),
            "lon": data.get("lon")
        }

    except:
        return None