
import os
from dotenv import load_dotenv
import requests
from utils import extract_location

load_dotenv()
APIFY_ACTOR_TASK_ID = os.environ.get("APIFY_ACTOR_TASK_ID")
APIFY_API_TOKEN = os.environ.get("APIFY_API_TOKEN")

APIFY_RUN_URL = f"https://api.apify.com/v2/acts/{APIFY_ACTOR_TASK_ID}/runs"  # POST to start actor run
APIFY_DATASET_URL_TEMPLATE = "https://api.apify.com/v2/datasets/{dataset_id}/items"


def get_restaurants_from_apify(query, max_places=10):
    location = extract_location(query)
    if not location:
        location = "Nairobi"  # Default fallback
    payload = {
        "checkNames": False,
        "deeperCityScrape": False,
        "location": location,
        "maxPlaces": max_places,
        "maxReviewsPerPlaceAndProvider": 10,
        "providers": [
            "google-maps",
            "tripadvisor",
            "yelp",
            "facebook",
            "uber-eats"
        ],
        "requireExactNameMatch": False,
        "scrapeReviewPictures": False,
        "scrapeReviewResponses": False
    }
    headers = {"Authorization": f"Bearer {APIFY_API_TOKEN}"}
    print(f"[DEBUG] Sending request to Apify actor: {APIFY_RUN_URL}")
    print(f"[DEBUG] Payload: {payload}")
    run_resp = requests.post(APIFY_RUN_URL, json=payload, headers=headers)
    print(f"[DEBUG] Actor run response status: {run_resp.status_code}")
    if run_resp.status_code != 201:
        print(f"[ERROR] Failed to start actor run: {run_resp.text}")
        return []
    run_data = run_resp.json().get("data", {})
    dataset_id = run_data.get("defaultDatasetId")
    run_id = run_data.get("id")
    print(f"[DEBUG] Received dataset_id: {dataset_id}")
    print(f"[DEBUG] Received run_id: {run_id}")
    if not dataset_id or not run_id:
        print(f"[ERROR] No dataset_id or run_id returned from actor run.")
        return []
    # Poll for results (simple version)
    import time
    items = []
    for poll_count in range(20):
        print(f"[DEBUG] Polling for results: attempt {poll_count+1}")
        data_resp = requests.get(APIFY_DATASET_URL_TEMPLATE.format(dataset_id=dataset_id), headers=headers)
        print(f"[DEBUG] Dataset response status: {data_resp.status_code}")
        if data_resp.status_code == 200:
            items = data_resp.json()
            print(f"[DEBUG] Items received: {len(items)}")
            if items:
                break
        time.sleep(5)
    # Abort actor run after results are received
    if run_id:
        abort_url = f"https://api.apify.com/v2/actor-runs/{run_id}/abort?token={APIFY_API_TOKEN}"
        try:
            abort_resp = requests.post(abort_url)
            print(f"[DEBUG] Abort actor run response status: {abort_resp.status_code}")
        except Exception as e:
            print(f"[ERROR] Failed to abort actor run: {e}")
    if items:
        return items
    print(f"[ERROR] No results received after polling.")
    return []
