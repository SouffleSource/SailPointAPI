import requests
import os
import json
import pandas as pd
from pandas import json_normalize
from dotenv import load_dotenv
import urllib3

# Suppress only the single InsecureRequestWarning from urllib3 
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Load environment variables from .env file
load_dotenv()

# Set API credentials and base URL using environment variables
client_id = os.getenv('CLIENT_ID')
client_secret = os.getenv('CLIENT_SECRET')
base_url = os.getenv('BASE_URL')

# Ensure all required environment variables are set
if not all([client_id, client_secret, base_url]):
    print("Missing one or more required environment variables.")
    exit(1)

# Construct specific URLs from base URL
auth_url = f"{base_url}/oauth/token"
roles_url = f"{base_url}/v3/roles"

# Obtain access token
auth_response = requests.post(auth_url, verify=False, data={
    'grant_type': 'client_credentials',
    'client_id': client_id,
    'client_secret': client_secret
})


if auth_response.status_code == 200:
    try:
        auth_response_json = auth_response.json()
    except ValueError: 
        print("Failed to decode JSON from response.")
        print("Response content:", auth_response.text)
else:
    print(f"Failed to obtain access token. Status code: {auth_response.status_code}")
    print("Response content:", auth_response.text)

def get_access_token():
    """Authenticate and obtain access token."""
    data = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret,
    }
    response = requests.post(auth_url, data=data, verify=False)  
    if response.status_code == 200:
        return response.json().get('access_token')
    else:
        print(f"Failed to obtain access token. Status code: {response.status_code}")
        return None

def list_all_roles():
    access_token = get_access_token()
    if access_token:
        roles_url = f"{base_url}/v3/roles"
        headers = {
            'Authorization': f"Bearer {access_token}",
            'Content-Type': 'application/json',
        }
        response = requests.get(roles_url, headers=headers, verify=False)  
        if response.status_code == 200:
            return response  
        else:
            print(f"Failed to list roles. Status code: {response.status_code}")
            return None  

def parse_to_xlsx(data, file_name):
    if isinstance(data, dict):
        data = [data]
    
    try:
        flattened_data = json_normalize(data)
    except Exception as e:
        print(f"Error flattening data: {e}")
        flattened_data = pd.DataFrame(data)
    
    flattened_data.to_excel(f"{file_name}.xlsx", index=False)
    print(f"Data saved to {file_name}.xlsx")

if __name__ == "__main__":
    response = list_all_roles()
    if response is not None and response.status_code == 200:
        roles_data = response.json()  
        parse_to_xlsx(roles_data, "roles")
    elif response is None:
        print("Failed to fetch roles. The response was None.")
    else:
        print(f"Failed to fetch roles. Status code: {response.status_code}")