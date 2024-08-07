"""
IMPORTANT: This script is intended to be run as a one-time operation to create certifications for all role owners in the SailPoint platform. It will create new certifications each time it is run. 
           This script also assumes you will have an enterprise firewall with TSL inspection enabled, and so it disables SSL verification.
"""

import requests
import os
import json
from dotenv import load_dotenv
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
load_dotenv()

# Set API credentials and base URL using environment variables 
client_id = os.getenv('CLIENT_ID')
client_secret = os.getenv('CLIENT_SECRET')
base_url = os.getenv('BASE_URL')

# Ensure all required environment variables are set
if not all([client_id, client_secret, base_url]):
    print("Missing one or more required environment variables.")
    exit(1)

#Define the deadline for the certifications
deadline = "2024-12-25T06:00:00.468Z"

# Ensure all required environment variables are set
if not all([client_id, client_secret, base_url]):
    print("Missing one or more required environment variables.")
    exit(1)

# Construct specific URLs from base URL
auth_url = f"{base_url}/oauth/token"
roles_url = f"{base_url}/v3/roles"
templates_url = f"{base_url}/v3/campaign-templates"
campaigns_url = f"{base_url}/v3/campaigns"

# Obtain access token
auth_response = requests.post(auth_url, verify=False, data={
    'grant_type': 'client_credentials',
    'client_id': client_id,
    'client_secret': client_secret
})

# Check the response status code
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

# Function to get roles and their owners
def get_role_owners():
    response = requests.get(roles_url, headers=headers, verify=False)  
    if response.status_code == 200:
        roles_data = response.json()
        role_owners_list = []
        unique_owners = {}
        for role in roles_data:
            if 'owner' in role and 'id' in role['owner'] and 'name' in role['owner']:
                role_owner_id = role['owner']['id']
                if role_owner_id not in unique_owners:
                    unique_owners[role_owner_id] = {
                        'role_owner_name': role['owner']['name'],
                        'role_owner_id': role_owner_id
                    }
        role_owners_list = list(unique_owners.values())
        return role_owners_list
    else:
        print(f"Failed to list roles. Status code: {response.status_code}")
        return None

# Function to create a role composition campaign for a specific role owner
def create_role_campaign_for_role_owner(role_owner_name, role_owner_id, deadline):
    campaign_data = {
        "name": f"{role_owner_name}s Role Composition Certifications",
        "description": f"Certification campaign for all roles owned by {role_owner_name}",
        "type": "ROLE_COMPOSITION",
        "emailNotificationEnabled": False,
        "autoRevokeAllowed": False,
        "recommendationsEnabled": True,
        "deadline": f"{deadline}",
        "roleCompositionCampaignInfo": {
            "remediatorRef": {
                "type": "IDENTITY",
                "id": "[MUST BE A SAILPOINT ADMIN]",
                "name": "[NAME OF SAILPOINT ADMIN]"
            },
            "reviewerId": f"{role_owner_id}",
            "reviewer": {
                "type": "IDENTITY",
                "id": f"{role_owner_id}",
                "name": f"{role_owner_name}",
            },
            "query": f"owner.name:{role_owner_name}",
        },
        "mandatoryCommentRequirement": "NO_DECISIONS"
    }

    response = requests.post(campaigns_url, headers=headers, data=json.dumps(campaign_data), verify=False)
    if response.status_code == 200 or response.status_code == 201:
        print(f"{role_owner_name}s role campaign created successfully.")
        return response.json()
    else:
        print(f"Failed to create {role_owner_name}s role campaign. Status code: {response.status_code}")
        print(response.text)
        return None

# Function to create an access item campaign for a specific role owner
def create_access_campaign_for_role_owner(role_owner_name, role_owner_id, deadline):
    campaign_data = {
        "name": f"{role_owner_name}s Access Item Certifications",
        "description": f"Certification campaign for access items in all roles owned by {role_owner_name}",
        "type": "SEARCH",
        "emailNotificationEnabled": False,
        "autoRevokeAllowed": False,
        "recommendationsEnabled": True,
        "deadline": f"{deadline}",
        "searchCampaignInfo": {
            "type": "ACCESS",
            "query": f"owner.name:{role_owner_name}",
            "reviewer": {
                "type": "IDENTITY",
                "id": f"{role_owner_id}",
                "name": f"{role_owner_name}"            
            }
        },
        "accessConstraints": {
            "type": "ROLE",
            "operator": "ALL"
        },
        "mandatoryCommentRequirement": "NO_DECISIONS"
    }        
    response = requests.post(campaigns_url, headers=headers, data=json.dumps(campaign_data), verify=False)
    if response.status_code == 200 or response.status_code == 201:
        print(f"{role_owner_name}s access campaign created successfully.")
        return response.json()
    else:
        print(f"Failed to create {role_owner_name}s access campaign. Status code: {response.status_code}")
        return None

access_token = get_access_token()

headers = {
  'Content-Type': 'application/json',
  'Accept': 'application/json',
  'Authorization': f"Bearer {access_token}",
}

def main():
    role_owners = get_role_owners()
    if role_owners is None:
        print("No role owners found or an error occurred.")
        return

    for owner in role_owners:
        role_owner_name = owner['role_owner_name']
        role_owner_id = owner['role_owner_id']
        create_access_campaign_for_role_owner(role_owner_name, role_owner_id, deadline)
        create_role_campaign_for_role_owner(role_owner_name, role_owner_id, deadline)

if __name__ == "__main__":
    main()