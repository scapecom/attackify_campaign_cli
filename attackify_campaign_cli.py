###
#
# Name: ATTACKIFY - Mitre ATT&CK Threat Actor Group Emulation for ATTACKIFY Campaigns
#
# Author: Gareth Phillips (@attackify)
# License: MIT License - Copyright (c) 2024 SCAPECOM/ATTACKIFY
#
###
import requests
import json
import argparse
from stix2 import MemoryStore, Filter
from datetime import datetime, timezone
import traceback
from difflib import get_close_matches
import os
import signal
import sys

BASE_URL = "http://dev.attackify.com/api"
MITRE_ATTCK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

def clear_screen():
    if os.name == 'nt':
        _ = os.system('cls')
    else:
        _ = os.system('clear')

def paginate_output(description, output_lines, lines_per_page=30):
    for i in range(0, len(output_lines), lines_per_page):
        clear_screen()
        print(description)
        print("\n".join(output_lines[i:i+lines_per_page]))
        user_input = input("\nPress Enter to continue (or 'q' to quit to main menu)...")
        if user_input.lower() == 'q':
            break

def handle_api_response(response):
    if response.status_code == 200:
        return response.json()
    elif response.status_code == 401:
        try:
            error_data = response.json()
            if "message" in error_data and "Token has expired" in error_data["message"]:
                print("\n[!] Your session has expired. Please log in again with a new token.")
                return None
        except json.JSONDecodeError:
            pass
    
    print(f"\n[!] API request failed. Status code: {response.status_code}")
    print(f"Response content: {response.text[:1000]}...")  # Print first 1000 characters
    return None

def get_current_user(token):
    headers = {
        "accept": "application/json",
        "authorization": f"Bearer {token}",
    }
    response = requests.get(f"{BASE_URL}/current-user", headers=headers)
    return response.json()

def get_environments(token, org_id):
    headers = {
        "accept": "application/json",
        "authorization": f"Bearer {token}",
    }
    response = requests.get(f"{BASE_URL}/customers/{org_id}/environments", headers=headers)
    return response.json()

def get_simulations(token):
    headers = {
        "accept": "application/json",
        "authorization": f"Bearer {token}",
    }
    response = requests.get(f"{BASE_URL}/simulations", headers=headers)
    return response

def print_module_requests_and_techniques(simulation):
    output_lines = []
    if 'module_requests' in simulation:
        for request in simulation['module_requests']:
            output_lines.append(f"  Module Request: {request.get('name', 'Unnamed')}")
            output_lines.append(f"    Request ID: {request.get('request_id', 'N/A')}")
            output_lines.append(f"    Request Data: {request.get('request_data', 'N/A')}")
            if 'mitre' in request:
                output_lines.append("    MITRE Techniques:")
                for technique in request['mitre']:
                    if 'technique' in technique and 'name' in technique:
                        output_lines.append(f"      - {technique['technique']}: {technique['name']}")
            output_lines.append("")
    return output_lines

def load_attack_data():
    response = requests.get(MITRE_ATTCK_URL)
    return MemoryStore(stix_data=response.json())

def find_similar_groups(src, input_name, max_suggestions=5):
    all_groups = src.query([Filter('type', '=', 'intrusion-set')])
    group_names = [group.name for group in all_groups]
    return get_close_matches(input_name, group_names, n=max_suggestions, cutoff=0.6)

def get_mitre_techniques_for_group(src, group_name):
    group = src.query([
        Filter('type', '=', 'intrusion-set'),
        Filter('name', '=', group_name)
    ])

    if not group:
        print(f"\n [!] Group '{group_name}' not found!")
        similar_groups = find_similar_groups(src, group_name)
        if similar_groups:
            print("\nDid you mean one of these groups?\n")
            for i, name in enumerate(similar_groups, 1):
                print(f" - {i}. {name}")
            choice = input("\nEnter the number of the correct group (or press Enter to cancel): ")
            if choice.isdigit() and 1 <= int(choice) <= len(similar_groups):
                group_name = similar_groups[int(choice) - 1]
                group = src.query([
                    Filter('type', '=', 'intrusion-set'),
                    Filter('name', '=', group_name)
                ])
            else:
                return []
        else:
            print("\t [!] No similar GROUP names found!\n")
            return []

    group = group[0]

    relationships = src.relationships(group, 'uses', source_only=True)
    technique_ids = [r.target_ref for r in relationships if r.target_ref.startswith('attack-pattern--')]

    techniques = []
    for tech_id in technique_ids:
        technique = src.get(tech_id)
        if technique:
            external_references = technique.get('external_references', [])
            tech_id = next((ref['external_id'] for ref in external_references if ref.get('source_name') == 'mitre-attack'), None)
            if tech_id:
                techniques.append((tech_id, technique.name))

    return techniques

def format_technique_output(techniques):
    return [f" - {technique_id}: {technique_name}" for technique_id, technique_name in techniques]

def get_attackify_modules_for_techniques(token, techniques):
    headers = {
        "accept": "application/json",
        "authorization": f"Bearer {token}",
    }
    response = requests.get(f"{BASE_URL}/simulations", headers=headers)
    simulations = response.json()

    matching_modules = []
    for sim in simulations:
        if 'module_requests' in sim:
            for request in sim['module_requests']:
                if 'mitre' in request:
                    for mitre_technique in request['mitre']:
                        if any(technique[0] == mitre_technique['technique'] for technique in techniques):
                            matching_modules.append({
                                'module_name': sim['name'],
                                'module_id': sim['id'],
                                'request_name': request['name'],
                                'technique_id': mitre_technique['technique'],
                                'technique_name': mitre_technique['name']
                            })
    
    return matching_modules

def print_matching_modules(group, modules):
    if not modules:
        print("[!] No matching ATTACKIFY Modules found!")
        return

    output_lines = [""]
    for module in modules:
        output_lines.append(f"- Module: {module['module_name']}")
        output_lines.append(f"  Request: {module['request_name']}")
        output_lines.append(f"  Technique: {module['technique_id']} - {module['technique_name']}")
        output_lines.append("")
    
    paginate_output(f"\nMatched ATTACKIFY Modules for {group}:", output_lines)

def parse_date(date_obj):
    if not date_obj or date_obj == 'Unknown':
        return datetime.min.replace(tzinfo=timezone.utc)
    try:
        if isinstance(date_obj, str):
            return datetime.fromisoformat(date_obj.rstrip('Z')).replace(tzinfo=timezone.utc)
        if hasattr(date_obj, 'year'):  # Check if it's a date-like object
            return date_obj.replace(tzinfo=timezone.utc)
        return datetime.min.replace(tzinfo=timezone.utc)
    except (ValueError, AttributeError):
        return datetime.min.replace(tzinfo=timezone.utc)

def get_recent_threat_groups(src, limit=10):
    groups = src.query([
        Filter('type', '=', 'intrusion-set'),
    ])
    
    sorted_groups = sorted(groups, key=lambda x: parse_date(x.get('created')), reverse=True)
    recent_groups = sorted_groups[:limit]
    
    return [(group.name, group.get('created', 'Unknown')) for group in recent_groups]

def print_recent_groups(groups):
    output_lines = [f"\nMost Recent {len(groups)} Threat Actor Groups:\n "]
    for name, created in groups:
        created_date = parse_date(created)
        if created_date != datetime.min.replace(tzinfo=timezone.utc):
            created_str = created_date.strftime("%Y-%m-%d")
        else:
            created_str = 'Unknown'
        output_lines.append(f" - {name} (Created: {created_str})")
    
    paginate_output("\nRecent Mitre Threat Actor Groups:", output_lines)

def create_new_campaign(token, src):
    user_data = get_current_user(token)
    org_id = user_data.get("organisation_id")
    
    if not org_id:
        print("\n [*] Failed to fetch organization ID. Cannot create campaign.")
        return

    all_environments = get_environments(token, org_id)

    headers = {
        "accept": "application/json",
        "authorization": f"Bearer {token}",
    }
    response = requests.get(f"{BASE_URL}/customers/{org_id}/environments/campaigns", headers=headers)
    if response.status_code != 200:
        print(f"\n [!] Failed to fetch available environments. Status code: {response.status_code}")
        return
    
    available_environments = response.json()

    available_env_ids = [env['environment_id'] for env in available_environments]
    environments = [env for env in all_environments if env['id'] in available_env_ids]

    if not environments:
        print("\n[!] No available environments found for campaign creation.")
        print("Please ensure you have at least one environment set up before creating a campaign.")
        return

    print("\nAvailable Environments:")
    for i, env in enumerate(environments, 1):
        print(f"   {i}. {env['name']} (ID: {env['id']})")
        print(f"\t - Description: {env['description']}")
        print()

    env_choice = int(input("Select an environment (enter the number): ")) - 1
    selected_env = environments[env_choice]

    campaign_name = input("Enter campaign name: ")
    campaign_description = input("Enter campaign description: ")

    group_name = input("Enter the name of the MITRE ATT&CK group to base the campaign on: ")
    
    techniques = get_mitre_techniques_for_group(src, group_name)
    
    if not techniques:
        print(f"\n [!] No techniques found for {group_name}. Cannot create campaign!")
        return

    matching_modules = get_attackify_modules_for_techniques(token, techniques)
    
    if not matching_modules:
        print("\n [!] No matching ATTACKIFY modules found. Cannot create campaign!")
        return

    unique_module_ids = set()
    unique_modules = []

    for module in matching_modules:
        if module['module_id'] not in unique_module_ids:
            unique_module_ids.add(module['module_id'])
            unique_modules.append(module)

    print(f"\n [i] Found {len(unique_modules)} unique matching ATTACKIFY modules for {group_name}")

    campaign_data = {
        "environment": selected_env['id'],
        "name": campaign_name,
        "description": f"[{group_name}] " + campaign_description,
        "simulate": [{"simulation": module['module_id'], "duration": 1} for module in unique_modules]
    }

    headers = {
        "accept": "application/json",
        "authorization": f"Bearer {token}",
        "content-type": "application/json"
    }
    response = requests.post(f"{BASE_URL}/simulate/campaigns/{selected_env['id']}/new", headers=headers, json=campaign_data)
    
    # Simulated response for testing
    #response = type('obj', (object,), {'status_code': 200})

    if response.status_code == 200:
        print("\n   [i] Campaign Created Successfully in ATTACKIFY!")
        # print(json.dumps(response.json(), indent=2))
    else:
        print(f"Failed to create campaign. Status code: {response.status_code}")
        print(response.text)

def print_menu(attackify_header):
    clear_screen()
    print(attackify_header + "\n\n")
    print("Menu Options:\n")
    print("Mitre ATT&CK:\n")
    print(" 1. List Recent Mitre ATT&CK Threat Actor Groups")
    print(" 2. Search for MITRE ATT&CK techniques used by a Threat Actor GROUP")
    
    print("\nATTACKIFY:\n")
    print(" 3. View available environments")
    print(" 4. View available ATTACKIFY Simulation Modules")
    print(" 5. List ATTACKIFY Modules/TTPs by Mitre ATT&CK Threat Actor Group")
    print(" 6. Create NEW Campaign based on Mitre ATT&CK Group")
    print("\n 7. Exit")

def signal_handler(sig, frame):
    print('\n\nCtrl+C detected...Exiting!')
    sys.exit(0)

def main():
    ATTACKIFY_HEADER = "\nATTACKIFY Threat Actor Campaign CLI -  v 0.1b\n"

    parser = argparse.ArgumentParser(description="ATTACKIFY CLI")
    parser.add_argument("--token", required=True, help="Your ATTACKIFY API token")
    args = parser.parse_args()

    signal.signal(signal.SIGINT, signal_handler)

    print("Loading MITRE ATT&CK data...")
    src = load_attack_data()
    print("MITRE ATT&CK data loaded successfully.")

    while True:
        try:
            print_menu(ATTACKIFY_HEADER)
            choice = input("\nEnter your choice (1-7): ")

            clear_screen()

            if choice == '2':
                print(ATTACKIFY_HEADER + "\n\n")
                group = input("Enter the name of the MITRE ATT&CK Threat Actor Group to SEARCH for: ")
                print(f"\nSearching for TECHNIQUES used by {group}...")
                try:
                    techniques = get_mitre_techniques_for_group(src, group)
                    if techniques:
                        print(f"Techniques used by {group}:")
                        formatted_techniques = format_technique_output(techniques)
                        paginate_output(f"\nMitre ATT&CK Threat Actor Group {group} Techniques:\n", formatted_techniques)
                    elif techniques is not None:
                        print(f"No techniques found for {group}.")
                except Exception as e:
                    print(f"[*] An error occurred while fetching techniques: {str(e)}")
                    traceback.print_exc()

            elif choice == '3':
                print(ATTACKIFY_HEADER + "\n\n")
                try:
                    user_data = get_current_user(args.token)
                    org_id = user_data.get("organisation_id")
                    environments = get_environments(args.token, org_id)
                    output_lines = ["\nAvailable Environments:"]
                    for env in environments:
                        output_lines.append(f" - {env['name']} (ID: {env['id']})")
                        output_lines.append(f"  Description: {env['description']}")
                        output_lines.append("")
                    paginate_output("\nATTACKIFY Environments:",output_lines)
                except Exception as e:
                    print(f"[*] An error occurred while fetching environments: {str(e)}")
                    traceback.print_exc()

            elif choice == '4':
                print(ATTACKIFY_HEADER + "\n\n")
                try:
                    response = get_simulations(args.token)
                    simulations = handle_api_response(response)
                    
                    if simulations is not None:
                        output_lines = ["\nAvailable Simulation Modules:"]
                        if isinstance(simulations, list):
                            for sim in simulations:
                                if isinstance(sim, dict):
                                    output_lines.append(f"- {sim.get('name', 'Unnamed')} (ID: {sim.get('id', 'N/A')})")
                                    output_lines.extend(print_module_requests_and_techniques(sim))
                                    output_lines.append("-" * 50)
                        paginate_output("\nATTACKIFY Modules:", output_lines)
                except Exception as e:
                    print(f"An error occurred while fetching simulations: {str(e)}")
                    traceback.print_exc()

            elif choice == '5':
                print(ATTACKIFY_HEADER + "\n\n")
                group = input("Enter the name of the MITRE ATT&CK Threat Actor Group to search for: ")
                print(f"\nSearching for techniques used by {group} and mapping to ATTACKIFY modules...\n")
                try:
                    techniques = get_mitre_techniques_for_group(src, group)
                    if techniques:
                        print(f"Techniques used by {group}:")
                        formatted_techniques = format_technique_output(techniques)
                        paginate_output(f"\nMitre ATT&CK Listed TTPs by {group}:\n", formatted_techniques)
                        
                        print("\nMapping to ATTACKIFY modules...")
                        matching_modules = get_attackify_modules_for_techniques(args.token, techniques)
                        print_matching_modules(group, matching_modules)
                    else:
                        print(f"No techniques found for {group}.")
                except Exception as e:
                    print(f"An error occurred while fetching techniques or mapping to modules: {str(e)}")
                    traceback.print_exc()

            elif choice == '1':
                print(ATTACKIFY_HEADER + "\n\n")
                print("\nFetching recent threat actor groups...")
                try:
                    recent_groups = get_recent_threat_groups(src)
                    print_recent_groups(recent_groups)
                except Exception as e:
                    print(f"An error occurred while fetching recent groups: {str(e)}")
                    traceback.print_exc()

            elif choice == '6':
                print(ATTACKIFY_HEADER + "\n\n")
                print("\nCreating new campaign...")
                try:
                    create_new_campaign(args.token, src)
                except Exception as e:
                    print(f"An error occurred while creating the campaign: {str(e)}")
                    traceback.print_exc()

            elif choice == '7':
                print(ATTACKIFY_HEADER + "\n\n")
                print("Exiting ATTACKIFY CLI. Goodbye!")
                break

            else:
                print("Invalid choice. Please enter a number between 1 and 7.")

            input("\nPress Enter to continue to main menu...")

        except KeyboardInterrupt:
            print('\n\nCtrl+C detected...Exiting tool!')
            break

if __name__ == "__main__":
    main()