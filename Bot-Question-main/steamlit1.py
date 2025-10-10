import streamlit as st
import pandas as pd
from fuzzywuzzy import fuzz
from fuzzywuzzy import process
import re
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize

# Download NLTK data
nltk.download('stopwords', quiet=True)
nltk.download('punkt', quiet=True)

# All your existing functions remain exactly the same
def public_link_sharing_policy():
    with open('"Public" Link Sharing Policy.txt', "r") as x:
        e = x.read()
        return e

def access_azure_aws_prod_uat():
    with open("Access Azure AWS Prod UAT.txt", "r") as x:
        e = x.read()
        return e

def access_cloud_vulnerabilities_report():
    with open("Access Cloud Vulnerabilities Report (CSPM).txt", "r") as x:
        e = x.read()
        return e

def access_denied_in_azure():
    with open("Access Denied in Azure.txt", "r") as x:
        e = x.read()
        return e

def access_files_of_departed_colleague():
    with open("Access Files of Departed Colleague.txt", "r") as x:
        e = x.read()
        return e

def apply_software_patch():
    with open("Apply a Software Patch.txt", "r") as x:
        e = x.read()
        return e

def are_we_compliant():
    with open("Are we compliant.txt", "r") as x:
        e = x.read()
        return e

def check_device_encryption():
    with open("Check Device Encryption.txt", "r") as x:
        e = x.read()
        return e

def clicked_suspicious_link():
    with open("Clicked Suspicious Link.txt", "r") as x:
        e = x.read()
        return e

def common_phishing_signs():
    with open("Common Phishing Signs.txt", "r") as x:
        e = x.read()
        return e

def company_mdm_on_personal_phone():
    with open("Company MDM on Personal Phone.txt", "r") as x:
        e = x.read()
        return e

def connect_to_corporate_vpn():
    with open("Connect to Corporate VPN.txt", "r") as x:
        e = x.read()
        return e

def connect_to_guest_wifi():
    with open("Connect to Guest Wi-Fi.txt", "r") as x:
        e = x.read()
        return e

def consequences_of_violation():
    with open("Consequences of Violation.txt", "r") as x:
        e = x.read()
        return e

def corporate_password_policy():
    with open("Corporate Password Policy.txt", "r") as x:
        e = x.read()
        return e

def corporate_vs_guest_network():
    with open("Corporate vs. Guest Network.txt", "r") as x:
        e = x.read()
        return e

def create_security_ticket():
    with open("Create a Security Ticket.txt", "r") as x:
        e = x.read()
        return e

def data_classification():
    with open("Data Classification.txt", "r") as x:
        e = x.read()
        return e

def device_behaving_strangely():
    with open("Device Behaving Strangely.txt", "r") as x:
        e = x.read()
        return e

def during_security_breach():
    with open("During a Security Breach.txt", "r") as x:
        e = x.read()
        return e

def enable_waf_for_my_app():
    with open("Enable WAF for My App.txt", "r") as x:
        e = x.read()
        return e

def encryption_policy():
    with open("Encryption Policy.txt", "r") as x:
        e = x.read()
        return e

def ensure_device_compliance():
    with open("Ensure Device Compliance.txt", "r") as x:
        e = x.read()
        return e

def entered_password_on_suspicious_site():
    with open("Entered Password on Suspicious Site.txt", "r") as x:
        e = x.read()
        return e

def escorting_visitors():
    with open("Escorting Visitors.txt", "r") as x:
        e = x.read()
        return e

def example_of_phishing_attempt():
    with open("Example of Phishing Attempt.txt", "r") as x:
        e = x.read()
        return e

def false_positive_vs_risk_accepted():
    with open("False Positive vs. Risk-Accepted.txt", "r") as x:
        e = x.read()
        return e

def file_retention():
    with open("File Retention.txt", "r") as x:
        e = x.read()
        return e

def find_infosec_policy():
    with open("Find InfoSec Policy.txt", "r") as x:
        e = x.read()
        return e

def get_security_training():
    with open("Get Security Training.txt", "r") as x:
        e = x.read()
        return e

def handle_confidential_info():
    with open("Handle Confidential Info.txt", "r") as x:
        e = x.read()
        return e

def is_my_cloud_sync_secure():
    with open("Is My Cloud Sync Secure.txt", "r") as x:
        e = x.read()
        return e

def leaving_company_role():
    with open("Leaving Company Role.txt", "r") as x:
        e = x.read()
        return e

def locked_out_of_account():
    with open("Locked Out of Account.txt", "r") as x:
        e = x.read()
        return e

def lost_stolen_laptop_phone():
    with open("Lost Stolen Laptop Phone.txt", "r") as x:
        e = x.read()
        return e

def mfa_error():
    with open("MFA Error.txt", "r") as x:
        e = x.read()
        return e

def mitm_attack():
    with open("Man-in-the-Middle (MitM) Attack.txt", "r") as x:
        e = x.read()
        return e

def manage_non_human_identities():
    with open("Manage Non-Human Identities.txt", "r") as x:
        e = x.read()
        return e

def manager_reviewing_access():
    with open("Manager Reviewing Access.txt", "r") as x:
        e = x.read()
        return e

def onboard_new_application():
    with open("Onboard New Application.txt", "r") as x:
        e = x.read()
        return e

def password():
    with open("Password.txt", "r") as x:
        e = x.read()
        return e

def personal_device_to_company_email():
    with open("Personal Device to Company Email.txt", "r") as x:
        e = x.read()
        return e

def personal_file_sharing_services():
    with open("Personal File Sharing Services.txt", "r") as x:
        e = x.read()
        return e

def personal_router_in_office():
    with open("Personal Router in Office.txt", "r") as x:
        e = x.read()
        return e

def personal_smart_device_on_wifi():
    with open("Personal Smart Device on WiFi.txt", "r") as x:
        e = x.read()
        return e

def personal_usb_drives():
    with open("Personal USB Drives.txt", "r") as x:
        e = x.read()
        return e

def policy_for_cloud_data_storage():
    with open("Policy for Cloud Data Storage.txt", "r") as x:
        e = x.read()
        return e

def policy_for_remote_wipe():
    with open("Policy for Remote Wipe.txt", "r") as x:
        e = x.read()
        return e

def policy_on_bluetooth():
    with open("Policy on Bluetooth.txt", "r") as x:
        e = x.read()
        return e

def policy_on_public_wifi():
    with open("Policy on Public Wi-Fi.txt", "r") as x:
        e = x.read()
        return e

def policy_on_recording_meetings():
    with open("Policy on Recording Meetings.txt", "r") as x:
        e = x.read()
        return e

def principle_of_least_privilege():
    with open("Principle of Least Privilege.txt", "r") as x:
        e = x.read()
        return e

def raise_request_for_device():
    with open("Raise Request for Laptop or Mobile or Headphone.txt", "r") as x:
        e = x.read()
        return e

def report_lost_stolen_badge():
    with open("Report Lost Stolen Badge.txt", "r") as x:
        e = x.read()
        return e

def report_phishing():
    with open("Report Phishing.txt", "r") as x:
        e = x.read()
        return e

def request_application_access():
    with open("Request Application Access.txt", "r") as x:
        e = x.read()
        return e

def request_azure_devops_api_keys():
    with open("Request Azure DevOps API Keys.txt", "r") as x:
        e = x.read()
        return e

def request_new_ssl_certificate():
    with open("Request New SSL Certificate.txt", "r") as x:
        e = x.read()
        return e

def request_prod_repo_in_azure_devops():
    with open("Request Prod Repo in Azure DevOps.txt", "r") as x:
        e = x.read()
        return e

def request_policy_exception():
    with open("Request a Policy Exception.txt", "r") as x:
        e = x.read()
        return e

def request_to_suppress_alert():
    with open("Request to Suppress Alert.txt", "r") as x:
        e = x.read()
        return e

def reset_password():
    with open("Reset Password.txt", "r") as x:
        e = x.read()
        return e

def review_own_cloud_permissions():
    with open("Review Own Cloud Permissions.txt", "r") as x:
        e = x.read()
        return e

def role_of_risk_register():
    with open("Role of a Risk Register.txt", "r") as x:
        e = x.read()
        return e

def rules_for_third_party_vendors():
    with open("Rules for Third Party Vendors.txt", "r") as x:
        e = x.read()
        return e

def secure_api_endpoints():
    with open("Secure API Endpoints.txt", "r") as x:
        e = x.read()
        return e

def secure_access_from_home():
    with open("Secure Access from Home.txt", "r") as x:
        e = x.read()
        return e

def secure_container_images():
    with open("Secure Container Images.txt", "r") as x:
        e = x.read()
        return e

def securely_dispose_old_device():
    with open("Securely Dispose of Old Device.txt", "r") as x:
        e = x.read()
        return e

def security_incident():
    with open("Security Incident.txt", "r") as x:
        e = x.read()
        return e

def security_software_on_device():
    with open("Security Software on Device.txt", "r") as x:
        e = x.read()
        return e

def set_up_reset_mfa():
    with open("Set Up Reset MFA.txt", "r") as x:
        e = x.read()
        return e

def someone_asked_for_password():
    with open("Someone Asked for Password.txt", "r") as x:
        e = x.read()
        return e

def strong_password():
    with open("Strong Password.txt", "r") as x:
        e = x.read()
        return e

def suspicious_email_received():
    with open("Suspicious Email Received.txt", "r") as x:
        e = x.read()
        return e

def threat_intelligence_vulnerabilities():
    with open("Threat Intelligence & Vulnerabilities.txt", "r") as x:
        e = x.read()
        return e

def threat_modeling():
    with open("Threat Modeling.txt", "r") as x:
        e = x.read()
        return e

def threat_vs_vulnerability_vs_risk():
    with open("Threat vs. Vulnerability vs. Risk.txt", "r") as x:
        e = x.read()
        return e

def transfer_data_to_new_laptop():
    with open("Transfer Data to New Laptop.txt", "r") as x:
        e = x.read()
        return e

def trouble_connecting_to_vpn():
    with open("Trouble Connecting to VPN.txt", "r") as x:
        e = x.read()
        return e

def unauthorized_person_in_office():
    with open("Unauthorized Person in Office.txt", "r") as x:
        e = x.read()
        return e

def update_os_software():
    with open("Update OS Software.txt", "r") as x:
        e = x.read()
        return e

def update_recovery_info():
    with open("Update Recovery Info.txt", "r") as x:
        e = x.read()
        return e

def verify_client_identity_sensitive_data():
    with open("Verify Client Identity for Sensitive Data.txt", "r") as x:
        e = x.read()
        return e

def virus_malware_warning():
    with open("Virus Malware Warning.txt", "r") as x:
        e = x.read()
        return e

def visitors_policy():
    with open("Visitors Policy.txt", "r") as x:
        e = x.read()
        return e

def what_is_mfa():
    with open("What is MFA.txt", "r") as x:
        e = x.read()
        return e

def what_is_virus_worm_trojan():
    with open("What is Virus vs. Worm vs. Trojan.txt", "r") as x:
        e = x.read()
        return e

def what_is_cloud_resource_policy():
    with open("What is a \"Cloud Resource Policy\".txt", "r") as x:
        e = x.read()
        return e

def what_is_privileged_account():
    with open("What is a Privileged Account.txt", "r") as x:
        e = x.read()
        return e

def what_is_soc():
    with open("What is a SOC.txt", "r") as x:
        e = x.read()
        return e

def whitelist_ip_in_firewall():
    with open("Whitelist IP in Firewall.txt", "r") as x:
        e = x.read()
        return e

def who_is_our_dpo_ciso():
    with open("Who is our DPO CISO.txt", "r") as x:
        e = x.read()
        return e

def why_change_password_frequently():
    with open("Why Change Password Frequently.txt", "r") as x:
        e = x.read()
        return e

def why_is_software_blocked():
    with open("Why is Software Blocked.txt", "r") as x:
        e = x.read()
        return e

def your_data_responsibilities():
    with open("Your Data Responsibilities.txt", "r") as x:
        e = x.read()
        return e

def zero_day_vulnerability():
    with open("Zero Day Vulnerability.txt", "r") as x:
        e = x.read()
        return e

# Streamlit app
st.title("Security Help Desk")
st.write("Select a security topic to get information:")

# Create options for radio buttons
options = [
    'Public Link Sharing Policy',
    'Access Azure AWS Prod UAT', 
    'Cloud CSPM Report',
    'Reset Password',
    'Report Phishing',
    'Strong Password',
    'What is MFA',
    'Device Encryption Check',
    'VPN Connection Issues',
    'Security Incident Report'
]

selected_option = st.radio('Choose a topic:', options)

# Display information based on selection
if selected_option == 'Public Link Sharing Policy':
    result = public_link_sharing_policy()
    st.write(result)
    
elif selected_option == 'Access Azure AWS Prod UAT':
    result = access_azure_aws_prod_uat()
    st.write(result)
    
elif selected_option == 'Cloud CSPM Report':
    result = access_cloud_vulnerabilities_report()
    st.write(result)
    
elif selected_option == 'Reset Password':
    result = reset_password()
    st.write(result)
    
elif selected_option == 'Report Phishing':
    result = report_phishing()
    st.write(result)
    
elif selected_option == 'Strong Password':
    result = strong_password()
    st.write(result)
    
elif selected_option == 'What is MFA':
    result = what_is_mfa()
    st.write(result)
    
elif selected_option == 'Device Encryption Check':
    result = check_device_encryption()
    st.write(result)
    
elif selected_option == 'VPN Connection Issues':
    result = trouble_connecting_to_vpn()
    st.write(result)
    
elif selected_option == 'Security Incident Report':
    result = security_incident()
    st.write(result)

# Additional simple checkbox example
st.write("---")
st.write("Quick Actions:")

if st.checkbox("Show emergency contacts"):
    st.write("Security Team: securityvivek.com")
    st.write("Emergency Line: +918807867149")

if st.checkbox("Need immediate help?"):
    st.write("Please contact the security team immediately!")