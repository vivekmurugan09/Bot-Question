import streamlit as st
import pandas as pd
from fuzzywuzzy import fuzz
from fuzzywuzzy import process
import re
import pandas as pd
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize

# Download NLTK data
nltk.download('stopwords')
nltk.download('punkt')

# All your existing functions remain the same
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

def sample():
    with open("sample.txt", "r") as x:
        e = x.read()
        return e

def virus_worm_trojan():
    with open("virus worm trojan.txt", "r") as x:
        e = x.read()
        return e

def webcam_for_confidential():
    with open("webcam for confidential.txt", "r") as x:
        e = x.read()
        st.write(e)
        return e


# Streamlit UI in checkbox format
st.title("Security Help Desk - Checkbox Selection")

st.write("Select a topic to get information:")

# Initialize session state
#if 'selected_topic' not in st.session_state:
#    st.session_state.selected_topic = None

# Checkboxes for each topic
st.title("Account & Access Management")
account_col1, account_col2 = st.columns(2)
with account_col1:
    access_azure_prod_uat = st.checkbox("Access Azure/AWS Prod/UAT")
    account_locked = st.checkbox("Account Locked")
    app_access = st.checkbox("Application Access Request")
    azure_api_keys = st.checkbox("Azure DevOps API Keys")
    change_password = st.checkbox("Change Password Frequently")
    cloud_permissions = st.checkbox("Cloud Permissions Review")
    mfa_error = st.checkbox("MFA Error")
    password_policy = st.checkbox("Password Policy")
    reset_password = st.checkbox("Reset Password")
    what_is_mfa = st.checkbox("What is MFA")

with account_col2:
    request_device = st.checkbox("Request Device")
    request_policy_exception = st.checkbox("Policy Exception Request")
    reviewing_access = st.checkbox("Review Access")
    set_up_reset_mfa = st.checkbox("Set Up/Reset MFA")
    someone_asked_for_password = st.checkbox("Someone Asked for Password")
    strong_password = st.checkbox("Strong Password")
    suspicious_password = st.checkbox("Entered Password on Suspicious Site")
    what_is_privileged_account = st.checkbox("What is Privileged Account")
    whitelist_ip = st.checkbox("Whitelist IP in Firewall")

st.subheader("Security Incidents & Threats")
security_col1, security_col2 = st.columns(2)
with security_col1:
    clicked_suspicious_link = st.checkbox("Clicked Suspicious Link")
    common_phishing_signs = st.checkbox("Common Phishing Signs")
    device_strange = st.checkbox("Device Behaving Strangely")
    false_positive = st.checkbox("False Positive vs Risk Accepted")
    malware_warning = st.checkbox("Virus/Malware Warning")
    mitm_attack = st.checkbox("MITM Attack")
    phishing_example = st.checkbox("Phishing Example")
    report_phishing = st.checkbox("Report Phishing")
    security_breach = st.checkbox("Security Breach")
    security_incident = st.checkbox("Security Incident")

with security_col2:
    security_ticket = st.checkbox("Create Security Ticket")
    suspicious_email = st.checkbox("Suspicious Email Received")
    threat_intel = st.checkbox("Threat Intelligence")
    threat_modeling = st.checkbox("Threat Modeling")
    threat_vs_risk = st.checkbox("Threat vs Vulnerability vs Risk")
    unauthorized_person = st.checkbox("Unauthorized Person in Office")
    virus_worm_trojan = st.checkbox("Virus vs Worm vs Trojan")
    what_is_soc = st.checkbox("What is SOC")
    zero_day = st.checkbox("Zero Day Vulnerability")

st.subheader("Device & Network Security")
device_col1, device_col2 = st.columns(2)
with device_col1:
    check_device_encryption = st.checkbox("Check Device Encryption")
    company_mdm_personal_phone = st.checkbox("Company MDM on Personal Phone")
    connect_corporate_vpn = st.checkbox("Connect to Corporate VPN")
    connect_guest_wifi = st.checkbox("Connect to Guest WiFi")
    device_compliance = st.checkbox("Device Compliance")
    lost_device = st.checkbox("Lost/Stolen Device")
    network_info = st.checkbox("Corporate vs Guest Network")
    personal_device_email = st.checkbox("Personal Device for Company Email")
    personal_smart_device_wifi = st.checkbox("Personal Smart Device on WiFi")
    security_software = st.checkbox("Security Software on Device")

with device_col2:
    transfer_data = st.checkbox("Transfer Data to New Laptop")
    trouble_connecting_vpn = st.checkbox("Trouble Connecting to VPN")
    update_os = st.checkbox("Update OS/Software")
    usb_drives = st.checkbox("Personal USB Drives")
    bluetooth_policy = st.checkbox("Bluetooth Policy")
    personal_router_office = st.checkbox("Personal Router in Office")
    public_wifi_policy = st.checkbox("Public WiFi Policy")
    remote_wipe_policy = st.checkbox("Remote Wipe Policy")
    securely_dispose_device = st.checkbox("Securely Dispose Old Device")

st.subheader("Data & Cloud Security")
data_col1, data_col2 = st.columns(2)
with data_col1:
    cloud_cspm_report = st.checkbox("Cloud CSPM Report")
    cloud_storage_policy = st.checkbox("Cloud Storage Policy")
    cloud_sync_secure = st.checkbox("Is Cloud Sync Secure")
    data_classification = st.checkbox("Data Classification")
    encryption_policy = st.checkbox("Encryption Policy")
    file_retention = st.checkbox("File Retention")
    handle_confidential_info = st.checkbox("Handle Confidential Info")
    least_privilege = st.checkbox("Principle of Least Privilege")
    public_link = st.checkbox("Public Link Sharing Policy")

with data_col2:
    secure_api = st.checkbox("Secure API Endpoints")
    secure_container = st.checkbox("Secure Container Images")
    what_is_cloud_resource_policy = st.checkbox("What is Cloud Resource Policy")
    webcam_confidential = st.checkbox("Webcam for Confidential")
    your_data_responsibilities = st.checkbox("Your Data Responsibilities")
    access_files_departed_colleague = st.checkbox("Access Departed Colleague Files")
    personal_file_sharing = st.checkbox("Personal File Sharing Services")
    verify_identity = st.checkbox("Verify Client Identity")

st.subheader("Policies & Compliance")
policy_col1, policy_col2 = st.columns(2)
with policy_col1:
    are_we_compliant = st.checkbox("Compliance Check")
    consequences_violation = st.checkbox("Consequences of Violation")
    escorting_visitors = st.checkbox("Escorting Visitors")
    file_sharing_services = st.checkbox("File Sharing Services")
    find_infosec_policy = st.checkbox("Find InfoSec Policy")
    leaving_role = st.checkbox("Leaving Company Role")
    non_human_identities = st.checkbox("Non-Human Identities")
    onboard_app = st.checkbox("Onboard New Application")
    recording_meetings_policy = st.checkbox("Recording Meetings Policy")

with policy_col2:
    role_of_risk_register = st.checkbox("Role of Risk Register")
    rules_third_party = st.checkbox("Third Party Vendor Rules")
    secure_access_home = st.checkbox("Secure Access from Home")
    security_training = st.checkbox("Security Training")
    visitors_policy = st.checkbox("Visitors Policy")
    who_is_dpo_ciso = st.checkbox("Who is DPO/CISO")
    why_software_blocked = st.checkbox("Why Software Blocked")
    apply_software_patch = st.checkbox("Apply Software Patch")
    enable_waf = st.checkbox("Enable WAF for My App")

# Display response based on selected checkbox
response_text = ""

# Account & Access Management
if access_azure_prod_uat:
    response_text = access_azure_aws_prod_uat()
elif account_locked:
    response_text = locked_out_of_account()
elif app_access:
    response_text = request_application_access()
elif azure_api_keys:
    response_text = request_azure_devops_api_keys()
elif change_password:
    response_text = why_change_password_frequently()
elif cloud_permissions:
    response_text = review_own_cloud_permissions()
elif mfa_error:
    response_text = mfa_error()
elif password_policy:
    response_text = corporate_password_policy()
elif reset_password:
    response_text = reset_password()
elif what_is_mfa:
    response_text = what_is_mfa()
elif request_device:
    response_text = raise_request_for_device()
elif request_policy_exception:
    response_text = request_policy_exception()
elif reviewing_access:
    response_text = manager_reviewing_access()
elif set_up_reset_mfa:
    response_text = set_up_reset_mfa()
elif someone_asked_for_password:
    response_text = someone_asked_for_password()
elif strong_password:
    response_text = strong_password()
elif suspicious_password:
    response_text = entered_password_on_suspicious_site()
elif what_is_privileged_account:
    response_text = what_is_privileged_account()
elif whitelist_ip:
    response_text = whitelist_ip_in_firewall()

# Security Incidents & Threats
elif clicked_suspicious_link:
    response_text = clicked_suspicious_link()
elif common_phishing_signs:
    response_text = common_phishing_signs()
elif device_strange:
    response_text = device_behaving_strangely()
elif false_positive:
    response_text = false_positive_vs_risk_accepted()
elif malware_warning:
    response_text = virus_malware_warning()
elif mitm_attack:
    response_text = mitm_attack()
elif phishing_example:
    response_text = example_of_phishing_attempt()
elif report_phishing:
    response_text = report_phishing()
elif security_breach:
    response_text = during_security_breach()
elif security_incident:
    response_text = security_incident()
elif security_ticket:
    response_text = create_security_ticket()
elif suspicious_email:
    response_text = suspicious_email_received()
elif threat_intel:
    response_text = threat_intelligence_vulnerabilities()
elif threat_modeling:
    response_text = threat_modeling()
elif threat_vs_risk:
    response_text = threat_vs_vulnerability_vs_risk()
elif unauthorized_person:
    response_text = unauthorized_person_in_office()
elif virus_worm_trojan:
    response_text = what_is_virus_worm_trojan()
elif what_is_soc:
    response_text = what_is_soc()
elif zero_day:
    response_text = zero_day_vulnerability()

# Device & Network Security
elif check_device_encryption:
    response_text = check_device_encryption()
elif company_mdm_personal_phone:
    response_text = company_mdm_on_personal_phone()
elif connect_corporate_vpn:
    response_text = connect_to_corporate_vpn()
elif connect_guest_wifi:
    response_text = connect_to_guest_wifi()
elif device_compliance:
    response_text = ensure_device_compliance()
elif lost_device:
    response_text = lost_stolen_laptop_phone()
elif network_info:
    response_text = corporate_vs_guest_network()
elif personal_device_email:
    response_text = personal_device_to_company_email()
elif personal_smart_device_wifi:
    response_text = personal_smart_device_on_wifi()
elif security_software:
    response_text = security_software_on_device()
elif transfer_data:
    response_text = transfer_data_to_new_laptop()
elif trouble_connecting_vpn:
    response_text = trouble_connecting_to_vpn()
elif update_os:
    response_text = update_os_software()
elif usb_drives:
    response_text = personal_usb_drives()
elif bluetooth_policy:
    response_text = policy_on_bluetooth()
elif personal_router_office:
    response_text = personal_router_in_office()
elif public_wifi_policy:
    response_text = policy_on_public_wifi()
elif remote_wipe_policy:
    response_text = policy_for_remote_wipe()
elif securely_dispose_device:
    response_text = securely_dispose_old_device()

# Data & Cloud Security
elif cloud_cspm_report:
    response_text = access_cloud_vulnerabilities_report()
elif cloud_storage_policy:
    response_text = policy_for_cloud_data_storage()
elif cloud_sync_secure:
    response_text = is_my_cloud_sync_secure()
elif data_classification:
    response_text = data_classification()
elif encryption_policy:
    response_text = encryption_policy()
elif file_retention:
    response_text = file_retention()
elif handle_confidential_info:
    response_text = handle_confidential_info()
elif least_privilege:
    response_text = principle_of_least_privilege()
elif public_link:
    response_text = public_link_sharing_policy()
elif secure_api:
    response_text = secure_api_endpoints()
elif secure_container:
    response_text = secure_container_images()
elif what_is_cloud_resource_policy:
    response_text = what_is_cloud_resource_policy()
elif webcam_confidential:
    response_text = webcam_for_confidential()
elif your_data_responsibilities:
    response_text = your_data_responsibilities()
elif access_files_departed_colleague:
    response_text = access_files_of_departed_colleague()
elif personal_file_sharing:
    response_text = personal_file_sharing_services()
elif verify_identity:
    response_text = verify_client_identity_sensitive_data()

# Policies & Compliance
elif are_we_compliant:
    response_text = are_we_compliant()
elif consequences_violation:
    response_text = consequences_of_violation()
elif escorting_visitors:
    response_text = escorting_visitors()
elif file_sharing_services:
    response_text = personal_file_sharing_services()
elif find_infosec_policy:
    response_text = find_infosec_policy()
elif leaving_role:
    response_text = leaving_company_role()
elif non_human_identities:
    response_text = manage_non_human_identities()
elif onboard_app:
    response_text = onboard_new_application()
elif recording_meetings_policy:
    response_text = policy_on_recording_meetings()
elif role_of_risk_register:
    response_text = role_of_risk_register()
elif rules_third_party:
    response_text = rules_for_third_party_vendors()
elif secure_access_home:
    response_text = secure_access_from_home()
elif security_training:
    response_text = get_security_training()
elif visitors_policy:
    response_text = visitors_policy()
elif who_is_dpo_ciso:
    response_text = who_is_our_dpo_ciso()
elif why_software_blocked:
    response_text = why_is_software_blocked()
elif apply_software_patch:
    response_text = apply_software_patch()
elif enable_waf:
    response_text = enable_waf_for_my_app()

# Display response
if response_text:
    st.subheader("📋 Response")
    st.text_area("Information", value=response_text, height=400, key="response_area")
else:
    st.info("Please select a topic from the checkboxes above to get information.")

# Footer
st.markdown("---")
st.markdown("Need immediate assistance? Contact the Security Team at security@company.com")