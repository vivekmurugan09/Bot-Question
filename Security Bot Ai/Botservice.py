import speech_recognition as sr
import pandas as pd#GA with fuzzy
from fuzzywuzzy import fuzz
from fuzzywuzzy import process
import re
import pandas as pd
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize

# Initialize the recognizer
recognizer = sr.Recognizer()

# Use the microphone as the audio source
with sr.Microphone() as source:
    print("Adjusting for background noise... Please wait.")
    recognizer.adjust_for_ambient_noise(source, duration=2)
    print("Listening... Speak something!")
    audio = recognizer.listen(source)

# Convert speech to text using Google Speech Recognition

print("Recognizing...")
text = recognizer.recognize_google(audio)
print("You said:", text)

def public_link_sharing_policy():
    with open('"Public" Link Sharing Policy.txt', "r") as x:
        e = x.read()
        print(e)
        return e

def access_azure_aws_prod_uat():
    with open("Access Azure AWS Prod UAT.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def access_cloud_vulnerabilities_report():
    with open("Access Cloud Vulnerabilities Report (CSPM).txt", "r") as x:
        e = x.read()
        print(e)
        return e

def access_denied_in_azure():
    with open("Access Denied in Azure.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def access_files_of_departed_colleague():
    with open("Access Files of Departed Colleague.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def apply_software_patch():
    with open("Apply a Software Patch.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def are_we_compliant():
    with open("Are we compliant.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def check_device_encryption():
    with open("Check Device Encryption.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def clicked_suspicious_link():
    with open("Clicked Suspicious Link.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def common_phishing_signs():
    with open("Common Phishing Signs.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def company_mdm_on_personal_phone():
    with open("Company MDM on Personal Phone.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def connect_to_corporate_vpn():
    with open("Connect to Corporate VPN.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def connect_to_guest_wifi():
    with open("Connect to Guest Wi-Fi.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def consequences_of_violation():
    with open("Consequences of Violation.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def corporate_password_policy():
    with open("Corporate Password Policy.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def corporate_vs_guest_network():
    with open("Corporate vs. Guest Network.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def create_security_ticket():
    with open("Create a Security Ticket.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def data_classification():
    with open("Data Classification.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def device_behaving_strangely():
    with open("Device Behaving Strangely.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def during_security_breach():
    with open("During a Security Breach.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def enable_waf_for_my_app():
    with open("Enable WAF for My App.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def encryption_policy():
    with open("Encryption Policy.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def ensure_device_compliance():
    with open("Ensure Device Compliance.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def entered_password_on_suspicious_site():
    with open("Entered Password on Suspicious Site.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def escorting_visitors():
    with open("Escorting Visitors.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def example_of_phishing_attempt():
    with open("Example of Phishing Attempt.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def false_positive_vs_risk_accepted():
    with open("False Positive vs. Risk-Accepted.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def file_retention():
    with open("File Retention.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def find_infosec_policy():
    with open("Find InfoSec Policy.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def get_security_training():
    with open("Get Security Training.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def handle_confidential_info():
    with open("Handle Confidential Info.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def is_my_cloud_sync_secure():
    with open("Is My Cloud Sync Secure.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def leaving_company_role():
    with open("Leaving Company Role.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def locked_out_of_account():
    with open("Locked Out of Account.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def lost_stolen_laptop_phone():
    with open("Lost Stolen Laptop Phone.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def mfa_error():
    with open("MFA Error.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def mitm_attack():
    with open("Man-in-the-Middle (MitM) Attack.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def manage_non_human_identities():
    with open("Manage Non-Human Identities.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def manager_reviewing_access():
    with open("Manager Reviewing Access.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def onboard_new_application():
    with open("Onboard New Application.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def password():
    with open("Password.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def personal_device_to_company_email():
    with open("Personal Device to Company Email.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def personal_file_sharing_services():
    with open("Personal File Sharing Services.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def personal_router_in_office():
    with open("Personal Router in Office.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def personal_smart_device_on_wifi():
    with open("Personal Smart Device on WiFi.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def personal_usb_drives():
    with open("Personal USB Drives.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def policy_for_cloud_data_storage():
    with open("Policy for Cloud Data Storage.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def policy_for_remote_wipe():
    with open("Policy for Remote Wipe.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def policy_on_bluetooth():
    with open("Policy on Bluetooth.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def policy_on_public_wifi():
    with open("Policy on Public Wi-Fi.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def policy_on_recording_meetings():
    with open("Policy on Recording Meetings.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def principle_of_least_privilege():
    with open("Principle of Least Privilege.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def raise_request_for_device():
    with open("Raise Request for Laptop or Mobile or Headphone.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def report_lost_stolen_badge():
    with open("Report Lost Stolen Badge.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def report_phishing():
    with open("Report Phishing.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def request_application_access():
    with open("Request Application Access.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def request_azure_devops_api_results():
    with open("Request Azure DevOps API Keys.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def request_new_ssl_certificate():
    with open("Request New SSL Certificate.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def request_prod_repo_in_azure_devops():
    with open("Request Prod Repo in Azure DevOps.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def request_policy_exception():
    with open("Request a Policy Exception.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def request_to_suppress_alert():
    with open("Request to Suppress Alert.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def reset_password():
    with open("Reset Password.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def review_own_cloud_permissions():
    with open("Review Own Cloud Permissions.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def role_of_risk_register():
    with open("Role of a Risk Register.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def rules_for_third_party_vendors():
    with open("Rules for Third Party Vendors.txt", "r") as x:
        e = x.read()
        print(e)
        return e
def secure_api_endpoints():
    with open("Secure API Endpoints.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def secure_access_from_home():
    with open("Secure Access from Home.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def secure_container_images():
    with open("Secure Container Images.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def securely_dispose_old_device():
    with open("Securely Dispose of Old Device.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def security_incident():
    with open("Security Incident.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def security_software_on_device():
    with open("Security Software on Device.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def set_up_reset_mfa():
    with open("Set Up Reset MFA.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def someone_asked_for_password():
    with open("Someone Asked for Password.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def strong_password():
    with open("Strong Password.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def suspicious_email_received():
    with open("Suspicious Email Received.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def threat_intelligence_vulnerabilities():
    with open("Threat Intelligence & Vulnerabilities.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def threat_modeling():
    with open("Threat Modeling.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def threat_vs_vulnerability_vs_risk():
    with open("Threat vs. Vulnerability vs. Risk.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def transfer_data_to_new_laptop():
    with open("Transfer Data to New Laptop.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def trouble_connecting_to_vpn():
    with open("Trouble Connecting to VPN.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def unauthorized_person_in_office():
    with open("Unauthorized Person in Office.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def update_os_software():
    with open("Update OS Software.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def update_recovery_info():
    with open("Update Recovery Info.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def verify_client_identity_sensitive_data():
    with open("Verify Client Identity for Sensitive Data.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def virus_malware_warning():
    with open("Virus Malware Warning.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def visitors_policy():
    with open("Visitors Policy.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def what_is_mfa():
    with open("What is MFA.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def what_is_virus_worm_trojan():
    with open("What is Virus vs. Worm vs. Trojan.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def what_is_cloud_resource_policy():
    with open("What is a \"Cloud Resource Policy\".txt", "r") as x:
        e = x.read()
        print(e)
        return e

def what_is_privileged_account():
    with open("What is a Privileged Account.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def what_is_soc():
    with open("What is a SOC.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def whitelist_ip_in_firewall():
    with open("Whitelist IP in Firewall.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def who_is_our_dpo_ciso():
    with open("Who is our DPO CISO.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def why_change_password_frequently():
    with open("Why Change Password Frequently.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def why_is_software_blocked():
    with open("Why is Software Blocked.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def your_data_responsibilities():
    with open("Your Data Responsibilities.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def zero_day_vulnerability():
    with open("Zero Day Vulnerability.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def sample():
    with open("sample.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def virus_worm_trojan():
    with open("virus worm trojan.txt", "r") as x:
        e = x.read()
        print(e)
        return e

def webcam_for_confidential():
    with open("webcam for confidential.txt", "r") as x:
        e = x.read()
        print(e)
        return e
    
nltk.download('stopwords')
nltk.download('punkt')
stop_words = set(stopwords.words('english'))
tokens = word_tokenize(text)
#b = text.split()
filter = [word for word in tokens if word.lower() not in stop_words]
##print("filtered words=",filter)
# Join the filtered words back together
result = " ".join(filter)
##print("Processed Input:", result)


if result == 'publiclink' or result == 'sharingpolicy':
    e = public_link_sharing_policy()

elif result == 'access_azure_prod_uat' or result == 'aws':
    e = access_azure_aws_prod_uat()

elif result == 'access_cloud_vulnerabilities' or result == 'cloud_cspm_report':
    e = access_cloud_vulnerabilities_report()

elif result == 'access_denied_azure' or result == 'azure_access_issue':
    e = access_denied_in_azure()

elif result == 'access_files_departed_colleague' or result == 'departed_colleague_files':
    e = access_files_of_departed_colleague()

elif result == 'apply_software_patch' or result == 'software_patch':
    e = apply_software_patch()

elif result == 'are_we_compliant' or result == 'compliance_check':
    e = are_we_compliant()

elif result == 'check_device_encryption' or result == 'device_encryption_status':
    e = check_device_encryption()

elif result == 'clicked_suspicious_link' or result == 'suspicious_link_clicked':
    e = clicked_suspicious_link()

elif result == 'common_phishing_signs' or result == 'phishing_signs':
    e = common_phishing_signs()

elif result == 'company_mdm_personal_phone' or result == 'mdm_on_personal_phone':
    e = company_mdm_on_personal_phone()

elif result == 'connect_corporate_vpn' or result == 'corporate_vpn_access':
    e = connect_to_corporate_vpn()

elif result == 'connect_guest_wifi' or result == 'guest_wifi_connection':
    e = connect_to_guest_wifi()

elif result == 'consequences_violation' or result == 'violation_consequences':
    e = consequences_of_violation()

elif result == 'password_policy' or result == 'corporate_password_policy':
    e = corporate_password_policy()

elif result == 'network_info' or result == 'corporate_vs_guest_network':
    e = corporate_vs_guest_network()

elif result == 'security_ticket' or result == 'create_security_ticket':
    e = create_security_ticket()

elif result == 'data_classification':
    e = data_classification()

elif result == 'device_strange' or result == 'device_behaving_strangely':
    e = device_behaving_strangely()

elif result == 'security_breach' or result == 'during_security_breach':
    e = during_security_breach()

elif result == 'enable_waf' or result == 'enable_waf_for_my_app':
    e = enable_waf_for_my_app()

elif result == 'encryption_policy':
    e = encryption_policy()

elif result == 'device_compliance' or result == 'ensure_device_compliance':
    e = ensure_device_compliance()

elif result == 'suspicious_password' or result == 'entered_password_on_suspicious_site':
    e = entered_password_on_suspicious_site()

elif result == 'escorting_visitors':
    e = escorting_visitors()

elif result == 'phishing_example' or result == 'example_of_phishing_attempt':
    e = example_of_phishing_attempt()

elif result == 'false_positive' or result == 'false_positive_vs_risk_accepted':
    e = false_positive_vs_risk_accepted()

elif result == 'file_retention':
    e = file_retention()

elif result == 'infosec_policy' or result == 'find_infosec_policy':
    e = find_infosec_policy()

elif result == 'security_training' or result == 'get_security_training':
    e = get_security_training()
elif result == 'confidential_info' or result == 'handle_confidential_info':
    e = handle_confidential_info()

elif result == 'cloud_sync_secure' or result == 'is_my_cloud_sync_secure':
    e = is_my_cloud_sync_secure()

elif result == 'leaving_role' or result == 'leaving_company_role':
    e = leaving_company_role()

elif result == 'account_locked' or result == 'locked_out_of_account':
    e = locked_out_of_account()

elif result == 'lost_device' or result == 'lost_stolen_laptop_phone':
    e = lost_stolen_laptop_phone()

elif result == 'mfa_error':
    e = mfa_error()

elif result == 'mitm_attack':
    e = mitm_attack()

elif result == 'non_human_identities' or result == 'manage_non_human_identities':
    e = manage_non_human_identities()

elif result == 'reviewing_access' or result == 'manager_reviewing_access':
    e = manager_reviewing_access()

elif result == 'onboard_app' or result == 'onboard_new_application':
    e = onboard_new_application()

elif result == 'password':
    e = password()

elif result == 'personal_device_email' or result == 'personal_device_to_company_email':
    e = personal_device_to_company_email()

elif result == 'file_sharing_services' or result == 'personal_file_sharing_services':
    e = personal_file_sharing_services()

elif result == 'router_in_office' or result == 'personal_router_in_office':
    e = personal_router_in_office()

elif result == 'smart_device_wifi' or result == 'personal_smart_device_on_wifi':
    e = personal_smart_device_on_wifi()

elif result == 'usb_drives' or result == 'personal_usb_drives':
    e = personal_usb_drives()

elif result == 'cloud_storage_policy' or result == 'policy_for_cloud_data_storage':
    e = policy_for_cloud_data_storage()

elif result == 'remote_wipe_policy' or result == 'policy_for_remote_wipe':
    e = policy_for_remote_wipe()

elif result == 'bluetooth_policy' or result == 'policy_on_bluetooth':
    e = policy_on_bluetooth()

elif result == 'public_wifi_policy' or result == 'policy_on_public_wifi':
    e = policy_on_public_wifi()

elif result == 'recording_meetings_policy' or result == 'policy_on_recording_meetings':
    e = policy_on_recording_meetings()
elif result == 'least_privilege' or result == 'principle_of_least_privilege':
    e = principle_of_least_privilege()

elif result == 'request_device' or result == 'raise_request_for_device':
    e = raise_request_for_device()

elif result == 'lost_badge' or result == 'report_lost_stolen_badge':
    e = report_lost_stolen_badge()

elif result == 'report_phishing':
    e = report_phishing()

elif result == 'app_access' or result == 'request_application_access':
    e = request_application_access()

elif result == 'azure_api_results' or result == 'request_azure_devops_api_results':
    e = request_azure_devops_api_keys()

elif result == 'ssl_certificate' or result == 'request_new_ssl_certificate':
    e = request_new_ssl_certificate()

elif result == 'prod_repo' or result == 'request_prod_repo_in_azure_devops':
    e = request_prod_repo_in_azure_devops()

elif result == 'policy_exception' or result == 'request_policy_exception':
    e = request_policy_exception()

elif result == 'suppress_alert' or result == 'request_to_suppress_alert':
    e = request_to_suppress_alert()

elif result == 'reset_password':
    e = reset_password()

elif result == 'cloud_permissions' or result == 'review_own_cloud_permissions':
    e = review_own_cloud_permissions()

elif result == 'risk_register' or result == 'role_of_risk_register':
    e = role_of_risk_register()

elif result == 'third_party_rules' or result == 'rules_for_third_party_vendors':
    e = rules_for_third_party_vendors()

elif result == 'secure_api' or result == 'secure_api_endpoints':
    e = secure_api_endpoints()

elif result == 'secure_home_access' or result == 'secure_access_from_home':
    e = secure_access_from_home()

elif result == 'secure_container' or result == 'secure_container_images':
    e = secure_container_images()

elif result == 'dispose_device' or result == 'securely_dispose_old_device':
    e = securely_dispose_old_device()

elif result == 'security_incident':
    e = security_incident()

elif result == 'security_software' or result == 'security_software_on_device':
    e = security_software_on_device()

elif result == 'setup_mfa' or result == 'set_up_reset_mfa':
    e = set_up_reset_mfa()

elif result == 'asked_for_password' or result == 'someone_asked_for_password':
    e = someone_asked_for_password()

elif result == 'strong_password':
    e = strong_password()

elif result == 'suspicious_email' or result == 'suspicious_email_received':
    e = suspicious_email_received()

elif result == 'threat_intel' or result == 'threat_intelligence_vulnerabilities':
    e = threat_intelligence_vulnerabilities()

elif result == 'threat_modeling':
    e = threat_modeling()

elif result == 'threat_vs_risk' or result == 'threat_vs_vulnerability_vs_risk':
    e = threat_vs_vulnerability_vs_risk()

elif result == 'transfer_data' or result == 'transfer_data_to_new_laptop':
    e = transfer_data_to_new_laptop()

elif result == 'vpn_issue' or result == 'trouble_connecting_to_vpn':
    e = trouble_connecting_to_vpn()

elif result == 'unauthorized_person' or result == 'unauthorized_person_in_office':
    e = unauthorized_person_in_office()

elif result == 'update_os' or result == 'update_os_software':
    e = update_os_software()

elif result == 'update_recovery' or result == 'update_recovery_info':
    e = update_recovery_info()

elif result == 'verify_identity' or result == 'verify_client_identity_sensitive_data':
    e = verify_client_identity_sensitive_data()

elif result == 'malware_warning' or result == 'virus_malware_warning':
    e = virus_malware_warning()

elif result == 'visitors_policy':
    e = visitors_policy()

elif result == 'what_is_mfa':
    e = what_is_mfa()

elif result == 'virus_worm_trojan' or result == 'what_is_virus_worm_trojan':
    e = what_is_virus_worm_trojan()

elif result == 'cloud_resource_policy' or result == 'what_is_cloud_resource_policy':
    e = what_is_cloud_resource_policy()

elif result == 'privileged_account' or result == 'what_is_privileged_account':
    e = what_is_privileged_account()

elif result == 'soc' or result == 'what_is_soc':
    e = what_is_soc()

elif result == 'whitelist_ip' or result == 'whitelist_ip_in_firewall':
    e = whitelist_ip_in_firewall()

elif result == 'dpo_ciso' or result == 'who_is_our_dpo_ciso':
    e = who_is_our_dpo_ciso()

elif result == 'change_password' or result == 'why_change_password_frequently':
    e = why_change_password_frequently()

elif result == 'software_blocked' or result == 'why_is_software_blocked':
    e = why_is_software_blocked()

elif result == 'data_responsibilities' or result == 'your_data_responsibilities':
    e = your_data_responsibilities()

elif result == 'zero_day' or result == 'zero_day_vulnerability':
    e = zero_day_vulnerability()

elif result == 'sample':
    e = sample()

elif result == 'virus_worm_trojan_alt' or result == 'virus_worm_trojan':
    e = virus_worm_trojan()

elif result == 'webcam_confidential' or result == 'webcam_for_confidential':
    e = webcam_for_confidential()
else:
    user_input = result


    user_input1 = "publiclink"
    user_input2 = "accessazureproduat"
    user_input3 = "cloudcspmreport"
    user_input4 = "azureaccessissue"
    user_input5 = "departedcolleaguefiles"
    user_input6 = "softwarepatch"
    user_input7 = "compliancecheck"
    user_input8 = "suspiciouslinkclicked"
    user_input9 = "checkdeviceencryption"
    user_input10 = "commonphishingsigns"
    user_input11 = "companymdmpersonalphone"
    user_input12 = "connectcorporatevpn"
    user_input13 = "connectguestwifi"
    user_input14 = "consequencesviolation"
    user_input15 = "passwordpolicy"
    user_input16 = "networkinfo"
    user_input17 = "securityticket"
    user_input18 = "dataclassification"
    user_input19 = "devicestrange"
    user_input20 = "securitybreach"
    user_input21 = "enablewaf"
    user_input22 = "encryptionpolicy"
    user_input23 = "devicecompliance"
    user_input24 = "suspiciouspassword"
    user_input25 = "escortingvisitors"
    user_input26 = "phishingexample"
    user_input27 = "falsepositive"
    user_input28 = "fileretention"
    user_input29 = "infosecpolicy"
    user_input30 = "securitytraining"
    user_input31 = "confidentialinfo"
    user_input32 = "cloudsyncsecure"
    user_input33 = "leavingrole"
    user_input34 = "accountlocked"
    user_input35 = "lostdevice"
    user_input36 = "mfaerror"
    user_input37 = "mitmattack"
    user_input38 = "nonhumanidentities"
    user_input39 = "reviewingaccess"
    user_input40 = "onboardapp"
    user_input41 = "password"
    user_input42 = "personaldeviceemail"
    user_input43 = "filesharingservices"
    user_input44 = "routerinoffice"
    user_input45 = "smartdevicewifi"
    user_input46 = "usbdrives"
    user_input47 = "cloudstoragepolicy"
    user_input48 = "remotewipepolicy"
    user_input49 = "bluetoothpolicy"
    user_input50 = "publicwifipolicy"
    user_input51 = "recordingmeetingspolicy"
    user_input52 = "leastprivilege"
    user_input53 = "requestdevice"
    user_input54 = "lostbadge"
    user_input55 = "reportphishing"
    user_input56 = "requestapplicationaccess"
    user_input57 = "requestazuredevopsapikeys"
    user_input58 = "requestnewsslcertificate"
    user_input59 = "requestprodrepoinazuredevops"
    user_input60 = "requestpolicyexception"
    user_input61 = "requesttosuppressalert"
    user_input62 = "resetpassword"
    user_input63 = "reviewowncloudpermissions"
    user_input64 = "roleofriskregister"
    user_input65 = "rulesforthirdpartyvendors"
    user_input66 = "secureapiendpoints"
    user_input67 = "secureaccessfromhome"
    user_input68 = "securecontainerimages"
    user_input69 = "securelydisposeolddevice"
    user_input70 = "securityincident"
    user_input71 = "securitysoftwareondevice"
    user_input72 = "setupresetmfa"
    user_input73 = "someoneaskedforpassword"
    user_input74 = "strongpassword"
    user_input75 = "suspiciousemailreceived"
    user_input76 = "threatintelligencevulnerabilities"
    user_input77 = "threatmodeling"
    user_input78 = "threatvsvulnerabilityvsrisk"
    user_input79 = "transferdatatonewlaptop"
    user_input80 = "troubleconnectingtovpn"
    user_input81 = "unauthorizedpersoninoffice"
    user_input82 = "updateossoftware"
    user_input83 = "updaterecoveryinfo"
    user_input84 = "verifyclientidentitysensitivedata"
    user_input85 = "virusmalwarewarning"
    user_input86 = "visitorspolicy"
    user_input87 = "whatismfa"
    user_input88 = "whatisviruswormtrojan"
    user_input89 = "whatiscloudresourcepolicy"
    user_input90 = "whatisprivilegedaccount"
    user_input91 = "whatissoc"
    user_input92 = "whitelistipinfirewall"
    user_input93 = "whoisourdpociso"
    user_input94 = "whychangepasswordfrequently"
    user_input95 = "whyissoftwareblocked"
    user_input96 = "yourdataresponsibilities"
    user_input97 = "zerodayvulnerability"
    user_input98 = "sample"
    user_input99 = "viruswormtrojan"
    user_input100 = "webcamforconfidential"


    Y1=fuzz.WRatio(user_input, user_input1)
    ###print("publiclink =",Y1)
    Y2=fuzz.WRatio(user_input, user_input2)
    ###print("aws =",Y2)
    Y3=fuzz.WRatio(user_input, user_input3)
    ###print("cloudcspmreport =",Y3)
    Y4=fuzz.WRatio(user_input, user_input4)
    #print("azureaccessissue =",Y4)
    Y5=fuzz.WRatio(user_input, user_input5)
    #print("departedcolleaguefiles =",Y5)
    Y6=fuzz.WRatio(user_input, user_input6)
    #print("softwarepatch =",Y6)
    Y7=fuzz.WRatio(user_input, user_input7)
    #print("compliancecheck =",Y7)
    Y8=fuzz.WRatio(user_input, user_input8)
    #print("suspiciouslinkclicked =",Y8)
    Y9=fuzz.WRatio(user_input, user_input9)
    #print("checkdeviceencryption =",Y9)
    Y10=fuzz.WRatio(user_input, user_input10)
    #print("commonphishingsigns =",Y10)
    Y11=fuzz.WRatio(user_input, user_input11)
    #print("companymdmpersonalphone =",Y11)
    Y12=fuzz.WRatio(user_input, user_input12)
    #print("connectcorporatevpn =",Y12)
    Y13=fuzz.WRatio(user_input, user_input13)
    #print("connectguestwifi =",Y13)
    Y14=fuzz.WRatio(user_input, user_input14)
    #print("consequencesviolation =",Y14)
    Y15=fuzz.WRatio(user_input, user_input15)
    #print("passwordpolicy =",Y15)
    Y16=fuzz.WRatio(user_input, user_input16)
    #print("networkinfo =",Y16)
    Y17=fuzz.WRatio(user_input, user_input17)
    #print("securityticket =",Y17)
    Y18=fuzz.WRatio(user_input, user_input18)
    #print("dataclassification =",Y18)
    Y19=fuzz.WRatio(user_input, user_input19)
    #print("devicestrange =",Y19)
    Y20=fuzz.WRatio(user_input, user_input20)
    #print("securitybreach =",Y20)
    Y21=fuzz.WRatio(user_input, user_input21)
    #print("enablewaf =",Y21)
    Y22=fuzz.WRatio(user_input, user_input22)
    #print("encryptionpolicy =",Y22)
    Y23=fuzz.WRatio(user_input, user_input23)
    #print("devicecompliance =",Y23)
    Y24=fuzz.WRatio(user_input, user_input24)
    #print("suspiciouspassword =",Y24)
    Y25=fuzz.WRatio(user_input, user_input25)
    #print("escortingvisitors =",Y25)
    Y26=fuzz.WRatio(user_input, user_input26)
    #print("phishingexample =",Y26)
    Y27=fuzz.WRatio(user_input, user_input27)
    #print("falsepositive =",Y27)
    Y28=fuzz.WRatio(user_input, user_input28)
    #print("fileretention =",Y28)
    Y29=fuzz.WRatio(user_input, user_input29)
    #print("infosecpolicy =",Y29)
    Y30=fuzz.WRatio(user_input, user_input30)
    #print("securitytraining =",Y30)
    Y31=fuzz.WRatio(user_input, user_input31)
    #print("confidentialinfo =",Y31)
    Y32=fuzz.WRatio(user_input, user_input32)
    #print("cloudsyncsecure =",Y32)
    Y33=fuzz.WRatio(user_input, user_input33)
    #print("leavingrole =",Y33)
    Y34=fuzz.WRatio(user_input, user_input34)
    #print("accountlocked =",Y34)
    Y35=fuzz.WRatio(user_input, user_input35)
    #print("lostdevice =",Y35)
    Y36=fuzz.WRatio(user_input, user_input36)
    #print("mfaerror =",Y36)
    Y37=fuzz.WRatio(user_input, user_input37)
    #print("mitmattack =",Y37)
    Y38=fuzz.WRatio(user_input, user_input38)
    #print("nonhumanidentities =",Y38)
    Y39=fuzz.WRatio(user_input, user_input39)
    #print("reviewingaccess =",Y39)
    Y40=fuzz.WRatio(user_input, user_input40)
    #print("onboardapp =",Y40)
    Y41=fuzz.WRatio(user_input, user_input41)
    #print("password =",Y41)
    Y42=fuzz.WRatio(user_input, user_input42)
    #print("personaldeviceemail =",Y42)
    Y43=fuzz.WRatio(user_input, user_input43)
    #print("filesharingservices =",Y43)
    Y44=fuzz.WRatio(user_input, user_input44)
    #print("routerinoffice =",Y44)
    Y45=fuzz.WRatio(user_input, user_input45)
    #print("smartdevicewifi =",Y45)
    Y46=fuzz.WRatio(user_input, user_input46)
    #print("usbdrives =",Y46)
    Y47=fuzz.WRatio(user_input, user_input47)
    #print("cloudstoragepolicy =",Y47)
    Y48=fuzz.WRatio(user_input, user_input48)
    #print("remotewipepolicy =",Y48)
    Y49=fuzz.WRatio(user_input, user_input49)
    #print("bluetoothpolicy =",Y49)
    Y50=fuzz.WRatio(user_input, user_input50)
    #print("publicwifipolicy =",Y50)
    Y51=fuzz.WRatio(user_input, user_input51)
    #print("recordingmeetingspolicy =",Y51)
    Y52=fuzz.WRatio(user_input, user_input52)
    #print("leastprivilege =",Y52)
    Y53=fuzz.WRatio(user_input, user_input53)
    #print("requestdevice =",Y53)
    Y54=fuzz.WRatio(user_input, user_input54)
    #print("lostbadge =",Y54)
    Y55=fuzz.WRatio(user_input, user_input55)
    #print("reportphishing =",Y55)
    Y56=fuzz.WRatio(user_input, user_input56)
    #print("requestapplicationaccess =",Y56)
    Y57=fuzz.WRatio(user_input, user_input57)
    #print("requestazuredevopsapikeys =",Y57)
    Y58=fuzz.WRatio(user_input, user_input58)
    #print("requestnewsslcertificate =",Y58)
    Y59=fuzz.WRatio(user_input, user_input59)
    #print("requestprodrepoinazuredevops =",Y59)
    Y60=fuzz.WRatio(user_input, user_input60)
    #print("requestpolicyexception =",Y60)
    Y61=fuzz.WRatio(user_input, user_input61)
    #print("requesttosuppressalert =",Y61)
    Y62=fuzz.WRatio(user_input, user_input62)
    #print("resetpassword =",Y62)
    Y63=fuzz.WRatio(user_input, user_input63)
    #print("reviewowncloudpermissions =",Y63)
    Y64=fuzz.WRatio(user_input, user_input64)
    #print("roleofriskregister =",Y64)
    Y65=fuzz.WRatio(user_input, user_input65)
    #print("rulesforthirdpartyvendors =",Y65)
    Y66=fuzz.WRatio(user_input, user_input66)
    #print("secureapiendpoints =",Y66)
    Y67=fuzz.WRatio(user_input, user_input67)
    #print("secureaccessfromhome =",Y67)
    Y68=fuzz.WRatio(user_input, user_input68)
    #print("securecontainerimages =",Y68)
    Y69=fuzz.WRatio(user_input, user_input69)
    #print("securelydisposeolddevice =",Y69)
    Y70=fuzz.WRatio(user_input, user_input70)
    #print("securityincident =",Y70)
    Y71=fuzz.WRatio(user_input, user_input71)
    #print("securitysoftwareondevice =",Y71)
    Y72=fuzz.WRatio(user_input, user_input72)
    #print("setupresetmfa =",Y72)
    Y73=fuzz.WRatio(user_input, user_input73)
    #print("someoneaskedforpassword =",Y73)
    Y74=fuzz.WRatio(user_input, user_input74)
    #print("strongpassword =",Y74)
    Y75=fuzz.WRatio(user_input, user_input75)
    #print("suspiciousemailreceived =",Y75)
    Y76=fuzz.WRatio(user_input, user_input76)
    #print("threatintelligencevulnerabilities =",Y76)
    Y77=fuzz.WRatio(user_input, user_input77)
    #print("threatmodeling =",Y77)
    Y78=fuzz.WRatio(user_input, user_input78)
    #print("threatvsvulnerabilityvsrisk =",Y78)
    Y79=fuzz.WRatio(user_input, user_input79)
    #print("transferdatatonewlaptop =",Y79)
    Y80=fuzz.WRatio(user_input, user_input80)
    #print("troubleconnectingtovpn =",Y80)
    Y81=fuzz.WRatio(user_input, user_input81)
    #print("unauthorizedpersoninoffice =",Y81)
    Y82=fuzz.WRatio(user_input, user_input82)
    #print("updateossoftware =",Y82)
    Y83=fuzz.WRatio(user_input, user_input83)
    #print("updaterecoveryinfo =",Y83)
    Y84=fuzz.WRatio(user_input, user_input84)
    #print("verifyclientidentitysensitivedata =",Y84)
    Y85=fuzz.WRatio(user_input, user_input85)
    #print("virusmalwarewarning =",Y85)
    Y86=fuzz.WRatio(user_input, user_input86)
    #print("visitorspolicy =",Y86)
    Y87=fuzz.WRatio(user_input, user_input87)
    #print("whatismfa =",Y87)
    Y88=fuzz.WRatio(user_input, user_input88)
    #print("whatisviruswormtrojan =",Y88)
    Y89=fuzz.WRatio(user_input, user_input89)
    #print("whatiscloudresourcepolicy =",Y89)
    Y90=fuzz.WRatio(user_input, user_input90)
    #print("whatisprivilegedaccount =",Y90)
    Y91=fuzz.WRatio(user_input, user_input91)
    #print("whatissoc =",Y91)
    Y92=fuzz.WRatio(user_input, user_input92)
    #print("whitelistipinfirewall =",Y92)
    Y93=fuzz.WRatio(user_input, user_input93)
    #print("whoisourdpociso =",Y93)
    Y94=fuzz.WRatio(user_input, user_input94)
    #print("whychangepasswordfrequently =",Y94)
    Y95=fuzz.WRatio(user_input, user_input95)
    #print("whyissoftwareblocked =",Y95)
    Y96=fuzz.WRatio(user_input, user_input96)
    #print("yourdataresponsibilities =",Y96)
    Y97=fuzz.WRatio(user_input, user_input97)
    #print("zerodayvulnerability =",Y97)
    Y98=fuzz.WRatio(user_input, user_input98)
    #print("sample =",Y98)
    Y99=fuzz.WRatio(user_input, user_input99)
    #print("viruswormtrojan =",Y99)
    Y100=fuzz.WRatio(user_input, user_input100)
    #print("webcamforconfidential =",Y100)

    if Y1 > 80 :
        e = public_link_sharing_policy()
    elif Y2 > 80 :
        e = access_azure_aws_prod_uat()
    elif Y3 > 80 :
        e = access_cloud_vulnerabilities_report()
    elif Y4 > 80 :
        e = access_denied_in_azure()
    elif Y5 > 80 :
        e = access_files_of_departed_colleague()
    elif Y6 > 80 :
        e = apply_software_patch()
    elif Y7 > 80 :
        e = are_we_compliant()
    elif Y8 > 80 :
        e = clicked_suspicious_link()
    elif Y9 > 80 :
        e = check_device_encryption()
    elif Y10 > 80 :
        e = common_phishing_signs()
    elif Y11 > 80 :
        e = company_mdm_on_personal_phone()
    elif Y12 > 80 :
        e = connect_to_corporate_vpn()
    elif Y13 > 80 :
        e = connect_to_guest_wifi()
    elif Y14 > 80 :
        e = consequences_of_violation()
    elif Y15 > 80 :
        e = corporate_password_policy()
    elif Y16 > 80 :
        e = corporate_vs_guest_network()
    elif Y17 > 80 :
        e = create_security_ticket()
    elif Y18 > 80 :
        e = data_classification()
    elif Y19 > 80 :
        e = device_behaving_strangely()
    elif Y20 > 80 :
        e = during_security_breach()
    elif Y21 > 80 :
        e = enable_waf_for_my_app() 
    elif Y22 > 80 :
        e = encryption_policy()
    elif Y23 > 80 :
        e = ensure_device_compliance()
    elif Y24 > 80 :
        e = entered_password_on_suspicious_site()
    elif Y25 > 80 :
        e = escorting_visitors()
    elif Y26 > 80 :
        e = example_of_phishing_attempt()
    elif Y27 > 80 :
        e = false_positive_vs_risk_accepted()
    elif Y28 > 80 :
        e = file_retention()
    elif Y29 > 80 :
        e = find_infosec_policy()
    elif Y30 > 80 :
        e = get_security_training()
    elif Y31 > 80 :
        e = handle_confidential_info()
    elif Y32 > 80 :
        e = is_my_cloud_sync_secure()
    elif Y33 > 80 :
        e = leaving_company_role()
    elif Y34 > 80 :
        e = locked_out_of_account()
    elif Y35 > 80 :
        e = lost_stolen_laptop_phone()
    elif Y36 > 80 :
        e = mfa_error()
    elif Y37 > 80 :
        e = mitm_attack()
    elif Y38 > 80 :
        e = manage_non_human_identities()
    elif Y39 > 80 :
        e = manager_reviewing_access()
    elif Y40 > 80 :
        e = onboard_new_application()
    elif Y41 > 80 :
        e = password()
    elif Y42 > 80 :
        e = personal_device_to_company_email()
    elif Y43 > 80 :
        e = personal_file_sharing_services()
    elif Y44 > 80 :
        e = personal_router_in_office()
    elif Y45 > 80 :
        e = personal_smart_device_on_wifi()
    elif Y46 > 80 :
        e = personal_usb_drives()
    elif Y47 > 80 :
        e = policy_for_cloud_data_storage()
    elif Y48 > 80 :
        e = policy_for_remote_wipe()
    elif Y49 > 80 :
        e = policy_on_bluetooth()
    elif Y50 > 80 :
        e = policy_on_public_wifi()
    elif Y51 > 80 :
        e = policy_on_recording_meetings()
    elif Y52 > 80 :
        e = principle_of_least_privilege()
    elif Y53 > 80 :
        e = raise_request_for_device()
    elif Y54 > 80 :
        e = report_lost_stolen_badge()
    elif Y55 > 80 :
        e = report_phishing()
    elif Y56 > 80 :
        e = request_application_access()
    elif Y57 > 80 :
        e = request_azure_devops_api_keys()
    elif Y58 > 80 :
        e = request_new_ssl_certificate()
    elif Y59 > 80 :
        e = request_prod_repo_in_azure_devops()
    elif Y60 > 80 :
        e = request_policy_exception()
    elif Y61 > 80 :
        e = request_to_suppress_alert()
    elif Y62 > 80 :
        e = reset_password()
    elif Y63 > 80 :
        e = review_own_cloud_permissions()
    elif Y64 > 80 :
        e = role_of_risk_register()
    elif Y65 > 80 :
        e = rules_for_third_party_vendors()
    elif Y66 > 80 :
        e = secure_api_endpoints()
    elif Y67 > 80 :
        e = secure_access_from_home()
    elif Y68 > 80 :
        e = secure_container_images()
    elif Y69 > 80 :
        e = securely_dispose_old_device()
    elif Y70 > 80 :
        e = security_incident()
    elif Y71 > 80 :
        e = security_software_on_device()
    elif Y72 > 80 :
        e = set_up_reset_mfa()
    elif Y73 > 80 :
        e = someone_asked_for_password()
    elif Y74 > 80 :
        e = strong_password()
    elif Y75 > 80 :
        e = suspicious_email_received()
    elif Y76 > 80 :
        e = threat_intelligence_vulnerabilities()
    elif Y77 > 80 :
        e = threat_modeling()
    elif Y78 > 80 :
        e = threat_vs_vulnerability_vs_risk()
    elif Y79 > 80 :
        e = transfer_data_to_new_laptop()
    elif Y80 > 80 :
        e = trouble_connecting_to_vpn()
    elif Y81 > 80 :
        e = unauthorized_person_in_office()
    elif Y82 > 80 :
        e = update_os_software()
    elif Y83 > 80 :
        e = update_recovery_info()
    elif Y84 > 80 :
        e = verify_client_identity_sensitive_data()
    elif Y85 > 80 :
        e = virus_malware_warning()
    elif Y86 > 80 :
        e = visitors_policy()
    elif Y87 > 80 :
        e = what_is_mfa()
    elif Y88 > 80 :
        e = what_is_virus_worm_trojan()
    elif Y89 > 80 :
        e = what_is_cloud_resource_policy()
    elif Y90 > 80 :
        e = what_is_privileged_account()
    elif Y91 > 80 :
        e = what_is_soc()
    elif Y92 > 80 :
        e = whitelist_ip_in_firewall()
    elif Y93 > 80 :
        e = who_is_our_dpo_ciso()
    elif Y94 > 80 :
        e = why_change_password_frequently()
    elif Y95 > 80 :
        e = why_is_software_blocked()
    elif Y96 > 80 :
        e = your_data_responsibilities()
    elif Y97 > 80 :
        e = zero_day_vulnerability()
    elif Y98 > 80 :
        e = sample()
    elif Y99 > 80 :
        e = virus_worm_trojan()
    elif Y100 > 80 :
        e = webcam_for_confidential()
    else:
      print("Invalid input")

    



