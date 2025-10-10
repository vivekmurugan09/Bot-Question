import pandas as pd#GA with fuzzy
from fuzzywuzzy import fuzz
from fuzzywuzzy import process
import re
import pandas as pd
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize

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

def request_azure_devops_api_keys():
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
user_input = input("How can I help you? ")
tokens = word_tokenize(user_input)
stop_words = set(stopwords.words('english'))
words = user_input.lower()
filtered_words = [word for word in tokens if word.lower() not in stop_words]
key = " ".join(filtered_words)

if key == 'public_link' or key == 'sharing_policy':
    e = public_link_sharing_policy()
elif key == 'access_azure_prod_uat' or key == 'aws_prod_uat':
    e = access_azure_aws_prod_uat()
elif key == 'access_cloud_vulnerabilities' or key == 'cloud_cspm_report':
    e = access_cloud_vulnerabilities_report()
elif key == 'access_denied_azure' or key == 'azure_access_issue':
    e = access_denied_in_azure()
elif key == 'access_files_departed_colleague' or key == 'departed_colleague_files':
    e = access_files_of_departed_colleague()
elif key == 'apply_software_patch' or key == 'software_patch':
    e = apply_software_patch()
elif key == 'are_we_compliant' or key == 'compliance_check':
    e = are_we_compliant()
elif key == 'check_device_encryption' or key == 'device_encryption_status':
    e = check_device_encryption()
elif key == 'clicked_suspicious_link' or key == 'suspicious_link_clicked':
    e = clicked_suspicious_link()
elif key == 'common_phishing_signs' or key == 'phishing_signs':
    e = common_phishing_signs()
elif key == 'company_mdm_personal_phone' or key == 'mdm_on_personal_phone':
    e = company_mdm_on_personal_phone()
elif key == 'connect_corporate_vpn' or key == 'corporate_vpn_access':
    e = connect_to_corporate_vpn()
elif key == 'connect_guest_wifi' or key == 'guest_wifi_connection':
    e = connect_to_guest_wifi()
elif key == 'consequences_violation' or key == 'violation_consequences':
    e = consequences_of_violation()
elif key == 'password_policy' or key == 'corporate_password_policy':
    e = corporate_password_policy()
elif key == 'network_info' or key == 'corporate_vs_guest_network':
    e = corporate_vs_guest_network()
elif key == 'security_ticket' or key == 'create_security_ticket':
    e = create_security_ticket()
elif key == 'data_classification':
    e = data_classification()
elif key == 'device_strange' or key == 'device_behaving_strangely':
    e = device_behaving_strangely()

elif key == 'security_breach' or key == 'during_security_breach':
    e = during_security_breach()

elif key == 'enable_waf' or key == 'enable_waf_for_my_app':
    e = enable_waf_for_my_app()

elif key == 'encryption_policy':
    e = encryption_policy()

elif key == 'device_compliance' or key == 'ensure_device_compliance':
    e = ensure_device_compliance()

elif key == 'suspicious_password' or key == 'entered_password_on_suspicious_site':
    e = entered_password_on_suspicious_site()

elif key == 'escorting_visitors':
    e = escorting_visitors()

elif key == 'phishing_example' or key == 'example_of_phishing_attempt':
    e = example_of_phishing_attempt()

elif key == 'false_positive' or key == 'false_positive_vs_risk_accepted':
    e = false_positive_vs_risk_accepted()

elif key == 'file_retention':
    e = file_retention()

elif key == 'infosec_policy' or key == 'find_infosec_policy':
    e = find_infosec_policy()

elif key == 'security_training' or key == 'get_security_training':
    e = get_security_training()
elif key == 'confidential_info' or key == 'handle_confidential_info':
    e = handle_confidential_info()

elif key == 'cloud_sync_secure' or key == 'is_my_cloud_sync_secure':
    e = is_my_cloud_sync_secure()

elif key == 'leaving_role' or key == 'leaving_company_role':
    e = leaving_company_role()

elif key == 'account_locked' or key == 'locked_out_of_account':
    e = locked_out_of_account()

elif key == 'lost_device' or key == 'lost_stolen_laptop_phone':
    e = lost_stolen_laptop_phone()

elif key == 'mfa_error':
    e = mfa_error()

elif key == 'mitm_attack':
    e = mitm_attack()

elif key == 'non_human_identities' or key == 'manage_non_human_identities':
    e = manage_non_human_identities()

elif key == 'reviewing_access' or key == 'manager_reviewing_access':
    e = manager_reviewing_access()

elif key == 'onboard_app' or key == 'onboard_new_application':
    e = onboard_new_application()

elif key == 'password':
    e = password()

elif key == 'personal_device_email' or key == 'personal_device_to_company_email':
    e = personal_device_to_company_email()

elif key == 'file_sharing_services' or key == 'personal_file_sharing_services':
    e = personal_file_sharing_services()

elif key == 'router_in_office' or key == 'personal_router_in_office':
    e = personal_router_in_office()

elif key == 'smart_device_wifi' or key == 'personal_smart_device_on_wifi':
    e = personal_smart_device_on_wifi()

elif key == 'usb_drives' or key == 'personal_usb_drives':
    e = personal_usb_drives()

elif key == 'cloud_storage_policy' or key == 'policy_for_cloud_data_storage':
    e = policy_for_cloud_data_storage()

elif key == 'remote_wipe_policy' or key == 'policy_for_remote_wipe':
    e = policy_for_remote_wipe()

elif key == 'bluetooth_policy' or key == 'policy_on_bluetooth':
    e = policy_on_bluetooth()

elif key == 'public_wifi_policy' or key == 'policy_on_public_wifi':
    e = policy_on_public_wifi()

elif key == 'recording_meetings_policy' or key == 'policy_on_recording_meetings':
    e = policy_on_recording_meetings()
elif key == 'least_privilege' or key == 'principle_of_least_privilege':
    e = principle_of_least_privilege()

elif key == 'request_device' or key == 'raise_request_for_device':
    e = raise_request_for_device()

elif key == 'lost_badge' or key == 'report_lost_stolen_badge':
    e = report_lost_stolen_badge()

elif key == 'report_phishing':
    e = report_phishing()

elif key == 'app_access' or key == 'request_application_access':
    e = request_application_access()

elif key == 'azure_api_keys' or key == 'request_azure_devops_api_keys':
    e = request_azure_devops_api_keys()

elif key == 'ssl_certificate' or key == 'request_new_ssl_certificate':
    e = request_new_ssl_certificate()

elif key == 'prod_repo' or key == 'request_prod_repo_in_azure_devops':
    e = request_prod_repo_in_azure_devops()

elif key == 'policy_exception' or key == 'request_policy_exception':
    e = request_policy_exception()

elif key == 'suppress_alert' or key == 'request_to_suppress_alert':
    e = request_to_suppress_alert()

elif key == 'reset_password':
    e = reset_password()

elif key == 'cloud_permissions' or key == 'review_own_cloud_permissions':
    e = review_own_cloud_permissions()

elif key == 'risk_register' or key == 'role_of_risk_register':
    e = role_of_risk_register()

elif key == 'third_party_rules' or key == 'rules_for_third_party_vendors':
    e = rules_for_third_party_vendors()

elif key == 'secure_api' or key == 'secure_api_endpoints':
    e = secure_api_endpoints()

elif key == 'secure_home_access' or key == 'secure_access_from_home':
    e = secure_access_from_home()

elif key == 'secure_container' or key == 'secure_container_images':
    e = secure_container_images()

elif key == 'dispose_device' or key == 'securely_dispose_old_device':
    e = securely_dispose_old_device()

elif key == 'security_incident':
    e = security_incident()

elif key == 'security_software' or key == 'security_software_on_device':
    e = security_software_on_device()

elif key == 'setup_mfa' or key == 'set_up_reset_mfa':
    e = set_up_reset_mfa()

elif key == 'asked_for_password' or key == 'someone_asked_for_password':
    e = someone_asked_for_password()

elif key == 'strong_password':
    e = strong_password()

elif key == 'suspicious_email' or key == 'suspicious_email_received':
    e = suspicious_email_received()

elif key == 'threat_intel' or key == 'threat_intelligence_vulnerabilities':
    e = threat_intelligence_vulnerabilities()

elif key == 'threat_modeling':
    e = threat_modeling()

elif key == 'threat_vs_risk' or key == 'threat_vs_vulnerability_vs_risk':
    e = threat_vs_vulnerability_vs_risk()

elif key == 'transfer_data' or key == 'transfer_data_to_new_laptop':
    e = transfer_data_to_new_laptop()

elif key == 'vpn_issue' or key == 'trouble_connecting_to_vpn':
    e = trouble_connecting_to_vpn()

elif key == 'unauthorized_person' or key == 'unauthorized_person_in_office':
    e = unauthorized_person_in_office()

elif key == 'update_os' or key == 'update_os_software':
    e = update_os_software()

elif key == 'update_recovery' or key == 'update_recovery_info':
    e = update_recovery_info()

elif key == 'verify_identity' or key == 'verify_client_identity_sensitive_data':
    e = verify_client_identity_sensitive_data()

elif key == 'malware_warning' or key == 'virus_malware_warning':
    e = virus_malware_warning()

elif key == 'visitors_policy':
    e = visitors_policy()

elif key == 'what_is_mfa':
    e = what_is_mfa()

elif key == 'virus_worm_trojan' or key == 'what_is_virus_worm_trojan':
    e = what_is_virus_worm_trojan()

elif key == 'cloud_resource_policy' or key == 'what_is_cloud_resource_policy':
    e = what_is_cloud_resource_policy()

elif key == 'privileged_account' or key == 'what_is_privileged_account':
    e = what_is_privileged_account()

elif key == 'soc' or key == 'what_is_soc':
    e = what_is_soc()

elif key == 'whitelist_ip' or key == 'whitelist_ip_in_firewall':
    e = whitelist_ip_in_firewall()

elif key == 'dpo_ciso' or key == 'who_is_our_dpo_ciso':
    e = who_is_our_dpo_ciso()

elif key == 'change_password' or key == 'why_change_password_frequently':
    e = why_change_password_frequently()

elif key == 'software_blocked' or key == 'why_is_software_blocked':
    e = why_is_software_blocked()

elif key == 'data_responsibilities' or key == 'your_data_responsibilities':
    e = your_data_responsibilities()

elif key == 'zero_day' or key == 'zero_day_vulnerability':
    e = zero_day_vulnerability()

elif key == 'sample':
    e = sample()

elif key == 'virus_worm_trojan_alt' or key == 'virus_worm_trojan':
    e = virus_worm_trojan()

elif key == 'webcam_confidential' or key == 'webcam_for_confidential':
    e = webcam_for_confidential()
else:
    user_input = key


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