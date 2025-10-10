import streamlit as st

# All your function definitions
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

def reset_password():
    with open("Reset Password.txt", "r") as x:
        e = x.read()
        return e

def report_phishing():
    with open("Report Phishing.txt", "r") as x:
        e = x.read()
        return e

def strong_password():
    with open("Strong Password.txt", "r") as x:
        e = x.read()
        return e

def what_is_mfa():
    with open("What is MFA.txt", "r") as x:
        e = x.read()
        return e

def check_device_encryption():
    with open("Check Device Encryption.txt", "r") as x:
        e = x.read()
        return e

def trouble_connecting_to_vpn():
    with open("Trouble Connecting to VPN.txt", "r") as x:
        e = x.read()
        return e

def security_incident():
    with open("Security Incident.txt", "r") as x:
        e = x.read()
        return e

# Add more functions as needed for other checkboxes
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

def clicked_suspicious_link():
    with open("Clicked Suspicious Link.txt", "r") as x:
        e = x.read()
        return e

def common_phishing_signs():
    with open("Common Phishing Signs.txt", "r") as x:
        e = x.read()
        return e

# Continue adding all your other functions here...

# Streamlit app
st.title("🔒 Security Help Desk - Checkbox Selection")
st.write("Check the topics you need information about:")

# Create checkboxes
public_link = st.checkbox("Public Link Sharing Policy")
access_azure = st.checkbox("Access Azure AWS Prod/UAT") 
cloud_report = st.checkbox("Cloud CSPM Report")
reset_pass = st.checkbox("Reset Password")
report_phish = st.checkbox("Report Phishing")
strong_pass = st.checkbox("Strong Password")
what_mfa = st.checkbox("What is MFA")
device_encrypt = st.checkbox("Device Encryption Check")
vpn_issues = st.checkbox("VPN Connection Issues")
security_inc = st.checkbox("Security Incident Report")

# Display results based on checkboxes
if public_link:
    st.subheader("Public Link Sharing Policy:")
    result = public_link_sharing_policy()
    st.write(result)


if access_azure:
    st.subheader("Access Azure AWS Prod/UAT:")
    result = access_azure_aws_prod_uat()
    st.write(result)


if cloud_report:
    st.subheader("Cloud CSPM Report:")
    result = access_cloud_vulnerabilities_report()
    st.write(result)


if reset_pass:
    st.subheader("Reset Password:")
    result = reset_password()
    st.write(result)


if report_phish:
    st.subheader("Report Phishing:")
    result = report_phishing()
    st.write(result)


if strong_pass:
    st.subheader("Strong Password:")
    result = strong_password()
    st.write(result)


if what_mfa:
    st.subheader("What is MFA:")
    result = what_is_mfa()
    st.write(result)


if device_encrypt:
    st.subheader("Device Encryption Check:")
    result = check_device_encryption()
    st.write(result)


if vpn_issues:
    st.subheader("VPN Connection Issues:")
    result = trouble_connecting_to_vpn()
    st.write(result)


if security_inc:
    st.subheader("Security Incident Report:")
    result = security_incident()
    st.write(result)
    

# Emergency contacts section
st.sidebar.title("Emergency Contacts")
st.sidebar.write("**Security Team:** security@company.com")
st.sidebar.write("**Emergency Line:** +1-XXX-XXX-XXXX")
st.sidebar.write("**IT Help Desk:** helpdesk@company.com")