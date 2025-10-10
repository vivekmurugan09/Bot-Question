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

# Streamlit app
st.title("Security Help Desk")
st.write("Click buttons to get information:")

# Create buttons
if st.button("Public Link Sharing Policy"):
    result = public_link_sharing_policy()
    st.write(result)

if st.button("Access Azure AWS Prod/UAT"):
    result = access_azure_aws_prod_uat()
    st.write(result)

if st.button("Cloud CSPM Report"):
    result = access_cloud_vulnerabilities_report()
    st.write(result)

if st.button("Reset Password"):
    result = reset_password()
    st.write(result)

if st.button("Report Phishing"):
    result = report_phishing()
    st.write(result)

if st.button("Strong Password"):
    result = strong_password()
    st.write(result)

if st.button("What is MFA"):
    result = what_is_mfa()
    st.write(result)

if st.button("Device Encryption Check"):
    result = check_device_encryption()
    st.write(result)

if st.button("VPN Connection Issues"):
    result = trouble_connecting_to_vpn()
    st.write(result)

if st.button("Security Incident Report"):
    result = security_incident()
    st.write(result)