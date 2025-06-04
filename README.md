# GetAccessTokenWithSSOCookie
This BOF can be used to request an access token to an entra resource using an entra ESTSAUTHPERSISTENT SSO cookie.

## Python Usage
### Install
pip install the requirements.txt file
```
> pip install -r requirements.txt
```

### Usage
```
python get-AccessTokenWithSSOCookie.py -h
usage: Usage: python get-AccessTokenWithSSOCookie.py <client_id> <tenant_id> <resource> <estsAuthP>

Request Entra ID access tokens using ESTSAUTHPERSISTENT cookie

positional arguments:
  client_id   (Required) Identifier for the client application to impersonate
  tenant_id   (Required) The identifier for the target Entra ID tenant
  resource    (Required) The target service/resource (e.g., https://graph.microsoft.com)
  estsAuthP   (Required) ESTSAUTHPERSISTENT cookie (Most likely taken from a cookies dump)

```
### Example
```
python get-AccessTokenWithSSOCookie.py 1950a258-227b-4e31-a9cf-717495945fc2  00000000-0000-0000-0000-000000000000 https://graph.microsoft.com 1.AXXXXXXXXXXXXX
```





## BOF Usage
### Build
This project can be compiled using Visual Studio 2022 or built from the command line. Follow the steps below to build it from the command line:

1. Run the Visual Studio environment script for x64
```
>"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64
```

2. Navigate to the projects root directory
```
cd path\to\your\project
```

3. Run the following command to start the build process using nmake

```
nmake all
```

### Usage
```
Usage: GetAccessTokenWithESTSCookie <client_id> <tenant_id> <resouce> <estsauthp>
Example: 
   GetAccessTokenWithESTSCookie d3590ed6-52b3-4102-aeff-aad2292ab01c 00000000-0000-0000-0000-000000000000 https://graph.microsoft.com 1.AVEAXXXX  
Options: 
    <client_id> -    (Required): Identifier for the client application to impersonate
    <tenant_id> - (Required): The identifier for the target Entra ID tenant
    <resource> - (Required): The target service/resource (e.g., https://graph.microsoft.com)
    <estsauthp> - (Required): The ESTSAUTHPERSISTENT cookie (Most likely taken from a cookies dump)

```
