#
# this program matches the Kiuwan static code analysis with the CEWL list

# process, go through list of applications
# get the CVE list per application
# Get full unique list of applications and join them
# output the application, cve, <some cve columns>

import requests

import os
import base64

import json
import pandas as pd

# get environment variables
# kiuwan username/password  they don't support tokens
# CEWL token

# KIUWAN_USERNAME, KIUWAN_PASSWORD
# CEWL_TOKEN as environment variables

# Tokens to find in the JSON responses
LAST_SUCCESSFUL_BASELINE_TOKEN = "lastSuccessfulBaseline"
CODE_TOKEN = "code"
NAME_TOKEN = "name"
DATA_TOKEN = "data"
CVE_TOKEN = "cve"

# Endpoints used
KIUWAN_APPLICATIONS_ENDPOINT = "https://api.kiuwan.com/applications"
KIUWAN_SECURITY_INSIGHTS_ENDPOINT = "https://api.kiuwan.com/insights/analysis/security"
CEWL_ENDPOINT = "https://api.ctci.ai/api/v1/cewl"

# Getting the Environment Variables need to to run this application
kiuwan_username = os.getenv('KIUWAN_USERNAME') # None
kiuwan_password = os.environ.get('KIUWAN_PASSWORD') # None
corporate_id = os.environ.get('X-Kw-Corporate-Domain-Id')
cookie = os.environ.get('Cookie')
cewl_token = os.environ.get('CEWL_TOKEN')



# The Cookie environment variable is formatted like:
#   AWSALB\=<the value of AWSALB>; AWSALBCORS\=<the value of AWSALBCORS>
# checking that we have them necessary environment variables
if kiuwan_username is None or kiuwan_password is None or corporate_id is None or cewl_token is None:
    print(f"Check you have the following environment variables set:")
    print("\tKIUWAN_USERNAME, KIUWAN_PASSWORD, X-Kw-Corporate-Domain-Id, Cookie, CEWL_TOKEN")
    exit(-100)

output_file = "./output/cve_issues.csv"

#  TODO make the functions for each of the stages
# Get applications
# Get CVEs per application
# Match with CEWL
# output results

if __name__ == '__main__':
    # format username:password for basic authorization
    user_password = f"{kiuwan_username}:{kiuwan_password}"
    b64_username_password = base64.b64encode(user_password.encode()).decode()

    app_security_cve_list = []

    # if a file has already been created then just do a match with CEWL, otherwise do all the work
    if not os.path.isfile(output_file):

        try:
            response = requests.get(
                url=KIUWAN_APPLICATIONS_ENDPOINT,
                headers={
                    "X-Kw-Corporate-Domain-Id": f"{corporate_id}",
                    "Authorization": f"Basic {b64_username_password}",
                    "Cookie": f"{cookie}",
                },
            )
            print('Response HTTP Status Code: {status_code}'.format(
                status_code=response.status_code))
            print('Response HTTP Response Body: {content}'.format(
                content=response.text))

            the_response = response.text
            application_list_json = json.loads(the_response)
            #print(application_list_json)

            # lets loop through each application
            for app_entry in application_list_json:
                # app_entry = json.loads(application)
                # print(app_entry)
                application = app_entry[NAME_TOKEN]
                code = None
                if LAST_SUCCESSFUL_BASELINE_TOKEN in app_entry:
                    if CODE_TOKEN in app_entry[LAST_SUCCESSFUL_BASELINE_TOKEN]:
                        code = app_entry[LAST_SUCCESSFUL_BASELINE_TOKEN][CODE_TOKEN]

                print(application, code)

                try:
                    if code:
                        response = requests.get(
                            url=KIUWAN_SECURITY_INSIGHTS_ENDPOINT,
                            params={
                                "application": f"{application}",
                                "analysisCode": f"{code}",
                            },
                            headers={
                                "X-Kw-Corporate-Domain-Id": f"{corporate_id}",
                                "Authorization": f"Basic {b64_username_password}",
                                "Cookie": f"{cookie}"
                                },
                        )
                        print('Response HTTP Status Code: {status_code}'.format(
                            status_code=response.status_code))
                        print('Response HTTP Response Body: {content}'.format(
                            content=response.content))

                    app_security_insights = response.text
                    app_security_insights_json = json.loads(app_security_insights)
                    if DATA_TOKEN in app_security_insights_json:
                        print(app_security_insights_json[DATA_TOKEN])
                        for app_vulnerability_entry in app_security_insights_json[DATA_TOKEN]:
                            if CVE_TOKEN in app_vulnerability_entry:
                                cve=app_vulnerability_entry[CVE_TOKEN]
                                print(cve)
                                cve_entry = {"application": application, "code": code, "cve": cve}
                                app_security_cve_list.append(cve_entry)

                except requests.exceptions.RequestException:
                    print('HTTP Request failed')

        except requests.exceptions.RequestException:
            print('HTTP Request failed')

        application_df = pd.DataFrame(app_security_cve_list)
        print(application_df)

        #  write this out
        application_df.to_csv("./output/cve_issues.csv", index=False)
    else:
        application_df = pd.read_csv(output_file)
    print(application_df)
    application_unique_cves = list(application_df['cve'].unique())
    print(application_df['cve'].value_counts())
    print(f"Number of unique CVEs:{len(application_unique_cves)}")

# let's get CEWL and do a join, we do an isin as it's fast and easy to do!
url = CEWL_ENDPOINT
payload = {}
headers = {
  'x-api-key': f'{cewl_token}'
}

response = requests.request("GET", url, headers=headers)
cewl_json = json.loads(response.text)

if DATA_TOKEN in cewl_json:
    # then lets make this a data frame
    cewl_df = pd.DataFrame(cewl_json[DATA_TOKEN])
    print(cewl_df)
    print("Checking for any matchy matchy")
    # uncomment to test that it actually matching something in the list. If you are not sure it's working.
    # cewl_df_matching = cewl_df[cewl_df[CVE_TOKEN].isin(["CVE-2019-0708"] + application_unique_cves)]
    cewl_df_matching = cewl_df[cewl_df[CVE_TOKEN].isin(application_unique_cves)]
    if len(cewl_df_matching) > 0:
        print("Some matchy matchy found!")
        print(cewl_df_matching)
        # save the output
        cewl_df_matching.to_csv("./output/cewl_matchy_matchy.csv", index=False)
    else:
        print("No matching entries found")