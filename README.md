# devsecops_kiuwan
This is used to match the CEWL list (CVEs being Actively Exploited by Threat Actors) with Kiuwan software vulnerabilities

It uses the following environment variables

KIUWAN_USERNAME
KIUWAN_PASSWORD
X-Kw-Corporate-Domain-Id
Cookie
CEWL_TOKEN

The Cookie Cookie environment variable is formatted like:
    AWSALB\=<the value of AWSALB>; AWSALBCORS\=<the value of AWSALBCORS>

# Application Flow
If there is a Kiuwan run already in ./output/cve_issues.csv then just do a match with CEWL
else:
    Get Kiuwan applications
    Get Kiuwan CVEs per application
    Match Kiuwan CVEs with CEWL

Output results