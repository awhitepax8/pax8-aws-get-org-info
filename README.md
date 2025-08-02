# pax8-aws-get-org-info
python script to gather aws organization info to prepare for migration to pax8 org

# AWS Organization Information Retriever

This Python script retrieves comprehensive information about an AWS Organization, including:

- Organization summary and metadata
- Complete organizational unit (OU) hierarchy with parent-child relationships
- Account-to-OU assignments and organizational structure
- All accounts with detailed information
- Enabled AWS services with activation dates
- Delegated administrators with their delegated services
- Enabled policy types and organizational governance settings
- Complete Service Control Policies (SCPs) with full policy content
- SCP attachment mappings and inheritance analysis
- Custom vs AWS-managed SCP identification
- Service configuration analysis with migration complexity assessment
- Service dependency mapping for proper enablement sequencing
- Trusted access settings and service integration requirements
- IAM policies and roles with organization dependencies
- Migration planning intelligence with critical warnings and guidance

## Usage

1. Open the AWS Management Console and navigate to the CloudShell.
2. Upload the Python script named list-org-info.py to the CloudShell.
3. Run the script and redirect the output to a file named org-info.txt: python3 list-org-info.py > org-info.txt
4. Download both the "org-info.txt" file and the "org-analysis.json" file from the CloudShell.

## Prerequisites

- You must have the necessary permissions to access the AWS Organizations service and list the organization's information.

## Output

The script will generate an "org-info.txt" file (from redirected console output) and an "org-analysis.json" file that contain the following information:

**Console Output (org-info.txt):**
1. Organization Summary - Basic organizational information and metadata
2. Account Inventory - All accounts with names, IDs, emails, and status
3. Enabled Services - Organization-enabled services with activation details
4. Delegated Administrators - Admin accounts with their delegated services
5. Enabled Policy Types - Policy types enabled in the organization
6. Organizational Unit Hierarchy - Visual tree structure of OUs with accounts and policies
7. Service Control Policies Analysis - Complete SCP analysis with inheritance mapping
8. Service Configuration Analysis - Service-by-service migration requirements and complexity
9. IAM Dependencies - IAM resources with organization ID dependencies
10. Migration Planning Summary - Critical steps, warnings, and resource requirements

**JSON Export Data (org-analysis.json):**
1. Organization metadata and basic information
2. Complete account inventory with detailed attributes
3. Enabled services with configuration details
4. Delegated administrator relationships and services
5. Policy types and organizational governance settings
6. Complete organizational structure (roots, OUs, hierarchy, account assignments)
7. Service Control Policies (policies, attachments, inheritance mapping, custom policy content)
8. Service configurations (complexity assessment, trusted access settings, dependencies)
9. IAM dependency analysis results
10. Migration summary with metrics and planning intelligence

If there are no enabled services, delegated administrators, or enabled policy types, the script will print "None" for the corresponding section.

## Troubleshooting

If you encounter any issues while running the script, please check the following:

- Ensure that you have the necessary permissions to access the AWS Organizations service.
- Check the CloudShell logs for any error messages or additional information that may help you troubleshoot the issue.

If you continue to experience problems, please reach out to the appropriate support channels for assistance.


