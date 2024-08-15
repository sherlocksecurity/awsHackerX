import boto3
import random
import string
import json
from botocore.exceptions import NoCredentialsError, PartialCredentialsError, ClientError
import markdown2
import pdfkit

def generate_random_ami_id():
    return 'ami-' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))

def get_region_from_access_key(access_key, secret_key):
    regions = boto3.session.Session().get_available_regions('ec2')
    for region in regions:
        try:
            client = boto3.client('ec2', aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
            client.describe_regions()
            return region
        except Exception:
            continue
    return None

def list_services(region, access_key, secret_key):
    session = boto3.Session(aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
    available_services = session.get_available_services()
    accessible_services = []
    for service in available_services:
        try:
            client = session.client(service)
            client.meta.service_model.operation_names
            accessible_services.append(service)
        except Exception:
            continue
    return accessible_services

def perform_operation(client, operation_name):
    try:
        operation = client.meta.service_model.operation_model(operation_name)
        print(f"Executing operation: {operation_name}")

        params = {}
        for param_name, param in operation.input_shape.members.items():
            if param.required:
                value = input(f"Enter value for {param_name} ({param.documentation}): ")
                params[param_name] = value
        response = client.meta.client._make_api_call(operation_name, params)
        print(json.dumps(response, indent=2))
    except ClientError as e:
        print(f"Error executing operation: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

def explore_s3(client):
    while True:
        print("\nExploring S3:")
        print("1: List buckets")
        print("2: Download a file from a bucket")
        print("0: Go back to service list")
        action_choice = int(input("Enter the number of the action you want to perform: "))
        if action_choice == 0:
            break
        elif action_choice == 1:
            buckets = client.list_buckets()
            if 'Buckets' in buckets and buckets['Buckets']:
                for i, bucket in enumerate(buckets['Buckets']):
                    print(f"{i + 1}: {bucket['Name']}")
            else:
                print("No S3 buckets found.")
        elif action_choice == 2:
            bucket_name = input("Enter the bucket name: ")
            objects = client.list_objects_v2(Bucket=bucket_name)
            if 'Contents' in objects:
                for i, obj in enumerate(objects['Contents']):
                    print(f"{i + 1}: {obj['Key']} (Size: {obj['Size']} bytes)")
                file_choice = int(input("Enter the number of the file to download: "))
                file_key = objects['Contents'][file_choice - 1]['Key']
                download_path = input("Enter the download path (with filename): ")
                client.download_file(bucket_name, file_key, download_path)
                print(f"Downloaded {file_key} to {download_path}")
            else:
                print(f"No files found in bucket {bucket_name}.")

def explore_ec2(client):
    while True:
        print("\nExploring EC2:")
        print("1: List instances")
        print("2: Create a new EC2 instance")
        print("3: Terminate an EC2 instance")
        print("0: Go back to service list")
        action_choice = int(input("Enter the number of the action you want to perform: "))
        if action_choice == 0:
            break
        elif action_choice == 1:
            instances = client.describe_instances()
            for reservation in instances['Reservations']:
                for instance in reservation['Instances']:
                    print(f"Instance ID: {instance['InstanceId']}, State: {instance['State']['Name']}")
        elif action_choice == 2:
            ami_id = generate_random_ami_id()  # Replace with a valid AMI ID for actual usage
            instance_type = input("Enter the instance type (e.g., t2.micro): ")
            try:
                client.run_instances(ImageId=ami_id, InstanceType=instance_type, MinCount=1, MaxCount=1)
                print("Instance launched successfully.")
            except client.exceptions.ClientError as e:
                print(f"Error launching instance: {e}")
        elif action_choice == 3:
            instance_id = input("Enter the Instance ID to terminate: ")
            try:
                client.terminate_instances(InstanceIds=[instance_id])
                print(f"Instance {instance_id} terminated.")
            except client.exceptions.ClientError as e:
                print(f"Error terminating instance: {e}")

def explore_route53(client):
    while True:
        print("\nExploring Route 53:")
        print("1: List hosted zones")
        print("2: List records in a hosted zone")
        print("0: Go back to service list")
        action_choice = int(input("Enter the number of the action you want to perform: "))
        if action_choice == 0:
            break
        elif action_choice == 1:
            zones = client.list_hosted_zones()
            for zone in zones['HostedZones']:
                print(f"Zone ID: {zone['Id']}, Name: {zone['Name']}")
        elif action_choice == 2:
            zone_id = input("Enter the Hosted Zone ID to list records for: ")
            records = client.list_resource_record_sets(HostedZoneId=zone_id)
            for record in records['ResourceRecordSets']:
                print(f"Name: {record['Name']}, Type: {record['Type']}, TTL: {record.get('TTL', 'N/A')}")
        else:
            print("Invalid option.")

def explore_other_services(service_name, client):
    while True:
        print(f"\nExploring {service_name}:")
        try:
            operations = client.meta.service_model.operation_names
            print(f"Available operations for {service_name}:")
            for i, op in enumerate(operations):
                print(f"{i + 1}: {op}")
            op_choice = int(input("Enter the number of the operation to execute (0 to go back): "))
            if op_choice == 0:
                break
            operation_name = operations[op_choice - 1]
            perform_operation(client, operation_name)
        except Exception as e:
            print(f"Could not list operations for {service_name}: {str(e)}")

def explore_services(services, region, access_key, secret_key):
    session = boto3.Session(aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)
    while True:
        print("\nAccessible AWS Services:")
        for i, service in enumerate(services):
            print(f"{i + 1}: {service}")
        service_choice = int(input("\nEnter the number of the service you want to explore (0 to exit): "))
        if service_choice == 0:
            break
        service_name = services[service_choice - 1]
        client = session.client(service_name)
        if service_name == 's3':
            explore_s3(client)
        elif service_name == 'ec2':
            explore_ec2(client)
        elif service_name == 'route53':
            explore_route53(client)
        else:
            explore_other_services(service_name, client)

def generate_markdown_report(credentials):
    report = []

    # AWS Account Info
    report.append("# AWS Comprehensive Report\n")
    report.append(f"**Access Key: REDACTED-This is a POC** \n")
    
    # Account Information
    try:
        sts_client = boto3.client('sts', aws_access_key_id=credentials['access_key'], aws_secret_access_key=credentials['secret_key'])
        account_id = sts_client.get_caller_identity().get('Account')
        report.append(f"**Account ID:** {account_id}\n")
    except ClientError as e:
        report.append(f"Error retrieving account information: {e}\n")

    # IAM Roles
    try:
        iam_client = boto3.client('iam', aws_access_key_id=credentials['access_key'], aws_secret_access_key=credentials['secret_key'])
        roles = iam_client.list_roles()
        report.append("## IAM Roles\n")
        for role in roles['Roles']:
            report.append(f"- **Role Name:** {role['RoleName']}\n")
            report.append(f"  - **Role ARN:** {role['Arn']}\n")
            # Additional role details
            role_details = iam_client.get_role(RoleName=role['RoleName'])
            report.append(f"  - **Role Description:** {role_details['Role'].get('Description', 'N/A')}\n")
    except ClientError as e:
        report.append(f"Error retrieving IAM roles: {e}\n")

    # Security Groups
    try:
        ec2_client = boto3.client('ec2', aws_access_key_id=credentials['access_key'], aws_secret_access_key=credentials['secret_key'])
        security_groups = ec2_client.describe_security_groups()
        report.append("## Security Groups\n")
        for sg in security_groups['SecurityGroups']:
            report.append(f"- **Group ID:** {sg['GroupId']}\n")
            report.append(f"  - **Group Name:** {sg['GroupName']}\n")
            report.append(f"  - **Description:** {sg['Description']}\n")
            for rule in sg['IpPermissions']:
                if rule.get('IpRanges'):
                    report.append(f"  - **Inbound Rule:** {', '.join(ip_range['CidrIp'] for ip_range in rule['IpRanges'])}\n")
    except ClientError as e:
        report.append(f"Error retrieving security groups: {e}\n")

    # S3 Buckets
    try:
        s3_client = boto3.client('s3', aws_access_key_id=credentials['access_key'], aws_secret_access_key=credentials['secret_key'])
        buckets = s3_client.list_buckets()
        report.append("## S3 Buckets\n")
        for bucket in buckets['Buckets']:
            bucket_name = bucket['Name']
            try:
                region = s3_client.get_bucket_location(Bucket=bucket_name).get('LocationConstraint', 'us-east-1')
                s3_region_client = boto3.client('s3', aws_access_key_id=credentials['access_key'], aws_secret_access_key=credentials['secret_key'], region_name=region)
                bucket_acl = s3_region_client.get_bucket_acl(Bucket=bucket_name)
                public = any(grant['Grantee'].get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers' for grant in bucket_acl['Grants'])
                public_status = 'Public' if public else 'Private'
                report.append(f"- **Bucket Name:** {bucket_name}\n")
                report.append(f"  - **Region:** {region}\n")
                report.append(f"  - **Public Status:** {public_status}\n")
            except ClientError as e:
                report.append(f"  - **Error retrieving bucket details for {bucket_name}: {e}**\n")
    except ClientError as e:
        report.append(f"Error retrieving S3 buckets: {e}\n")

    # EC2 Instances
    try:
        instances = ec2_client.describe_instances()
        report.append("## EC2 Instances\n")
        for reservation in instances['Reservations']:
            for instance in reservation['Instances']:
                report.append(f"- **Instance ID:** {instance['InstanceId']}\n")
                report.append(f"  - **State:** {instance['State']['Name']}\n")
                report.append(f"  - **Type:** {instance['InstanceType']}\n")
                report.append(f"  - **Public IP:** {instance.get('PublicIpAddress', 'N/A')}\n")
    except ClientError as e:
        report.append(f"Error retrieving EC2 instances: {e}\n")

    # Route 53 Hosted Zones
    try:
        route53_client = boto3.client('route53', aws_access_key_id=credentials['access_key'], aws_secret_access_key=credentials['secret_key'])
        zones = route53_client.list_hosted_zones()
        report.append("## Route 53 Hosted Zones\n")
        for zone in zones['HostedZones']:
            report.append(f"- **Hosted Zone ID:** {zone['Id']}\n")
            report.append(f"  - **Name:** {zone['Name']}\n")
    except ClientError as e:
        report.append(f"Error retrieving Route 53 hosted zones: {e}\n")

    # CloudTrail Trails
    try:
        cloudtrail_client = boto3.client('cloudtrail', aws_access_key_id=credentials['access_key'], aws_secret_access_key=credentials['secret_key'])
        trails = cloudtrail_client.describe_trails()
        report.append("## CloudTrail Trails\n")
        for trail in trails['trailList']:
            report.append(f"- **Trail Name:** {trail['Name']}\n")
            report.append(f"  - **S3 Bucket:** {trail.get('S3BucketName', 'N/A')}\n")
    except ClientError as e:
        report.append(f"Error retrieving CloudTrail trails: {e}\n")

    # CloudWatch Alarms
    try:
        cloudwatch_client = boto3.client('cloudwatch', aws_access_key_id=credentials['access_key'], aws_secret_access_key=credentials['secret_key'])
        alarms = cloudwatch_client.describe_alarms()
        report.append("## CloudWatch Alarms\n")
        for alarm in alarms['MetricAlarms']:
            report.append(f"- **Alarm Name:** {alarm['AlarmName']}\n")
            report.append(f"  - **Metric:** {alarm['MetricName']}\n")
            report.append(f"  - **Threshold:** {alarm['Threshold']}\n")
    except ClientError as e:
        report.append(f"Error retrieving CloudWatch alarms: {e}\n")

    # Secrets Manager
    try:
        secrets_manager_client = boto3.client('secretsmanager', aws_access_key_id=credentials['access_key'], aws_secret_access_key=credentials['secret_key'])
        secrets = secrets_manager_client.list_secrets()
        report.append("## Secrets Manager Secrets\n")
        for secret in secrets['SecretList']:
            report.append(f"- **Secret Name:** {secret['Name']}\n")
    except ClientError as e:
        report.append(f"Error retrieving Secrets Manager secrets: {e}\n")

    # Parameter Store
    try:
        ssm_client = boto3.client('ssm', aws_access_key_id=credentials['access_key'], aws_secret_access_key=credentials['secret_key'])
        parameters = ssm_client.describe_parameters()
        report.append("## Parameter Store Parameters\n")
        for parameter in parameters['Parameters']:
            if 'SecureString' in parameter['Type']:
                report.append(f"- **Parameter Name:** {parameter['Name']}\n")
    except ClientError as e:
        report.append(f"Error retrieving Parameter Store parameters: {e}\n")


    return "\n".join(report)


def save_markdown_to_pdf(markdown_text, pdf_path):
    html = markdown2.markdown(markdown_text)
    pdfkit.from_string(html, pdf_path)

def main():
    access_key = input("Enter your AWS Access Key: ")
    secret_key = input("Enter your AWS Secret Key: ")

    try:
        credentials = {'access_key': access_key, 'secret_key': secret_key}
        region = get_region_from_access_key(access_key, secret_key)
        if region:
            if input("Do you want to generate a comprehensive report? (yes/no): ").strip().lower() == 'yes':
                report_markdown = generate_markdown_report(credentials)
                report_path = 'aws_report.md'
                with open(report_path, 'w') as f:
                    f.write(report_markdown)
                print(f"Markdown report saved to {report_path}")

                if input("Do you want to convert the report to PDF? (yes/no): ").strip().lower() == 'yes':
                    pdf_path = 'aws_report.pdf'
                    save_markdown_to_pdf(report_markdown, pdf_path)
                    print(f"PDF report saved to {pdf_path}")

            if input("Do you want to explore AWS services? (yes/no): ").strip().lower() == 'yes':
                services = list_services(region, access_key, secret_key)
                if services:
                    explore_services(services, region, access_key, secret_key)
                else:
                    print("No services accessible with these credentials.")
        else:
            print("Could not determine a valid AWS region for these credentials.")
    
    except (NoCredentialsError, PartialCredentialsError):
        print("Invalid credentials. Please check your access and secret keys.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
