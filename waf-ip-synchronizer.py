import json
import boto3
import time
import os
from datetime import datetime, timedelta

# Cache config file to avoid repeated S3 calls
config_cache = None
config_last_modified = None

# AWS clients
s3 = boto3.client("s3")
sts = boto3.client("sts")
sns = boto3.client("sns")

# Load environment variables
env = os.environ
BUCKET_NAME = env["BUCKET_NAME"]
CONFIG_KEY = env["CONFIG_KEY"]
SNS_TOPIC_ARN = env["SNS_TOPIC_ARN"]


def load_config():
    global config_cache, config_last_modified

    try:
        response = s3.head_object(Bucket=BUCKET_NAME, Key=CONFIG_KEY)
        last_modified = response["LastModified"]

        if config_cache is None:
            print("Fetching config from S3...")
            obj = s3.get_object(Bucket=BUCKET_NAME, Key=CONFIG_KEY)
            config_cache = json.loads(obj["Body"].read())
            config_last_modified = last_modified

        elif last_modified != config_last_modified:
            print("Config updated, fetching latest config from S3...")
            obj = s3.get_object(Bucket=BUCKET_NAME, Key=CONFIG_KEY)
            config_cache = json.loads(obj["Body"].read())
            config_last_modified = last_modified

        else:
            print("Using cached config to avoid repetitive S3 calls...")

        return config_cache

    except Exception as e:
        print("Unable to load configuration from S3")
        print(f"Reason: {str(e)}")
        raise


def lambda_handler(event, context):
    try:
        # Step 1: Lambda Execution
        print("Step 1: Lambda execution started")

        # Step 2: Event validation
        print("Step 2: Validating incoming event...")

        detail = event.get("detail")
        request_params = detail.get("requestParameters") if detail else None

        if not detail or not request_params or "addresses" not in request_params:
            print("Invalid event, skipping execution")
            print("Lambda execution stopped")
            return

        print("Event validated successfully")

        incoming_ips = request_params.get("addresses", [])

        # IP presence check
        print("Checking if IP(s) are present in the event...")

        if not incoming_ips:
            print("No IP(s) found in event, skipping execution")
            print("Lambda execution stopped")
            return

        print("IP(s) found in event, continuing execution")

        # Log incoming event
        # print(json.dumps(event))

        # Remove duplicate IPs
        incoming_ips = list(set(incoming_ips))
        print(f"IP(s) to be appended in the targets: {', '.join(incoming_ips)}")

        # Step 3: Config load from S3
        print("Step 3: Loading configuration from S3")
        config = load_config()
        print(f"Configuration loaded successfully for {len(config['accounts'])} account(s)")

        # Step 4: Cross-account execution phase
        print("Step 4: Assuming roles and starting IP synchronization across target accounts")

        synced_accounts = []
        failed_accounts = []
        skipped_accounts = []

        for account in config["accounts"]:
            account_id = account["account_id"]
            account_name = account.get("account_name", "unknown")
            role_arn = account["role_arn"]
            ipset_id = account["ipset_id"]
            ipset_name = account["ipset_name"]
            region = account["region"]

            try:
                assumed = sts.assume_role(
                    RoleArn=role_arn,
                    RoleSessionName="WAFSyncSession",
                    DurationSeconds=900
                )
                creds = assumed["Credentials"]

                waf = boto3.client(
                    "wafv2",
                    region_name=region,
                    aws_access_key_id=creds["AccessKeyId"],
                    aws_secret_access_key=creds["SecretAccessKey"],
                    aws_session_token=creds["SessionToken"]
                )

                max_retries = 3
                for attempt in range(1, max_retries + 1):
                    try:
                        ipset = waf.get_ip_set(
                            Name=ipset_name,
                            Scope="REGIONAL",
                            Id=ipset_id
                        )
                        current_ips = ipset["IPSet"]["Addresses"]

                        new_ips = [ip for ip in incoming_ips if ip not in current_ips]

                        if not new_ips:
                            print(f"Account {account_name} ({account_id}): SKIPPED")
                            print("Reason: IP(s) already exist in IP set")
                            skipped_accounts.append(f"{account_name} ({account_id})")
                            break

                        updated_ips = current_ips + new_ips

                        waf.update_ip_set(
                            Name=ipset_name,
                            Scope="REGIONAL",
                            Id=ipset_id,
                            Addresses=updated_ips,
                            LockToken=ipset["LockToken"]
                        )

                        print(f"Account {account_name} ({account_id}): SYNCED")
                        synced_accounts.append(f"{account_name} ({account_id})")
                        break

                    except waf.exceptions.WAFOptimisticLockException:
                        print(f"Lock conflict detected, retrying (attempt {attempt})")
                        if attempt < max_retries:
                            time.sleep(1)
                        else:
                            raise RuntimeError("IP synchronization failed due to repeated WAF lock conflicts after multiple retries")

            except Exception as e:
                print(f"Account {account_name} ({account_id}): FAILED")
                print(f"Reason: {str(e)}")
                failed_accounts.append({
                    "name": account_name,
                    "account": f"{account_name} ({account_id})"
                })

            time.sleep(0.2)

        # Step 5: Final Summary
        print("Step 5: Aggregating final synchronization results...")

        total_accounts = len(config['accounts'])
        num_failed = len(failed_accounts)
        num_synced = len(synced_accounts)
        num_skipped = len(skipped_accounts)

        if num_failed > 0:
            final_status_message = f"IP Synchronization failed for {num_failed} account(s)"
        elif num_skipped > 0 and num_synced == 0:
            final_status_message = f"IP Synchronization skipped for {num_skipped} account(s)"
        else:
            final_status_message = "IP Synchronization completed successfully across all accounts"

        print(final_status_message)

        summary_dict = {
            "total_accounts": total_accounts,
            "synced_accounts": {
                "count": num_synced,
                "name": synced_accounts if synced_accounts else []
            },
            "failed_accounts": {
                "count": num_failed,
                "name": [acc['account'] for acc in failed_accounts] if failed_accounts else []
            },
            "skipped_accounts": {
                "count": num_skipped,
                "name": skipped_accounts if skipped_accounts else []
            }
        }

        print(json.dumps(summary_dict))

        user_identity = event.get("detail", {}).get("userIdentity", {})
        arn = user_identity.get("arn", "")
        username = arn.split("/")[-1] if arn and "/" in arn else "Unknown"

        ist_time = datetime.utcnow() + timedelta(hours=5, minutes=30)
        execution_time = ist_time.strftime("%Y-%m-%d %H:%M:%S IST")

        if failed_accounts:
            message = f"""
The Cross Account WAF IP Synchronization Lambda function was executed by {username} at {execution_time} from the source account.

Below is the summary of the execution:

Total accounts processed: {total_accounts}

Synced account(s): {num_synced}

Skipped account(s): {num_skipped}
    
Failed account(s): {num_failed}
Account name(s): {', '.join([acc['account'] for acc in failed_accounts])}
"""
            try:
                sns.publish(
                    TopicArn=SNS_TOPIC_ARN,
                    Subject="Action Required: Cross Account WAF IP Synchronization Failed for Target Account(s)",
                    Message=message
                )
                print("Notification sent successfully via SNS")
            except Exception as e:
                print("Failed to send notification via SNS")
                print(f"Reason: {str(e)}")

        print("Lambda execution stopped")

    except Exception as e:
        print("Lambda execution failed")
        print(f"Reason: {str(e)}")
        raise
