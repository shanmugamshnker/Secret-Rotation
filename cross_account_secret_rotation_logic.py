import json
import boto3
import pymysql
import logging

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    logger.info("Lambda function has started")
    conn = None

    # Extract details from the event JSON
    try:
        action = event['action']
        db_secret_name = event['db_secret_name']  # Secret name for DB connection details in Account A
        region_name = event['region_name']
        role_arn = event['role_arn']  # Role ARN to assume in Account B
        user_secret_name = event['user_secret_name']  # Secret name in Account B
        database_name = event.get('database_name', 'mysql')  # Default to 'mysql' if not provided
        grant_type = event.get('grant_type', '')  # Grant type for permissions (e.g., 'ro_db_access')
    except KeyError as e:
        logger.error(f"Missing event parameter: {str(e)}")
        return {'statusCode': 400, 'body': json.dumps('Missing event parameter')}

    # Retrieve DB connection details from Secrets Manager in Account A
    try:
        secretsmanager_client_a = boto3.client('secretsmanager', region_name=region_name)
        db_secret = json.loads(secretsmanager_client_a.get_secret_value(SecretId=db_secret_name)['SecretString'])
        db_host = db_secret['host']
        db_admin_username = db_secret['username']
        db_admin_password = db_secret['password']
        logger.info("Successfully retrieved DB connection details from database account ")
    except Exception as e:
        logger.error(f"Error retrieving DB secret from database account: {str(e)}")
        return {'statusCode': 500, 'body': json.dumps('Error retrieving DB secret from database account')}

    # Retrieve user secret from Secrets Manager in Account B
    try:
        sts_client = boto3.client('sts', endpoint_url=f'https://sts.ap-southeast-1.amazonaws.com')
        assumed_role_object = sts_client.assume_role(RoleArn=role_arn, RoleSessionName="AssumeRoleSession1")
        credentials = assumed_role_object['Credentials']

        secretsmanager_client_b = boto3.client('secretsmanager', region_name=region_name,
                                               aws_access_key_id=credentials['AccessKeyId'],
                                               aws_secret_access_key=credentials['SecretAccessKey'],
                                               aws_session_token=credentials['SessionToken'])

        user_secret = json.loads(secretsmanager_client_b.get_secret_value(SecretId=user_secret_name)['SecretString'])
        user_username = user_secret['username']
        user_password = user_secret['password']
        logger.info("Successfully retrieved user secret from D&I")
    except Exception as e:
        logger.error(f"Error retrieving user secret from Account B: {str(e)}")
        return {'statusCode': 500, 'body': json.dumps('Error retrieving user secret from D&I')}

    # Connect to the RDS Database and perform action
    try:
        conn = pymysql.connect(host=db_host, user=db_admin_username, passwd=db_admin_password, port=3306, connect_timeout=5, ssl_verify_identity=True)
        with conn.cursor() as cur:
            if action == 'password_reset':
                # Check if MySQL user exists in the mysql.user table and reset the password
                cur.execute("SELECT EXISTS(SELECT 1 FROM mysql.user WHERE User = %s)", (user_username,))
                if cur.fetchone()[0]:
                    cur.execute("ALTER USER %s IDENTIFIED BY %s", (user_username, user_password))
                    conn.commit()
                    logger.info(f"Password reset successfully for MySQL user {user_username}")
                else:
                    logger.info(f"MySQL user {user_username} does not exist in mysql.user table")

            elif action == 'create_user':
                cur.execute("SELECT EXISTS(SELECT 1 FROM mysql.user WHERE User = %s)", (user_username,))
                if cur.fetchone()[0]:
                    logger.info(f"User {user_username} already exists in the database.")
                else:
                    # Create a new MySQL user and set the password
                    cur.execute("CREATE USER %s IDENTIFIED BY %s", (user_username, user_password))
                    # Grant read-only access if specified
                    if grant_type == 'ro_db_access':
                        grant_query = "GRANT SELECT ON `{}`.* TO %s".format(database_name)
                        cur.execute(grant_query, (user_username,))
                    conn.commit()
                    logger.info(f"User {user_username} created successfully with the provided password")
                    if grant_type == 'ro_db_access':
                        logger.info(f"User {user_username} granted 'readonly' access for database '{database_name}'")
                    # Trigger secret rotation in D&I
                    try:
                        secretsmanager_client_b.rotate_secret(SecretId=user_secret_name)
                        logger.info(f"Secret rotation triggered for secret: {user_secret_name}")
                    except Exception as e:
                        logger.error(f"Error triggering secret rotation in Account B: {str(e)}")


    except pymysql.MySQLError as e:
        logger.error(f"Error in MySQL operation: {str(e)}")
        return {'statusCode': 500, 'body': json.dumps('Error in MySQL operation')}
    finally:
        if conn:
            conn.close()

    logger.info("Lambda function has completed")
    return {'statusCode': 200, 'body': json.dumps('Function executed successfully!')}

# For local testing (if needed)
if __name__ == "__main__":
    lambda_handler(event={}, context=None)
