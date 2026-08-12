# ============================================================================
# INTENTIONAL IaC MISCONFIGURATIONS — test fixtures for Upwind IaC scanning.
# Distinct from bla.tf / bla2.tf (which cover public-read S3, open SG 22/3306,
# wildcard IAM, public RDS + hardcoded creds, user_data secrets). This file
# focuses on encryption-at-rest, logging, backups, key rotation, TLS, and
# scanning misconfigs. All values are dummy — no real secrets. Not for apply.
# ============================================================================

# ---------------------------------------------------------------------------
# IaC: Unencrypted EBS volume
# ---------------------------------------------------------------------------
resource "aws_ebs_volume" "unencrypted_ebs" {
  availability_zone = "us-east-1a"
  size              = 20
  encrypted         = false # should be true
}

# ---------------------------------------------------------------------------
# IaC: RDS without encryption at rest, no backups, no deletion protection
# ---------------------------------------------------------------------------
resource "aws_db_instance" "unencrypted_db" {
  identifier                  = "insecure-db-2"
  engine                      = "postgres"
  instance_class              = "db.t3.micro"
  allocated_storage           = 20
  username                    = "app"
  password                    = "ChangeMe123!" # dummy
  storage_encrypted           = false # should be true
  backup_retention_period     = 0     # backups disabled
  deletion_protection         = false # should be true
  auto_minor_version_upgrade  = false # should be true
  iam_database_authentication_enabled = false
  skip_final_snapshot         = true
}

# ---------------------------------------------------------------------------
# IaC: CloudTrail without log-file validation, single-region, unencrypted
# ---------------------------------------------------------------------------
resource "aws_cloudtrail" "no_validation" {
  name                          = "insecure-trail"
  s3_bucket_name                = "insecure-trail-bucket"
  enable_log_file_validation    = false # should be true
  is_multi_region_trail         = false # should be true
  include_global_service_events = false
  # kms_key_id intentionally omitted -> logs not encrypted with CMK
}

# ---------------------------------------------------------------------------
# IaC: Weak IAM account password policy
# ---------------------------------------------------------------------------
resource "aws_iam_account_password_policy" "weak" {
  minimum_password_length        = 6     # too short
  require_symbols                = false
  require_numbers                = false
  require_uppercase_characters   = false
  require_lowercase_characters   = false
  allow_users_to_change_password = true
  max_password_age               = 0     # never expires
  password_reuse_prevention      = 0
}

# ---------------------------------------------------------------------------
# IaC: KMS key with rotation disabled
# ---------------------------------------------------------------------------
resource "aws_kms_key" "no_rotation" {
  description         = "insecure key"
  enable_key_rotation = false # should be true
}

# ---------------------------------------------------------------------------
# IaC: SNS topic without server-side encryption
# ---------------------------------------------------------------------------
resource "aws_sns_topic" "unencrypted_sns" {
  name = "insecure-topic"
  # kms_master_key_id intentionally omitted
}

# ---------------------------------------------------------------------------
# IaC: SQS queue without encryption
# ---------------------------------------------------------------------------
resource "aws_sqs_queue" "unencrypted_sqs" {
  name = "insecure-queue"
  # kms_master_key_id / sqs_managed_sse_enabled intentionally omitted
}

# ---------------------------------------------------------------------------
# IaC: DynamoDB without encryption and point-in-time recovery
# ---------------------------------------------------------------------------
resource "aws_dynamodb_table" "no_pitr" {
  name         = "insecure-table"
  hash_key     = "id"
  billing_mode = "PAY_PER_REQUEST"

  attribute {
    name = "id"
    type = "S"
  }

  point_in_time_recovery {
    enabled = false # should be true
  }

  server_side_encryption {
    enabled = false # should be true
  }
}

# ---------------------------------------------------------------------------
# IaC: ECR repo with mutable tags and scan-on-push disabled
# ---------------------------------------------------------------------------
resource "aws_ecr_repository" "mutable_noscan" {
  name                 = "insecure-repo"
  image_tag_mutability = "MUTABLE" # should be IMMUTABLE

  image_scanning_configuration {
    scan_on_push = false # should be true
  }
}

# ---------------------------------------------------------------------------
# IaC: CloudWatch log group without retention or CMK encryption
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "no_retention" {
  name = "/insecure/log-group"
  # retention_in_days omitted -> never expires
  # kms_key_id omitted -> not encrypted with CMK
}

# ---------------------------------------------------------------------------
# IaC: EFS file system not encrypted
# ---------------------------------------------------------------------------
resource "aws_efs_file_system" "unencrypted_efs" {
  creation_token = "insecure-efs"
  encrypted      = false # should be true
}

# ---------------------------------------------------------------------------
# IaC: ALB with access logs disabled + plaintext HTTP listener
# ---------------------------------------------------------------------------
resource "aws_lb" "no_logs" {
  name               = "insecure-alb"
  internal           = false
  load_balancer_type = "application"
  subnets            = ["subnet-12345678", "subnet-87654321"]

  drop_invalid_header_fields = false # should be true

  access_logs {
    bucket  = "insecure-alb-logs"
    enabled = false # access logging disabled
  }
}

resource "aws_lb_listener" "plaintext_http" {
  load_balancer_arn = aws_lb.no_logs.arn
  port              = 80
  protocol          = "HTTP" # should be HTTPS with a modern TLS policy

  default_action {
    type = "fixed-response"

    fixed_response {
      content_type = "text/plain"
      message_body = "ok"
      status_code  = "200"
    }
  }
}

# ---------------------------------------------------------------------------
# IaC: Lambda with plaintext secret in env, no tracing, outdated runtime
# ---------------------------------------------------------------------------
resource "aws_lambda_function" "insecure_lambda" {
  function_name = "insecure-fn"
  role          = "arn:aws:iam::123456789012:role/dummy"
  handler       = "index.handler"
  runtime       = "python3.7" # EOL runtime
  filename      = "function.zip"

  tracing_config {
    mode = "PassThrough" # X-Ray tracing effectively off (should be Active)
  }

  environment {
    variables = {
      DB_PASSWORD = "dummy-plaintext-password" # secret in plaintext env var
    }
  }
  # kms_key_arn omitted -> env vars not encrypted with a CMK
}