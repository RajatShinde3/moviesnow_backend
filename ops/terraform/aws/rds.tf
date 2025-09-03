resource "aws_db_subnet_group" "main" {
  name       = "${var.project}-db-subnets"
  subnet_ids = [] # supply in real deployment
}

resource "aws_db_instance" "postgres" {
  allocated_storage    = 20
  engine               = "postgres"
  engine_version       = "15"
  instance_class       = var.db_instance_class
  db_name              = "moviesnow"
  username             = "moviesnow"
  password             = "change-me"
  skip_final_snapshot  = true
  publicly_accessible  = false
  storage_encrypted    = true
  backup_retention_period = 7
  deletion_protection  = false
  apply_immediately    = true

  # networking to be wired by integrator
  # db_subnet_group_name = aws_db_subnet_group.main.name

  tags = local.tags
}
