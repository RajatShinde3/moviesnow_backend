resource "aws_elasticache_subnet_group" "main" {
  name       = "${var.project}-redis-subnets"
  subnet_ids = [] # supply in real deployment
}

resource "aws_elasticache_replication_group" "redis" {
  replication_group_id          = "${var.project}-redis"
  description                   = "Redis for MoviesNow"
  engine                        = "redis"
  engine_version                = "7.0"
  node_type                     = var.redis_node_type
  number_cache_clusters         = 1
  automatic_failover_enabled    = false
  multi_az_enabled              = false
  at_rest_encryption_enabled    = true
  transit_encryption_enabled    = true
  apply_immediately             = true
  maintenance_window            = "sun:07:00-sun:08:00"
  subnet_group_name             = aws_elasticache_subnet_group.main.name
  security_group_ids            = [] # supply in real deployment
  tags                          = local.tags
}
