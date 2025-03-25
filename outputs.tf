output "ecr_repository_url" {
  value = aws_ecr_repository.app_repo.repository_url
}

output "codebuild_project_name" {
  value = aws_codebuild_project.app_build.name
}

output "ecs_cluster_name" {
  value = aws_ecs_cluster.app_cluster.name
}

output "ecs_service_name" {
  value = aws_ecs_service.app_service.name
}

output "codepipeline_name" {
  value = aws_codepipeline.pipeline.name
}

output "webhook_url" {
  value     = aws_codepipeline_webhook.github_webhook.url
  sensitive = true
}
