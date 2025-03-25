# Create CodePipeline
resource "aws_codepipeline" "pipeline" {
  name     = "${var.app_name}-pipeline-1"
  role_arn = aws_iam_role.codepipeline_role.arn

  artifact_store {
    location = aws_s3_bucket.artifact_bucket.bucket
    type     = "S3"
  }

  stage {
    name = "Source"

    action {
      name             = "Source"
      category         = "Source"
      owner            = "ThirdParty"
      provider         = "GitHub"
      version          = "1"
      output_artifacts = ["source_output"]

      configuration = {
        Owner                = split("/", var.github_repo)[0]
        Repo                 = split("/", var.github_repo)[1]
        Branch               = var.github_branch
        OAuthToken           = var.github_token
        PollForSourceChanges = "false"
      }
    }
  }

  stage {
    name = "Build"

    action {
      name             = "BuildAndPush"
      category         = "Build"
      owner            = "AWS"
      provider         = "CodeBuild"
      version          = "1"
      input_artifacts  = ["source_output"]
      output_artifacts = ["build_output"]

      configuration = {
        ProjectName = aws_codebuild_project.app_build.name
      }
    }
  }

  stage {
    name = "Deploy"

    action {
      name            = "Deploy"
      category        = "Deploy"
      owner           = "AWS"
      provider        = "ECS"
      version         = "1"
      input_artifacts = ["build_output"]

      configuration = {
        ClusterName = aws_ecs_cluster.app_cluster.name
        ServiceName = aws_ecs_service.app_service.name
        FileName    = "imageDefinition.json"
      }
    }
  }
}

# Create webhook for the pipeline
resource "aws_codepipeline_webhook" "github_webhook" {
  name            = "${var.app_name}-webhook-1"
  authentication  = "GITHUB_HMAC"
  target_action   = "Source"
  target_pipeline = aws_codepipeline.pipeline.name

  authentication_configuration {
    secret_token = var.github_token
  }

  filter {
    json_path    = "$.ref"
    match_equals = "refs/heads/${var.github_branch}"
  }
}

# Register the webhook with GitHub
resource "null_resource" "register_webhook" {
  provisioner "local-exec" {
    command = <<EOF
      curl -X POST \
        -H "Authorization: token ${var.github_token}" \
        -H "Accept: application/vnd.github.v3+json" \
        https://api.github.com/repos/${var.github_repo}/hooks \
        -d '{
          "name": "web",
          "active": true,
          "events": ["push"],
          "config": {
            "url": "${aws_codepipeline_webhook.github_webhook.url}",
            "content_type": "json",
            "insecure_ssl": "0",
            "secret": "${var.github_token}"
          }
        }'
    EOF
  }

  depends_on = [aws_codepipeline_webhook.github_webhook]
}
