# t-airs/terraform/aws/outputs.tf
output "mcp_auth_token" {
  description = "Bearer token required in the Authorization header when registering the MCP VM in Prisma AIRS AI Gateway"
  value       = local.effective_mcp_token
  sensitive   = true
}

output "deployment_summary" {
  description = "A clean, formatted summary of the multi-VM AWS deployment."
  depends_on = [
    aws_eip_association.app_eip_assoc,
    aws_eip_association.mcp_eip_assoc
  ]
  value = <<-EOT

  ========================================================================
  🚀 T-AIRS MULTI-VM LAB DEPLOYMENT SUCCESSFUL (AWS - SAME VPC)
  ========================================================================

  📦 App Version          : v${fileexists("${path.module}/../../VERSION") ? chomp(file("${path.module}/../../VERSION")) : (fileexists("${path.module}/../../version") ? chomp(file("${path.module}/../../version")) : "unknown")}
  🌐 Environment          : ${local.env}

  🖥️  App Dashboard URL    : http://${local.app_public_ip}:8000
  💻 App VM SSH           : ssh -i ${local_sensitive_file.private_key.filename} ubuntu@${local.app_public_ip}

  🗄️  MCP Public Endpoint  : http://${local.mcp_public_ip}:${var.mcp_port}/mcp
  🔒 MCP VPC Private IP   : http://${aws_instance.t_airs_mcp.private_ip}:${var.mcp_port}/mcp
  💻 MCP VM SSH           : ssh -i ${local_sensitive_file.private_key.filename} ubuntu@${local.mcp_public_ip}

  ------------------------------------------------------------------------
  🔗 PRISMA AIRS AI GATEWAY - MCP REGISTRY SETUP (ONE-TIME)
  ------------------------------------------------------------------------
  1. In Prisma AIRS AI Gateway, go to: MCP Registry -> Add Server
  2. Enter:
     - Name        : T-AIRS SQLite
     - Slug        : ${var.portkey_mcp_slug}
     - Server Type : HTTP (Streamable HTTP)
     - Server URL  : http://${local.mcp_public_ip}:${var.mcp_port}/mcp
     - Auth Type   : Headers
       Header Key  : Authorization
       Header Value: Bearer <your TF_VAR_mcp_auth_token or run: terraform output -raw mcp_auth_token>
  3. Enable workspace access & verify tools (read_query, write_query) appear.
  4. Agent traffic path:
     App VM -> https://mcp-aigw.portkey.ai/${var.portkey_mcp_slug}/mcp -> MCP VM

  🛡️ Security Notice      : App VM firewall is restricted to ${local.my_auto_subnet}
                            and Prisma AIRS nodes. MCP VM SSH is restricted to
                            ${local.my_auto_subnet}, and port ${var.mcp_port} is protected
                            by Bearer token auth.

  ⏳ Readiness Note       : Allow ~5 minutes for startup scripts to complete.
  EOT
}