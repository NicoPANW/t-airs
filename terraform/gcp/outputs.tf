# t-airs/terraform/gcp/outputs.tf
output "mcp_auth_token" {
  description = "Bearer token required in the Authorization header when registering the MCP VM in Prisma AIRS AI Gateway"
  value       = local.effective_mcp_token
  sensitive   = true
}

output "deployment_summary" {
  description = "A clean, formatted summary of the multi-VM GCP deployment."
  value       = <<-EOT

  ========================================================================
  🚀 T-AIRS MULTI-VM LAB DEPLOYMENT SUCCESSFUL (GCP - SAME VPC)
  ========================================================================

  📦 App Version          : v${fileexists("${path.module}/../../VERSION") ? chomp(file("${path.module}/../../VERSION")) : (fileexists("${path.module}/../../version") ? chomp(file("${path.module}/../../version")) : "unknown")}
  🌐 Environment          : ${local.env}

  🖥️  App Dashboard URL    : http://${google_compute_instance.t_airs_node.network_interface[0].access_config[0].nat_ip}:8000
  💻 App VM SSH           : gcloud compute ssh ${google_compute_instance.t_airs_node.name} --zone=${google_compute_instance.t_airs_node.zone}

  🗄️  MCP Public Endpoint  : http://${google_compute_instance.t_airs_mcp.network_interface[0].access_config[0].nat_ip}:${var.mcp_port}/mcp
  🔒 MCP VPC Internal IP  : http://${google_compute_instance.t_airs_mcp.network_interface[0].network_ip}:${var.mcp_port}/mcp
  💻 MCP VM SSH           : gcloud compute ssh ${google_compute_instance.t_airs_mcp.name} --zone=${google_compute_instance.t_airs_mcp.zone}

  ------------------------------------------------------------------------
  🔗 PRISMA AIRS AI GATEWAY - MCP REGISTRY SETUP (ONE-TIME)
  ------------------------------------------------------------------------
  1. In Prisma AIRS AI Gateway, go to: MCP Registry -> Add Server
  2. Enter:
     - Name        : T-AIRS SQLite
     - Slug        : ${var.portkey_mcp_slug}
     - Server Type : HTTP (Streamable HTTP)
     - Server URL  : http://${google_compute_instance.t_airs_mcp.network_interface[0].access_config[0].nat_ip}:${var.mcp_port}/mcp
     - Auth Type   : Headers
       Header Key  : Authorization
       Header Value: Bearer <your TF_VAR_mcp_auth_token or run: terraform output -raw mcp_auth_token>
  3. Enable workspace access & verify tools (read_query, write_query) appear.
  4. Agent traffic path:
     App VM -> https://mcp-aigw.portkey.ai/${var.portkey_mcp_slug}/mcp -> MCP VM

  🛡️ Security Notice      : App VM firewall is restricted to ${local.my_auto_subnet}
                            and Prisma AIRS nodes. MCP VM port ${var.mcp_port} is restricted
                            to Prisma AIRS nodes, VPC CIDR (${var.gcp_subnet_cidr}),
                            and ${local.my_auto_subnet}, plus Bearer token auth.

  ⏳ Readiness Note       : Allow ~5 minutes for startup scripts to complete.
  EOT
}