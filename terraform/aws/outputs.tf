output "deployment_summary" {
  description = "A clean, formatted summary of the deployment."
  value       = <<-EOT

  ========================================================================
  🚀 T-AIRS LAB DEPLOYMENT SUCCESSFUL (AWS)
  ========================================================================

  📊 Dashboard URL   : http://${aws_instance.t_airs_node.public_ip}:8000
  
  💻 SSH Command     : ssh -i ${local_sensitive_file.private_key.filename} ubuntu@${aws_instance.t_airs_node.public_ip}
  
  🛡️ Security Notice : CSP firewalls are RESTRICTED to your auto-detected subnet
                       (${local.my_auto_subnet}) and Prisma AIRS nodes (${join(", ", var.prisma_airs_ips)}).
  
  ⏳ Readiness Note  : Please note it takes approximately 10 minutes for the startup 
                       scripts to finish installing the application. The dashboard 
                       will be available once the process completes.

  EOT
}