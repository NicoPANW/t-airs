output "deployment_summary" {
  description = "A clean, formatted summary of the deployment."
  value       = <<-EOT

  ========================================================================
  🚀 T-AIRS LAB DEPLOYMENT SUCCESSFUL (GCP)
  ========================================================================

  📊 Dashboard URL   : http://${google_compute_instance.t_airs_node.network_interface[0].access_config[0].nat_ip}:8000
  
  💻 SSH Command     : gcloud compute ssh ${google_compute_instance.t_airs_node.name} --zone=${google_compute_instance.t_airs_node.zone}
  
  🛡️ Security Notice : CSP firewalls are RESTRICTED to your auto-detected subnet
                       (${local.my_auto_subnet}) and Prisma AIRS nodes (${join(", ", var.prisma_airs_ips)}).
  
  ⏳ Readiness Note  : Please note it takes approximately 10 minutes for the startup 
                       scripts to finish installing the application. The dashboard 
                       will be available once the process completes.

  EOT
}