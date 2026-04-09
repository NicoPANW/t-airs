output "deployment_summary" {
  description = "A clean, formatted summary of the deployment."
  value       = 

  ========================================================================
  🚀 T-AIRS LAB DEPLOYMENT SUCCESSFUL
  ========================================================================

  📊 Dashboard URL   : ${var.target_cloud == "gcp" ? "http://${try(google_compute_instance.t_airs_node[0].network_interface[0].access_config[0].nat_ip, "")}:8000" : "http://${try(aws_instance.t_airs_node[0].public_ip, "")}:8000"}
  
  💻 SSH Command     : ${var.target_cloud == "gcp" ? "gcloud compute ssh ${try(google_compute_instance.t_airs_node[0].name, "")} --zone=${try(google_compute_instance.t_airs_node[0].zone, "")}" : "ssh ubuntu@${try(aws_instance.t_airs_node[0].public_ip, "")}"}
  
  🛡️ Security Notice : CSP firewalls are RESTRICTED to your auto-detected subnet
                       (${local.my_auto_subnet}) and Prisma AIRS nodes (${join(", ", var.prisma_airs_ips)}).
  
  ⏳ Readiness Note  : Please note it takes approximately 10 minutes for the startup 
                       scripts to finish installing the application. The dashboard 
                       will be available once the process completes.

}
