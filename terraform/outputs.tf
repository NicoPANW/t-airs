output "dashboard_url" {
  description = "Access your T-AIRS Dashboard here:"
  value       = var.target_cloud == "gcp" ? "http://${try(google_compute_instance.t_airs_node[0].network_interface[0].access_config[0].nat_ip, "")}:8000" : "http://${try(aws_instance.t_airs_node[0].public_ip, "")}:8000"
}

output "ssh_command" {
  description = "Command to SSH into the instance:"
  value       = var.target_cloud == "gcp" ? "gcloud compute ssh ${try(google_compute_instance.t_airs_node[0].name, "")} --zone=${try(google_compute_instance.t_airs_node[0].zone, "")}" : "ssh ubuntu@${try(aws_instance.t_airs_node[0].public_ip, "")}"
}

output "security_notice" {
  value = "CSP firewalls are RESTRICTED to your auto-detected subnet (${local.my_auto_subnet}) and Prisma AIRS nodes (${join(", ", var.prisma_airs_ips)})."
}