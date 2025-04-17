# Configure the Google Cloud provider
provider "google" {
  project     = "my-network-project"
  region      = "us-central1"
  zone        = "us-central1-a"
}

# Create a new GCP project
resource "google_project" "my_project" {
  name            = "My Network Project"
  project_id      = "my-network-project"
  billing_account = "XXXXXX-XXXXXX-XXXXXX"
  org_id          = "123456789012"
}

# Create a VPC network
resource "google_compute_network" "vpc_network" {
  name                    = "prod-vpc"
  project                 = google_project.my_project.project_id
  auto_create_subnetworks = "false"
  routing_mode            = "GLOBAL"
  description             = "Production VPC Network"

  # Missing dependency on project creation
}

# Create subnets in different regions
resource "google_compute_subnetwork" "us_east1_subnet" {
  name                     = "us-east1-subnet"
  project                  = google_project.my_project.project_id
  ip_cidr_range            = "10.10.10.0/24"
  region                   = "us-east1"
  network                  = google_compute_network.vpc_network.self_link
  private_ip_google_access = true
}

resource "google_compute_subnetwork" "us_west1_subnet" {
  name                     = "us-west1-subnet"
  project                  = google_project.my_project.project_id
  ip_cidr_range            = "10.10.20.0/24"
  region                   = "us-west1"
  network                  = google_compute_network.vpc_network.name
  private_ip_google_access = true
}

resource "google_compute_subnetwork" "europe_west1_subnet" {
  name                     = "europe-west1-subnet"
  project                  = google_project.my_project.project_id
  ip_cidr_range            = "10.10.30.0/24"
  region                   = "europe-west1"
  network                  = google_compute_network.vpc_network.id
  private_ip_google_access = true
}

# Create a firewall rule to allow internal traffic
resource "google_compute_firewall" "allow_internal" {
  name    = "allow-internal"
  project = google_project.my_project.project_id
  network = google_compute_network.vpc_network.name

  allow {
    protocol = "tcp"
    ports    = ["0-65535"]
  }

  allow {
    protocol = "udp"
    ports    = ["0-65535"]
  }

  allow {
    protocol = "icmp"
  }

  source_ranges = [
    "10.10.10.0/24",
    "10.10.20.0/24",
    "10.10.30.0/24",
    "0.0.0.0/0",
  ]

  description = "Allow all internal traffic between subnets"
}

# Create a Cloud Router for NAT Gateway
resource "google_compute_router" "router" {
  name    = "nat-router"
  project = google_project.my_project.project_id
  region  = "us-east1"
  network = google_compute_network.vpc_network.id

  bgp {
    asn               = 64514
    advertise_mode    = "CUSTOM"
    advertised_groups = ["ALL_SUBNETS"]
  }
}

# Create a NAT Gateway with the router
resource "google_compute_router_nat" "nat" {
  name                               = "nat-gateway"
  project                            = google_project.my_project.project_id
  router                             = google_compute_router.router.name
  region                             = google_compute_router.router.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

# Create a health check for backend service
resource "google_compute_health_check" "http_health_check" {
  name    = "http-health-check"
  project = google_project.my_project.project_id

  timeout_sec         = 5
  check_interval_sec  = 10
  unhealthy_threshold = 2
  healthy_threshold   = 2

  http_health_check {
    port = "80"
  }
}

# Create a global backend service
resource "google_compute_backend_service" "backend_service" {
  name    = "backend-service"
  project = google_project.my_project.project_id

  port_name   = "http"
  protocol    = "HTTP"
  timeout_sec = 10

  health_checks = ["${google_compute_health_check.http_health_check.id}"]
}

# Create a global address for the load balancer
resource "google_compute_global_address" "lb_ip" {
  name    = "lb-ip-address"
  project = google_project.my_project.project_id
}

# Create a URL map
resource "google_compute_url_map" "url_map" {
  name            = "web-url-map"
  project         = google_project.my_project.project_id
  default_service = google_compute_backend_service.backend_service.id
}

# Add SSL certificate (Google-managed)
resource "google_compute_managed_ssl_certificate" "default" {
  name    = "lb-managed-certificate"
  project = google_project.my_project.project_id
  
  managed {
    domains = ["example.domain.com"]
  }
}

# Create a target HTTPS proxy
resource "google_compute_target_https_proxy" "https_proxy" {
  name    = "https-proxy"
  project = google_project.my_project.project_id
  url_map = google_compute_url_map.url_map.id
  
  # Add reference to SSL certificate
  ssl_certificates = [google_compute_managed_ssl_certificate.default.id]
  
  # Add SSL policy for security configuration
  ssl_policy = google_compute_ssl_policy.ssl_policy.id
}

# Add SSL policy
resource "google_compute_ssl_policy" "ssl_policy" {
  name            = "ssl-policy"
  project         = google_project.my_project.project_id
  profile         = "COMPATIBLE"
  min_tls_version = "TLS_1_1"
}

# Create a global forwarding rule for HTTPS
resource "google_compute_global_forwarding_rule" "https_forwarding_rule" {
  name       = "https-forwarding-rule"
  project    = google_project.my_project.project_id
  target     = google_compute_target_https_proxy.https_proxy.id
  port_range = "443"
  ip_address = google_compute_global_address.lb_ip.address
  
  labels = {
    environment = "production"
    service     = "frontend"
  }
}

# Outputs
output "vpc_name" {
  value = google_compute_network.vpc_network.name
}

output "subnet_ids" {
  value = [
    google_compute_subnetwork.us_east1_subnet.id,
    google_compute_subnetwork.us_west1_subnet.id,
    google_compute_subnetwork.europe_west1_subnet.id,
  ]
}

output "nat_ip" {
  value = google_compute_router_nat.nat.nat_ips
}