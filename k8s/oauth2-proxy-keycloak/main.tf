locals {
  cluster_name           = var.kubernetes_cluster_name
  provider_display_name  = var.provider_display_name
  app_name               = var.app_name
  public_host            = var.public_host
  namespace              = var.namespace
  image_pullPolicy       = var.image_pullPolicy
  cookie_increment       = var.cookie_increment
  oidc_realm             = var.oidc_realm
  keycloak_client_id     = var.keycloak_client_id
  keycloak_client_secret = var.keycloak_client_secret
  keycloak_url           = var.keycloak_url
  oidc_issuer_url        = "${var.keycloak_url}/realms/${var.oidc_realm}"
  helm_force_update      = var.helm_force_update
  helm_cleanup_on_fail   = var.helm_cleanup_on_fail
  helm_reuse_values      = var.helm_reuse_values
  app_secrets            = var.app_secrets
  upstreams              = jsonencode(var.upstreams)
  tls_secret_name        = var.tls_secret_name
  development_versions   = var.development_versions
  valid_web_origins      = var.valid_web_origins
  valid_redirect_uris    = var.valid_redirect_uris
  oauth2_proxy_pass_access_token = var.oauth2_proxy_pass_access_token
  oauth2_proxy_set_xauthrequest = var.oauth2_proxy_set_xauthrequest
  oauth2_proxy_pass_authorization_header = var.oauth2_proxy_pass_authorization_header
  oauth2_proxy_set_authorization_header = var.oauth2_proxy_set_authorization_header
  oauth2_proxy_skip_jwt_bearer_tokens = var.oauth2_proxy_skip_jwt_bearer_tokens
  oauth2_proxy_extra_args = jsonencode(var.oauth2_proxy_extra_args)
}

data "aws_eks_cluster" "cluster" {
  name = local.cluster_name
}

data "aws_eks_cluster_auth" "cluster" {
  name = local.cluster_name
}

provider "keycloak" {
  client_id     = local.keycloak_client_id
  client_secret = local.keycloak_client_secret
  url           = local.keycloak_url
}


provider "kubernetes" {
  host                   = data.aws_eks_cluster.cluster.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.cluster.certificate_authority.0.data)
  token                  = data.aws_eks_cluster_auth.cluster.token
}

provider "helm" {
  debug = true
  kubernetes {
    host                   = data.aws_eks_cluster.cluster.endpoint
    cluster_ca_certificate = base64decode(data.aws_eks_cluster.cluster.certificate_authority.0.data)
    token                  = data.aws_eks_cluster_auth.cluster.token
  }
}

resource "random_password" "password" {
  length  = 32
  special = false
}

resource "random_id" "cookie_secret" {
  keepers = {
    # Generate a new id each time we increment
    cookie_increment = local.cookie_increment
  }
  byte_length = 32
}

resource "kubernetes_secret" "app_secrets" {
  metadata {
    name      = "${local.app_name}-secrets"
    namespace = local.namespace
  }
  type = "Opaque"
  data = local.app_secrets
}

data "keycloak_realm" "realm" {
  realm = local.oidc_realm
}

resource "keycloak_openid_client" "openid_client" {
  realm_id    = data.keycloak_realm.realm.id
  client_id   = local.app_name
  description = "Client for ${local.app_name}"
  name        = local.app_name
  enabled     = true

  client_secret = random_password.password.result

  standard_flow_enabled        = true
  implicit_flow_enabled        = true
  direct_access_grants_enabled = false
  service_accounts_enabled     = true

  access_type = "CONFIDENTIAL"
  valid_redirect_uris = concat(
    local.valid_redirect_uris,
    [
      "https://${local.public_host}/*",
    ],
  )
  
  web_origins = concat(
    local.valid_web_origins,
    [
      "https://${local.public_host}",
    ],
  )

  //login_theme = "keycloak"
}

resource "helm_release" "chart" {
  name              = local.app_name
  chart             = "${path.module}/chart"
  verify            = false
  namespace         = local.namespace
  atomic            = true
  wait              = true
  timeout           = 6000
  dependency_update = true
  lint              = true
  force_update      = local.helm_force_update
  cleanup_on_fail   = local.helm_cleanup_on_fail
  reuse_values      = local.helm_reuse_values
  devel             = local.development_versions
  version           = "0.1.17"
  disable_webhooks  = true

  values = [
    fileexists("${path.module}/values.yml") ? file("${path.module}/values.yml") : <<EOF
oauth2-proxy:
  # Oauth client configuration specifics
  config:
    # Add config annotations
    annotations: {}
    clientID: ${keycloak_openid_client.openid_client.client_id}
    cookieSecret: ${random_id.cookie_secret.id}
    # The name of the cookie that oauth2-proxy will create
    # If left empty, it will default to the release name
    cookieName: "${local.app_name}"
    configFile: |-
      email_domains = [ "*" ]
      upstreams =  ${local.upstreams}
      oidc_issuer_url="${local.oidc_issuer_url}"
      redirect_url="https://${local.public_host}/oauth2/callback"
      provider="oidc"
      provider_display_name="${local.provider_display_name}"
      request_logging = true
      #request_logging_format = "{{.Client}} - {{.Username}} [{{.Timestamp}}] {{.Host}} {{.RequestMethod}} {{.Upstream}} {{.RequestURI}} {{.Protocol}} {{.UserAgent}} {{.StatusCode}} {{.ResponseSize}} {{.RequestDuration}}"
      auth_logging = true
      #auth_logging_format = "{{.Client}} - {{.Username}} [{{.Timestamp}}] [{{.Status}}] {{.Message}}"
      standard_logging = true
      pass_access_token = ${local.oauth2_proxy_pass_access_token}
      set_xauthrequest = ${local.oauth2_proxy_set_xauthrequest}
      pass_authorization_header = ${local.oauth2_proxy_pass_authorization_header}
      set_authorization_header = ${local.oauth2_proxy_set_authorization_header}
      skip_jwt_bearer_tokens = ${local.oauth2_proxy_skip_jwt_bearer_tokens}
      ssl_upstream_insecure_skip_verify=true
      skip_provider_button=true
      cookie_secure=false
      cookie_httponly=false
      cookie_refresh="1h"
      cookie_domains=[ "${local.public_host}" ]
      cookie_path="/"
      whitelist_domains=[ "${local.public_host}" ]
  ingress:
      enabled: false
  extraArgs: ${local.oauth2_proxy_extra_args}
ingress:
  enabled: true
  annotations:
      cert-manager.io/cluster-issuer: letsencrypt-prod
      kubernetes.io/ingress.class: nginx
      kubernetes.io/tls-acme: "true"
  hosts:
  - host: ${local.public_host}
  tls:
  - hosts:
    - ${local.public_host}
    secretName: ${local.tls_secret_name}
    EOF
    , fileexists("${path.module}/extra-values.yml") ? file("${path.module}/extra-values.yml") : ""
  ]

  set {
    name  = "oauth2-proxy.config.clientSecret"
    value = keycloak_openid_client.openid_client.client_secret
  }
}
