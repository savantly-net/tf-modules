variable "kubernetes_cluster_name" {
  type = string
}

variable "environment" {
  type = string
}

variable "app_name" {
  type = string
  default = "portal"
}

variable "app_secrets" {
  type = map(string)
  default = {}
}

variable "namespace" {
  type = string
}

variable "provider_display_name" {
  type = string
}

variable "keycloak_client_id" {
  type = string
  default = "terraform"
}

variable "keycloak_client_secret" {
  type = string
}

variable "keycloak_url" {
  type = string
}

variable "public_host" {
  type = string
  default = ""
}

variable "image_pullPolicy" {
  type = string
  default = "IfNotPresent"
}

variable "cookie_increment" {
  type = number
  default = 1
  description = "Increment to invalidate the cookie secret"
}

variable "oidc_realm" {
  type = string
}

variable "tls_secret_name" {
  type = string
}

variable "upstreams" {
  type = list(object({
    id  = string
    path = string
    rewriteTarget = optional(string)
    uri = string
    insecureSkipTLSVerify = optional(bool, false)
    static = optional(bool)
    staticCode = optional(number)
    flushInterval = optional(string)
    passHostHeader = optional(bool, true)
    proxyWebSockets = optional(bool, true)
    timeout = optional(string)
  }))
}

variable "helm_cleanup_on_fail" {
  type = bool
  default = true
}

variable "helm_force_update" {
  type = bool
  default = false
}

variable "helm_reuse_values" {
  type = bool
  default = false
}

variable "development_versions" {
  type = bool
  default = true
}

variable "valid_web_origins" {
  type = list(string)
  default = []
}

variable "valid_redirect_uris" {
  type = list(string)
  default = []
}

variable "oauth2_proxy_provider" {
  type = string
  default = "oidc"
}

variable "oauth2_proxy_pass_access_token" {
  type = bool
  default = false
}

variable "oauth2_proxy_set_xauthrequest" {
  type = bool
  default = false
}

variable "oauth2_proxy_pass_authorization_header" {
  type = bool
  default = false
}

variable "oauth2_proxy_set_authorization_header" {
  type = bool
  default = false
}

variable "oauth2_proxy_skip_jwt_bearer_tokens" {
  type = bool
  default = false
}

variable "oauth2_proxy_extra_args" {
  type = map(string)
  default = {}
}

variable "oauth2_proxy_inject_request_headers" {
  type = list(any)
  default = [
      {
        name = "x-forwarded-access-token"
        values = [
          {
            claim = "access_token"
          }
        ]
      }
    ]
}

variable "oauth2_proxy_inject_response_headers" {
  type = list(any)
  default = []
}