# OAuth2 Proxy for Keycloak

Orchestrates deploying and configuring an oauth2 proxy with Keycloak as the auth provider.  

You may need to delete the `ValidatingWebhookConfiguration ingress-nginx-admission` if you're using the same host name, and regex for path matching.  
I think there's a bug specifically when the host matches and regex is being used on the path, but not certain yet.   


```
kubectl delete ValidatingWebhookConfiguration ingress-nginx-admission
```

