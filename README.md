# Kubikey
Kubernetes access with your yubikey.

# Daily use

This tool requires a gcloud service account with access rights to your kubernetes cluster (see below) to use. Here, we will assume that we have such a service account with email address a-1@b.iam.gserviceaccount.com. To configure kubectl to use the yubikey to authenticate to the kubernetes cluster with this account name, you first need to run

`
kubikey -u a-1@b.iam.gserviceaccount.com config
`

This will generate a kubeconfig for accessing the kubernetes cluster kubikey was configured for with the given service account.

Now, you can simply access the cluster using kubectl, for example
`
kubectl get pods
`

On first use, this will ask you for your PIN. After entry, kubectl gets an access token valid for a maximum of 1 hour, after which it will again ask for a PIN to create a new token.

# Direct token generation

Should you for some reason have a need to directly obtain either an identity or access token for your service account, then this is possible using
```
kubikey -u a-1@b.iam.gserviceaccount.com id
```
for an identity token, and
```
kubikey -u a-1@b.iam.gserviceaccount.com access
```
to get an access token. Both tokens are fully scoped for all gcloud services.

# Configuring Kubikey

Kubikey config generates the kubeconfig based on the template `templates/kubeconfig`. This template should contain all the necessary access information for your cluster, and contain the scaffolding for the kubikey auth provider. When switching this code to a different cluster, it is easiest to first use the gcloud sdk to generate a kubeconfig for it, then using that to edit the template here, keeping just the yubikey auth_provider section unchanged.

# Creating new gcloud service accounts

To use this tool, a gcloud service account should be set up first, and given access to the kubernetes cluster. Specifically, the service account must be configured for key access using the public key of the yubikey (which can be obtained by running `yubico-piv-tool -a read-cert -s 9a` with the yubikey plugged in), and given at least the access right `container.clusters.get` (part of o.a. the role `container.clusterViewer`).

Access control can be done through either further gcloud access rights or roles, or by using RBAC. For the second, kubernetes will see the service account as an account with username matching the email address of the service account.

To create a service account with the needed rights from the commandline, three steps are needed. First, create the account with
```
gcloud iam service-accounts create <NAME>
```
This creates a new service account with the given name, and returns the email address associated with that new account. This email address can be used to configure the access rights in kubernetes itself and is needed in the next steps

Second, we add the public key as authentication method:
```
gcloud iam service-accounts keys upload <KEYFILE> --iam-account <SERVICE_EMAIL>
```

Finally, we grant `container.clusterViewer` (this is the smallest predefined role having `container.clusters.get`) using
```
gcloud projects add-iam-policy-binding tweedegolf-cluster --member=serviceAccount:<SERVICE_EMAIL> --role=container.clusterViewer
```
