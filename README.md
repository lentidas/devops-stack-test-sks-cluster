# devops-stack-test-sks-cluster

Repository that holds the Terraform files for my test cluster on Exoscale SKS using Camptocamp's [DevOps Stack](https://devops-stack.io/).

```bash
# Create the cluster
summon terraform init && summon terraform apply

# Get the kubeconfig settings for the created cluster (https://community.exoscale.com/documentation/sks/quick-start/#kubeconfig)
summon exo compute sks kubeconfig gh-sks-cluster kube-admin --zone ch-gva-2 --group system:masters > gh-sks-cluster-config

# Then you can add the settings to your kubeconfig or use this file directly with the KUBECONFIG environment variables
KUBECONFIG="$(echo ~/Documents/Camptocamp_Repos/devops-stack-tests/devops-stack-test-sks-cluster/gh-sks-cluster-config)" k9s

# Destroy the cluster
summon terraform state rm $(summon terraform state list | grep "argocd_application\|argocd_project\|argocd_cluster\|argocd_repository\|kubernetes_\|helm_") && summon terraform destroy
```
