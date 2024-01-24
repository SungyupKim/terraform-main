# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

provider "aws" {
  region = var.region
}

provider "acme" {
  #server_url = "https://acme-staging-v02.api.letsencrypt.org/directory"
  server_url = "https://acme-v02.api.letsencrypt.org/directory"
}

data "aws_region" "current" {
}

data "aws_eks_cluster_auth" "main" {
  name = data.aws_eks_cluster.test.name
}

provider "kubernetes" {
  host = data.aws_eks_cluster.test.endpoint

  token                  = data.aws_eks_cluster_auth.main.token
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.test.certificate_authority.0.data)
}

data "aws_availability_zones" "available" {}
data "aws_caller_identity" "current" {}

locals {
  cluster_name = "education-eks-${random_string.suffix.result}"
  cidr = "10.0.0.0/16"
  account_id = data.aws_caller_identity.current.account_id
  service_account_name = "terraform-eks-ebs-serviceaccount-${random_id.rng.hex}"
  storage_class_name = "efs-sc"


  #for creating docker secret
  #image_repository_address = "nexus.mlops.matilda-mzc.com"
  image_repository_id = "admin"
  #do not commit actual pw to git repository!!
  image_repository_pw = "admin33"
  elastic_search_password = "megaz!"
  platform_domain = "terraform-demo-site.matilda-mzc.com"
  image_repository_address = "nexus.${local.platform_domain}"
  
  ############################## container image tags ########################################
  platform-image-repository = "nexus.mlops.matilda-mzc.com"
  mlops-backend-tag = "8360faf1"
  asset-backend-tag = "a0c9c0"
  portal-frontend-tag = "cae6e5"
  admin-frontend-tag = "cb3b36"
}

resource "random_string" "suffix" {
  length  = 8
  special = false
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "3.19.0"

  name = "education-vpc-${random_string.suffix.result}"

  cidr = local.cidr
  azs  = slice(data.aws_availability_zones.available.names, 0, 3)

  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.4.0/24", "10.0.5.0/24", "10.0.6.0/24"]

  enable_nat_gateway   = true
  single_nat_gateway   = true
  enable_dns_hostnames = true

  public_subnet_tags = {
    "kubernetes.io/cluster/${local.cluster_name}" = "shared"
    "kubernetes.io/role/elb"                      = 1
  }

  private_subnet_tags = {
    "kubernetes.io/cluster/${local.cluster_name}" = "shared"
    "kubernetes.io/role/internal-elb"             = 1
  }
}

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "19.5.1"

  cluster_name    = local.cluster_name
  cluster_version = "1.25"

  vpc_id                         = module.vpc.vpc_id
  subnet_ids                     = module.vpc.private_subnets
  cluster_endpoint_public_access = true
  cluster_endpoint_private_access = true

  eks_managed_node_group_defaults = {
    ami_type = "AL2_x86_64"
    disk_size            = "200"
    block_device_mappings = {
      xvda = {
        device_name = "/dev/xvda"
        ebs         = {
          volume_size           = 200
          volume_type           = "gp3"
          iops                  = 3000
          throughput            = 150
          encrypted             = true
          delete_on_termination = true
        }
      }
    }
  }

  iam_role_additional_policies = {
    AmazonEBSCSIDriverPolicy = "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
  }

  eks_managed_node_groups = {

    one = {
      name = "node-group-platform"

      instance_types = ["t3.2xlarge"]

      min_size     = 1
      max_size     = 3
      desired_size = 3
    }

    three = {
      name = "node-group-notebook"
	
      instance_types = ["t3.2xlarge"]

      min_size     = 0
      max_size     = 2
      desired_size = 2
      
      labels = {
        target = "notebook"
      }
      taints = [
       {
        key = "target"
        value  = "notebook"
        effect = "NO_SCHEDULE"
       }
      ]
    }
  }
}

resource "aws_iam_role_policy_attachment" "additional" {
  for_each = {
    for node_group, group_details in module.eks.eks_managed_node_groups : node_group => group_details
    # We have to add if condition as the module output contains all node names,
    # even if they are not created.
  }

  policy_arn = aws_iam_policy.auto_scailing_policy.arn
  role       = each.value.iam_role_name
}

data "aws_security_group" "imported_sg" {
  id = "${module.eks.node_security_group_id}"
}
    
# SG Rule which you would like to add
resource "aws_security_group_rule" "example" {
  type              = "ingress"
  from_port         = 15017
  to_port           = 15017
  protocol          = "tcp"
  cidr_blocks       = [local.cidr]

  security_group_id = "${data.aws_security_group.imported_sg.id}"
}




# https://aws.amazon.com/blogs/containers/amazon-ebs-csi-driver-is-now-generally-available-in-amazon-eks-add-ons/ 
data "aws_iam_policy" "ebs_csi_policy" {
  arn = "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
}

module "irsa-ebs-csi" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-assumable-role-with-oidc"
  version = "4.7.0"

  create_role                   = true
  role_name                     = "AmazonEKSTFEBSCSIRole-${module.eks.cluster_name}"
  provider_url                  = module.eks.oidc_provider
  role_policy_arns              = [data.aws_iam_policy.ebs_csi_policy.arn]
  oidc_fully_qualified_subjects = ["system:serviceaccount:kube-system:ebs-csi-controller-sa"]
}

resource "aws_eks_addon" "ebs-csi" {
  cluster_name             = module.eks.cluster_name
  addon_name               = "aws-ebs-csi-driver"
  addon_version            = "v1.19.0-eksbuild.2"
  service_account_role_arn = module.irsa-ebs-csi.iam_role_arn
  tags = {
    "eks_addon" = "ebs-csi"
    "terraform" = "true"
  }
}

data "aws_eks_cluster" "test" {
  name = module.eks.cluster_name
  depends_on = [module.eks.cluster_name]
}

data "aws_eks_cluster_auth" "test" {
  name = module.eks.cluster_name
  depends_on = [module.eks.cluster_name]
}

provider "helm" {
  kubernetes {
    host                   = data.aws_eks_cluster.test.endpoint
    token                  = data.aws_eks_cluster_auth.test.token
    cluster_ca_certificate = base64decode(data.aws_eks_cluster.test.certificate_authority[0].data)
  }
}

resource "helm_release" "metrics_server" {
  namespace        = "kube-system"
  name             = "metrics-server"
  chart            = "metrics-server"
  version          = "3.8.2"
  repository       = "https://kubernetes-sigs.github.io/metrics-server/"
  create_namespace = true
  timeout = 1500
  set {
    name  = "replicas"
    value = 2
  }
}

resource "aws_iam_policy" "auto_scailing_policy" {
  name = "AmazonEKS_AutoScaler_Policy_${local.cluster_name}_${random_id.rng.hex}"
  path = "/"
  policy = jsonencode({
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "autoscaling:DescribeAutoScalingGroups",
        "autoscaling:DescribeAutoScalingInstances",
        "autoscaling:DescribeLaunchConfigurations",
        "autoscaling:DescribeScalingActivities",
        "autoscaling:DescribeTags",
        "ec2:DescribeInstanceTypes",
        "ec2:DescribeLaunchTemplateVersions"
      ],
      "Resource": ["*"]
    },
    {
      "Effect": "Allow",
      "Action": [
        "autoscaling:SetDesiredCapacity",
        "autoscaling:TerminateInstanceInAutoScalingGroup",
        "ec2:DescribeImages",
        "ec2:GetInstanceTypesFromInstanceRequirements",
        "eks:DescribeNodegroup"
      ],
      "Resource": ["*"]
    }
  ]
})
}
resource "aws_iam_policy" "eks_csi_policy" {
  name        = "AmazonEKS_EFS_CSI_Driver_Policy_${local.cluster_name}_${random_id.rng.hex}"
  path        = "/"
  description = "policy for efs"

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  policy = jsonencode({
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "elasticfilesystem:DescribeAccessPoints",
        "elasticfilesystem:DescribeFileSystems",
        "elasticfilesystem:DescribeMountTargets",
        "ec2:DescribeAvailabilityZones"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "elasticfilesystem:CreateAccessPoint"
      ],
      "Resource": "*",
      "Condition": {
        "StringLike": {
          "aws:RequestTag/efs.csi.aws.com/cluster": "true"
        }
      }
    },
    {
      "Effect": "Allow",
      "Action": [
        "elasticfilesystem:TagResource"
      ],
      "Resource": "*",
      "Condition": {
        "StringLike": {
          "aws:ResourceTag/efs.csi.aws.com/cluster": "true"
        }
      }
    },
    {
      "Effect": "Allow",
      "Action": "elasticfilesystem:DeleteAccessPoint",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "aws:ResourceTag/efs.csi.aws.com/cluster": "true"
        }
      }
    }
  ]
})
}

resource "random_id" "rng" {
  keepers = {
    first = "${timestamp()}"
  }     
  byte_length = 8
}

module "kubernetes-iamserviceaccount"{
  depends_on = [data.aws_eks_cluster.test]
  source  = "bigdatabr/kubernetes-iamserviceaccount/aws"
  version = "1.1.0"
  cluster_name = local.cluster_name
  service_account_name = local.service_account_name
  namespace = "kube-system"
  role_name = "eks-csi-role-${random_id.rng.hex}"
  use_existing_service_account = false
  # insert the 4 required variables here
}

resource "aws_iam_role_policy_attachment" "eks_csi_role" {
  role       = module.kubernetes-iamserviceaccount.iam_role.name
  policy_arn = "${aws_iam_policy.eks_csi_policy.arn}"
}

resource "helm_release" "aws-efs-csi-driver" {
  namespace        = "kube-system"
  name             = "aws-efs-csi-driver"
  chart            = "aws-efs-csi-driver"
  repository       = "https://kubernetes-sigs.github.io/aws-efs-csi-driver/"
  create_namespace = true
  timeout = 1500

  set {
    name = "image.repository"
    value = "602401143452.dkr.ecr.ap-northeast-2.amazonaws.com/eks/aws-efs-csi-driver"
  }
  
  set {
    name = "controller.serviceAccount.create"
    value = false
  }

  set {
    name = "controller.serviceAccount.name"
    value = "${local.service_account_name}"
  }
}

resource "aws_security_group" "allow_tls" {
  name        = "allow_efs_csi_${local.cluster_name}"
  description = "Allow efs csi inbound traffic"
  vpc_id      = module.vpc.vpc_id

  ingress {
    description      = "TLS from VPC"
    to_port          = 2049
    from_port        = 2049
    protocol         = "tcp"
    cidr_blocks      = [local.cidr]
  }

  tags = {
    Name = "allow_tls"
  }
}

resource "aws_efs_file_system" "eks-matilda-filesystem" {
  creation_token = "eks-matilda-${local.cluster_name}"

  tags = {
    Name = "eks-matilda-${local.cluster_name}"
  }
}

resource "aws_efs_mount_target" "alpha" {
  count = length(module.vpc.private_subnets)
  file_system_id = aws_efs_file_system.eks-matilda-filesystem.id
  subnet_id      = module.vpc.private_subnets[count.index]
  security_groups = ["${aws_security_group.allow_tls.id}"]
}

resource "kubernetes_storage_class_v1" "example" {
  count = length(module.vpc.private_subnets)
  metadata {
    name = "${local.storage_class_name}-${count.index}"
  }
  storage_provisioner = "efs.csi.aws.com"
  reclaim_policy      = "Retain"
  parameters = {
    provisioningMode = "efs-ap"
    fileSystemId = "${aws_efs_file_system.eks-matilda-filesystem.id}"
    directoryPerms = "777"
    gidRangeStart =  "1000"
    gidRangeEnd = "2000"
    gid = "1000"
    uid = "1000"
  }
}

resource "kubernetes_storage_class_v1" "postgres-sc" {
  metadata {
    name = "${local.storage_class_name}-postgres"
  }
  storage_provisioner = "efs.csi.aws.com"
  reclaim_policy      = "Retain"
  parameters = {
    provisioningMode = "efs-ap"
    fileSystemId = "${aws_efs_file_system.eks-matilda-filesystem.id}"
    directoryPerms = "777"
    gidRangeStart =  "1000"
    gidRangeEnd = "2000"
    gid = "1001"
    uid = "1001"
  }
}

resource "kubernetes_storage_class_v1" "grafana-sc" {
  metadata {
    name = "${local.storage_class_name}-grafana"
  }
  storage_provisioner = "efs.csi.aws.com"
  reclaim_policy      = "Retain"
  parameters = {
    provisioningMode = "efs-ap"
    fileSystemId = "${aws_efs_file_system.eks-matilda-filesystem.id}"
    directoryPerms = "777"
    gidRangeStart =  "1000"
    gidRangeEnd = "2000"
    gid = "147"
    uid = "147"
  }
}

resource "kubernetes_storage_class_v1" "efs-sc-notebook" {
  metadata {
    name = "${local.storage_class_name}-notebook"
  }
  storage_provisioner = "efs.csi.aws.com"
  reclaim_policy      = "Retain"
  parameters = {
    provisioningMode = "efs-ap"
    fileSystemId = "${aws_efs_file_system.eks-matilda-filesystem.id}"
    directoryPerms = "777"
    gidRangeStart =  "1000"
    gidRangeEnd = "2000"
    gid = "1000"
    uid = "1000"
  }
}

resource "kubernetes_annotations" "default-storageclass" {
  api_version = "storage.k8s.io/v1"
  kind        = "StorageClass"
  force       = "true"

  metadata {
    name = "gp2"
  }
  annotations = {
    "storageclass.kubernetes.io/is-default-class" = "false"
  }
}

resource "kubernetes_annotations" "new-default-storageclass" {
  depends_on = [kubernetes_storage_class_v1.example]

  api_version = "storage.k8s.io/v1"
  kind        = "StorageClass"
  force       = "true"

  metadata {
    name = "${local.storage_class_name}-0"
  }
  annotations = {
    "storageclass.kubernetes.io/is-default-class" = "true"
  }
}

resource "null_resource" "kubeconfig" {
  triggers = {
    cluster = module.eks.cluster_name
  }
  
  provisioner "local-exec" {
    command = "aws eks update-kubeconfig --name ${local.cluster_name}"
  }
}

resource "null_resource" "kubeflow" {
  depends_on = [module.eks.cluster_name, null_resource.kubeconfig]
  provisioner "local-exec" {
    working_dir = "${path.module}/kubeflow-manifests"
    command = "./install_kubeflow.sh"
  }
}

resource "null_resource" "create-manifests"{
  depends_on = [data.external.docker-config]
  triggers = {
    always_run = "${timestamp()}"
  }
  provisioner "local-exec" {
    command = "./provide_yaml.sh 'nexus.${local.platform_domain}' 'nexus-web.${local.platform_domain}' '${local.platform_domain}' '${local.platform-image-repository}' '${base64encode(data.local_file.docker-config.content)}' '${local.mlops-backend-tag}' '${local.asset-backend-tag}' '${local.portal-frontend-tag}' '${local.admin-frontend-tag}'"
  }
}

resource "null_resource" "platform-manifests" {
  triggers = {
    always_run = "${timestamp()}"
  }
  depends_on = [helm_release.matilda-helm, null_resource.kubeflow, helm_release.nexus-hdx, null_resource.create-manifests, kubernetes_secret.docker-registry-kubeflow]
  provisioner "local-exec" {
    command = "./apply_matilda_manifests.sh"
  }
}

data "external" "project-volume-name" {
  depends_on = [null_resource.platform-manifests]
  program = ["${abspath(path.module)}/get_volume_name.sh"]
}

resource "null_resource" "apply-configmap" {
  triggers = {
    always_run = "${timestamp()}"
  }
  depends_on = [data.external.project-volume-name]
  provisioner "local-exec" {
    command = "./apply_configmap.sh '${aws_efs_file_system.eks-matilda-filesystem.id}' '${data.external.project-volume-name.result.volume_name}'"
  }
}

#######################################certifiicate###############################################


resource "tls_private_key" "private_key" {
  algorithm = "RSA"
}

resource "acme_registration" "reg" {
  account_key_pem = tls_private_key.private_key.private_key_pem
  email_address   = "sungyup@mz.co.kr"
}

resource "acme_certificate" "certificate" {
  account_key_pem           = acme_registration.reg.account_key_pem
  common_name               = local.platform_domain
  subject_alternative_names = ["*.${local.platform_domain}"]

  dns_challenge {
    provider = "route53"
  }
}

resource "aws_acm_certificate" "aws_acm_certificate" {
  certificate_body  = acme_certificate.certificate.certificate_pem
  private_key       = acme_certificate.certificate.private_key_pem
  certificate_chain = acme_certificate.certificate.issuer_pem
}

/*
resource "kubernetes_secret" "istio-gateway-secret" {
  depends_on = [acme_certificate.certificate]
  
  metadata {
    name = "istio-secret-${random_id.rng.hex}"
    namespace = "istio-system"
  }

  data = {
    "tls.crt" = acme_certificate.certificate.certificate_pem
    "tls.key" = acme_certificate.certificate.private_key_pem
  }

  type = "kubernetes.io/tls"
}
*/

############################################ get worker nodes ##############################################
data "aws_instances" "my_worker_nodes" {
  instance_tags = {
    "aws:eks:cluster-name" = "${local.cluster_name}"
  }
  depends_on = [module.eks.eks_managed_node_groups]
}

#######################################ELB#########################################

resource "aws_elb" "keycloak-elb" {
  name               = "elb-kc-${local.cluster_name}"
  subnets = module.vpc.public_subnets

  listener {
    instance_port      = 32222
    instance_protocol  = "tcp"
    lb_port            = 443
    lb_protocol        = "ssl"
    ssl_certificate_id = "${aws_acm_certificate.aws_acm_certificate.id}"
  }
  
  instances                   = data.aws_instances.my_worker_nodes.ids
  cross_zone_load_balancing   = true
  idle_timeout                = 400
  connection_draining         = true
  connection_draining_timeout = 400

  tags = {
    Name = "keycloak-gateway-elb"
  }
}

resource "aws_elb" "istio" {
  name               = "elb-${local.cluster_name}"
  #availability_zones = module.vpc.azs
  subnets = module.vpc.public_subnets
  listener {
    instance_port     = 31663
    instance_protocol = "tcp"
    lb_port           = 80
    lb_protocol       = "tcp"
  }

  listener {
    instance_port      = 31663
    instance_protocol  = "tcp"
    lb_port            = 443
    lb_protocol        = "ssl"
    ssl_certificate_id = "${aws_acm_certificate.aws_acm_certificate.id}"
  }

  listener {
    instance_port     = 30493
    instance_protocol = "tcp"
    lb_port           = 15443
    lb_protocol       = "tcp"
  }

  listener {
    instance_port     = 32159
    instance_protocol = "tcp"
    lb_port           = 31400
    lb_protocol       = "tcp"
  }

  listener {
    instance_port     = 32285
    instance_protocol = "tcp"
    lb_port           = 15021
    lb_protocol       = "tcp"
  }

  health_check {
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 3
    target              = "TCP:32285"
    interval            = 30
  }

  instances                   = data.aws_instances.my_worker_nodes.ids
  cross_zone_load_balancing   = true
  idle_timeout                = 400
  connection_draining         = true
  connection_draining_timeout = 400

  tags = {
    Name = "istio-gateway-elb"
  }
}

import {
    to = aws_route53_zone.matilda
    id = "Z0042811268M2IGBICPG0"
}

resource "aws_route53_zone" "matilda" {
  name = "matilda-mzc.com"
}

resource "aws_route53_record" "matilda_elb_record" {
  zone_id = aws_route53_zone.matilda.zone_id
  name    = local.platform_domain
  type    = "CNAME"
  ttl     = 300
  records = [aws_elb.istio.dns_name]
}

resource "aws_route53_record" "matilda_elb_record_nexus" {
  zone_id = aws_route53_zone.matilda.zone_id
  name    = "nexus.${local.platform_domain}"
  type    = "CNAME"
  ttl     = 300
  records = [aws_elb.istio.dns_name]
}

resource "aws_route53_record" "matilda_elb_record_nexus_web" {
  zone_id = aws_route53_zone.matilda.zone_id
  name    = "nexus-web.${local.platform_domain}"
  type    = "CNAME"
  ttl     = 300
  records = [aws_elb.istio.dns_name]
}

resource "aws_route53_record" "matilda_elb_record_keycloak" {
  zone_id = aws_route53_zone.matilda.zone_id
  name    = "keycloak.${local.platform_domain}"
  type    = "CNAME"
  ttl     = 300
  records = [aws_elb.keycloak-elb.dns_name]
}

resource "aws_security_group_rule" "elb_allow_all" {
  type              = "ingress"
  from_port         = 0
  to_port           = 65535
  protocol          = "all"
  cidr_blocks       = ["0.0.0.0/0"]
  #source_security_group_id = "${aws_elb.istio.source_security_group_id}"
  security_group_id = "${aws_elb.istio.source_security_group_id}"
}

resource "aws_security_group_rule" "elb_rule" {
  type              = "ingress"
  from_port         = 0
  to_port           = 65535
  protocol          = "all"
  
  #cidr_blocks       = [local.cidr]
  source_security_group_id = "${aws_elb.istio.source_security_group_id}"
  security_group_id = "${data.aws_security_group.imported_sg.id}"
}
#######################################prometheus-helm###############################################

resource "helm_release" "prometheus-hdx" {
  depends_on = [kubernetes_annotations.default-storageclass, kubernetes_annotations.new-default-storageclass]
  namespace        = "monitoring"
  name             = "kube-prometheus-stack"
  chart            = "kube-prometheus-stack"
  version          = "45.9.1"
  repository       = "https://prometheus-community.github.io/helm-charts"
  create_namespace = true
  timeout = 1500
  values = [
    "${file("prometheus_values.yaml")}"
  ] 
}

#######################################keycloak##########################################

resource "helm_release" "keycloak" {
  depends_on = [kubernetes_annotations.default-storageclass, kubernetes_annotations.new-default-storageclass, null_resource.platform-manifests]
  namespace        = "keycloak"
  name             = "keycloak"
  chart            = "keycloak"
  version          = "18.0.2"
  repository       = "https://charts.bitnami.com/bitnami"
  create_namespace = true
  timeout = 1500
  set {
    name  = "global.storageClass"
    value = "efs-sc-postgres"
  }
  
  set {
    name  = "service.http.enabled"
    value = "true"
  }

  set {
    name  = "service.type"
    value = "NodePort"
  }
  
  set {
    name  = "service.ports.http"
    value = "80"
  }

  set {
    name  = "service.nodePorts.http"
    value = "32222"
  }
  
  set {
    name  = "proxy"
    value = "edge"
  }
  
  set {
    name  = "auth.adminUser"
    value = "admin"
  }
  
  set {
    name  = "auth.adminPassword"
    value = "admin"
  }

  set {
    name = "extraEnvVars[0].name"
    value = "KC_HOSTNAME_ADMIN_URL"
  }
 
  set {
    name = "extraEnvVars[0].value"
    value = "https://keycloak.${local.platform_domain}"
  }
  
  set {
    name = "extraEnvVars[1].name"
    value = "KC_HOSTNAME_STRICT_HTTPS"
  }
 
  set {
    name = "extraEnvVars[1].value"
    type = "string"
    value = "true"
  }
  
  set {
    name = "extraEnvVars[2].name"
    value = "KC_HOSTNAME_URL"
  }
 
  set {
    name = "extraEnvVars[2].value"
    value = "https://keycloak.${local.platform_domain}"
  }
 
  set {
    name = "extraVolumes[0].name"
    value = "keycloak"
  }
 
  set {
    name = "extraVolumes[0].configMap.name"
    value = "keycloak-import"
  }
  
  set {
    name = "extraVolumeMounts[0].name"
    value = "keycloak"
  }

  set {
    name = "extraVolumeMounts[0].mountPath"
    value = "/opt/bitnami/keycloak/data/import"
  }

  set {
    name = "extraStartupArgs"
    value = "--import-realm"
  }
 
  /*
  set {
    name  = "proxy"
    value = "passthrough"
  }

  set {
    name = "extraStartupArgs"
    value = "-Dkeycloak.frontendUrl=https://${local.platform_domain}/keycloak/auth"
  }
  
  set {
    name = "extraEnvVars[0].name"
    value = "SET_PROXY_ADDRESS_FORWARDING"
  }
  
  set {
    name = "extraEnvVars[0].value"
    type = "string"
    value = "true"
  }
  
  set {
    name = "extraEnvVars[1].name"
    value = "KEYCLOAK_LOG_LEVEL"
  }
 
  set {
    name = "extraEnvVars[1].value"
    value = "DEBUG"
  }
  */
}

#######################################auto scaler ######################################

resource "helm_release" "cluster-autoscaler" {
  name             = "autoscaler"
  chart            = "cluster-autoscaler"
  repository       = "https://kubernetes.github.io/autoscaler"
  timeout = 1500
  set {
    name  = "autoDiscovery.clusterName"
    value = "${module.eks.cluster_name}"
  }
  
  set {
    name  = "awsRegion"
    value = "${data.aws_region.current.name}"
  }
  
  set {
    name  = "extraArgs.skip-nodes-with-local-storage"
    type  = "string"
    value = "false"
  }
}

#######################################postgres##########################################

resource "helm_release" "postgres" {
  depends_on = [kubernetes_annotations.default-storageclass, kubernetes_annotations.new-default-storageclass]
  namespace        = "database"
  name             = "postgresql"
  chart            = "postgresql"
  version          = "12.8.2"
  repository       = "https://charts.bitnami.com/bitnami"
  create_namespace = true
  timeout = 1500
  set {
    name  = "global.storageClass"
    value = "efs-sc-postgres"
  }
  
  set {
    name  = "global.postgresql.auth.postgresPassword"
    value = "megaz133"
  }
}

resource "null_resource" "postgres-matilda-schema" {
  depends_on = [helm_release.postgres, null_resource.platform-manifests, kubernetes_secret.docker-registry-dex]
  triggers = {
    always_run = "${timestamp()}"
  }

  provisioner "local-exec" {
    command="./matilda_schema.sh"
  }
}

#####################################redis#################################################

resource "helm_release" "redis" {
  depends_on = [kubernetes_annotations.default-storageclass, kubernetes_annotations.new-default-storageclass]
  namespace        = "redis"
  name             = "redis"
  chart            = "redis"
  version          = "18.1.6"
  repository       = "https://charts.bitnami.com/bitnami"
  create_namespace = true
  timeout = 1500
  values = [
    "${file("values_redis.yaml")}"
  ]
}

######################################gitea################################################
resource "null_resource" "postgres-gitea-config-1" {
  depends_on = [helm_release.postgres]

  provisioner "local-exec" {
    command="./giteaschema.sh"
  }
}

resource "helm_release" "gitea-hdx" {
  depends_on = [kubernetes_annotations.default-storageclass, kubernetes_annotations.new-default-storageclass]
  namespace        = "gitea"
  name             = "gitea"
  chart            = "gitea"
  repository       = "https://dl.gitea.io/charts/"
  create_namespace = true
  timeout = 1500

  values = [
    "${file("values_gitea.yaml")}"
  ]
}

##########################################nexus###########################################
resource "helm_release" "nexus-hdx" {
  depends_on = [kubernetes_annotations.default-storageclass, kubernetes_annotations.new-default-storageclass]
  namespace        = "nexus"
  name             = "nexus"
  chart            = "nexus-repository-manager"
  version          = "56.0.0"
  repository       = "https://sonatype.github.io/helm3-charts"
  create_namespace = true
  timeout = 1500

  values = [
    "${file("nexus_values.yaml")}"
  ]
}

#######################################elk###############################################
resource "helm_release" "elastic-search-hdx" {
  depends_on = [kubernetes_annotations.default-storageclass, kubernetes_annotations.new-default-storageclass]
  name       = "elastic-search-hdx"
  chart      = "./elk-hdx/elasticsearch"
  namespace  = "elastic-helm"
  create_namespace = true
  timeout = 1500
  values = [
    "${file("./elk-hdx/elasticsearch/values.yaml")}"
  ]
}

resource "helm_release" "filebeat-hdx" {
  depends_on = [kubernetes_annotations.default-storageclass, kubernetes_annotations.new-default-storageclass]
  name       = "filebeat-hdx"
  chart      = "./elk-hdx/filebeat"
  namespace  = "elastic-helm"
  create_namespace = true
  timeout = 1500

  values = [
    "${file("./elk-hdx/filebeat/values.yaml")}"
  ]
}

resource "helm_release" "logstash-hdx" {
  depends_on = [kubernetes_annotations.default-storageclass, kubernetes_annotations.new-default-storageclass]
  name       = "logstash-hdx"
  chart      = "./elk-hdx/logstash"
  namespace  = "elastic-helm"
  create_namespace = true
  timeout = 1500

  values = [
    "${file("./elk-hdx/logstash/values_terraform.yaml")}"
  ]
}

resource "null_resource" "init_nexus_hdx" {
  triggers = {
    always_run = "${timestamp()}"
  }
  depends_on = [helm_release.nexus-hdx]
  
  provisioner "local-exec" {
    command = "kubectl apply -f ./matilda-manifests-deploy/nexus_gateway.yaml && ./matilda-manifests-deploy/init_nexus.sh"
  }
}

resource "null_resource" "download_images" {
  triggers = {
    always_run = "${timestamp()}"
  }

  depends_on = [null_resource.init_nexus_hdx]

  provisioner "local-exec" {
    command = "./matilda-manifests-deploy/download_and_push_platform_images.sh"
  }
}

resource "helm_release" "matilda-helm" {
  depends_on = [null_resource.download_images, helm_release.nexus-hdx, kubernetes_annotations.default-storageclass, kubernetes_annotations.new-default-storageclass]
  name       = "matilda-hdx"
  chart      = "./matilda-hdx-helm-chart"
  timeout = 1500
  
  set {
    name = "nexusDockerConfig"
    value = "${base64encode(data.local_file.docker-config.content)}"
  }
  set {
    name = "platformDomain"
    value = "${local.platform_domain}"
  }
  set {
    name  = "nexusDomain"
    value = "nexus.${local.platform_domain}"
  }

  set {
    name  = "nexusWebDomain"
    value = "nexus-web.${local.platform_domain}"
  }

  set {
    name = "adminFrontendTag"
    value = "${local.admin-frontend-tag}"
  }

  set {
    name = "assetBackendTag"
    value = "${local.asset-backend-tag}"
  }

  set {
    name = "mlopsBackendTag"
    value = "${local.mlops-backend-tag}"
  }

  set {
    name = "portalFrontendTag"
    value = "${local.portal-frontend-tag}"
  }

  set {
    name = "schedulerTag"
    value = "4e32ec3"
  }

  set {
    name = "dexTag" 
    value = "latest"
  } 
}

resource "null_resource" "logstash-library" {
  depends_on = [helm_release.logstash-hdx]
  
  provisioner "local-exec" {
    command = "kubectl exec -n elastic-helm logstash-hdx-logstash-0 -- bash -c 'cd /usr/share/logstash/data && curl -O https://repo1.maven.org/maven2/org/postgresql/postgresql/42.6.0/postgresql-42.6.0.jar' && kubectl delete pod -n elastic-helm logstash-hdx-logstash-0 --force"
  }
}

resource "helm_release" "kibana-hdx" {
  depends_on = [kubernetes_annotations.default-storageclass, kubernetes_annotations.new-default-storageclass]
  name       = "kibana-hdx"
  chart      = "./elk-hdx/kibana"
  namespace  = "elastic-helm"
  create_namespace = true
  timeout = 1500

  values = [
    "${file("./elk-hdx/kibana/values.yaml")}"
  ]
}

#######################################docker secret###############################################
/*
resource "null_resource" "docker-config" {
  depends_on = [null_resource.kubeconfig]
  triggers = {
    image_repository = "${local.image_repository_address}"
    image_repository_id = "${local.image_repository_id}"
    image_repository_pw = "${local.image_repository_pw}"
  }

  provisioner "local-exec" {
    working_dir = "${path.module}/scripts"
    command = "./${path.module}/scripts/docker-credential.sh -r ${local.image_repository_address} -u ${local.image_repository_id} -p ${local.image_repository_pw} -w yes"
  }
}
*/

data "external" "docker-config" {
  depends_on = [null_resource.kubeconfig]
  #working_dir = "${abspath(path.module)}/scripts"
  program = ["${abspath(path.module)}/scripts/docker-credential.sh", "-r", "${local.image_repository_address}", "-u", "${local.image_repository_id}", "-p", "${local.image_repository_pw}", "-w", "yes"]
}

data "local_file" "docker-config" {
  filename = "${path.module}${data.external.docker-config.result.file_path}"
}

resource "kubernetes_secret" "docker-registry-kubeflow" {
  depends_on = [null_resource.kubeflow, data.external.docker-config]
  metadata {
    name = "nexuscred"
    namespace = "kubeflow"
  }

  data = {
    ".dockerconfigjson" = "${data.local_file.docker-config.content}"
  }

  type = "kubernetes.io/dockerconfigjson"
}

resource "kubernetes_secret" "docker-registry-dex" {
  depends_on = [null_resource.kubeflow, data.external.docker-config]
  metadata {
    name = "nexuscred"
    namespace = "auth"
  }

  data = {
    ".dockerconfigjson" = "${data.local_file.docker-config.content}"
  }

  type = "kubernetes.io/dockerconfigjson"
}
