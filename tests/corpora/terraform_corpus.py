#!/usr/bin/env python3
"""The seeded Terraform corpus behind the IaC scanners' READ ranges (D-VF-4, ledger V-02).

WHY THIS EXISTS

    KDEC-014 turns the uat/prod refusal of a version gap on only where the scanners' ranges are
    PROVEN: scanner-registry.yaml `version_support` iac-scan/checkov and iac-scan/trivy-config were
    UNVERIFIED, so every IaC gap was recorded and none was enforced. A range is proven the way
    PIPELINE_ORDERING section 3.1 proved bandit's (PEP 695 under 3.11: the file was skipped, exit 0):
    a file written in the target version's syntax, holding a misconfiguration the scanner is known to
    report, and the question is whether the finding comes back. A parser that cannot read the file
    drops it -- and its silence looks exactly like a clean file. That is the failure this measures.

WHAT A FAMILY IS

    One Terraform release line that added a configuration-language construct. Each family's file
    uses that construct AND holds the same seeded misconfiguration (an SSH ingress open to
    0.0.0.0/0), so "the finding came back" means "the scanner read a file written for this family".
    Releases that added no construct to the .tf language (1.0, 1.6, 1.12, 1.13 as far as this corpus
    knows) are not separate families: a range spanning them claims them through their neighbours,
    and the basis says so. Which release introduced a construct is the corpus author's reading of
    the Terraform changelog (INFERRED); whether the scanner reads the file is MEASURED.

    The CONTROL family is a deliberately unparseable file holding the same seed. A scanner that
    reports the seed from it is not dropping unreadable files, so absence of the seed cannot mean
    "could not read" for that scanner and the probe refuses to write a range (exit 2).

TEST-ONLY INPUT (KDEC-011)

    The corpus is DATA in this module and is written to a temporary directory only when a probe
    runs. No .tf file is committed, so no consumer's IaC scan, and no export of this kit, can ever
    meet a seed as a finding. tests/prove_iac_corpus.py holds that to be true.
"""
import os

# The seeded misconfiguration. checkov's ckv_aws_24 (SSH open to 0.0.0.0/0) and trivy AWS-0107
# (security group ingress from the public internet) both report it; the probe accepts a family only
# when the expected rule is reported AGAINST THIS FILE.
SEED = '''
resource "aws_security_group" "corpus_seed" {
  name        = "corpus-seed"
  description = "corpus seed: SSH open to the internet (deliberate)"
  ingress {
    description = "seeded misconfiguration"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
'''

# What each scanner must report for the seed. A list: a rule renamed between releases (trivy's
# AVD- prefix was dropped) is the same rule.
EXPECTED = {
    'checkov': ['ckv_aws_24'],
    'trivy-config': ['AWS-0107', 'AVD-AWS-0107'],
}

CONTROL = 'control-unparseable'

# (family, construct, body). Ordered oldest first; the probe measures contiguously from the first.
FAMILIES = [
    ('0.12', 'HCL2: first-class expressions, for expressions, dynamic blocks, rich types', '''
variable "ports" {
  type    = list(number)
  default = [443]
}

locals {
  doubled = [for p in var.ports : p * 2]
}

resource "aws_security_group" "dyn" {
  name = "corpus-dyn"
  dynamic "egress" {
    for_each = var.ports
    content {
      from_port   = egress.value
      to_port     = egress.value
      protocol    = "tcp"
      cidr_blocks = ["10.0.0.0/8"]
    }
  }
}
'''),
    ('0.13', 'required_providers source addresses; variable validation blocks', '''
terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}

variable "env" {
  type    = string
  default = "dev"
  validation {
    condition     = contains(["dev", "prod"], var.env)
    error_message = "The env value must be dev or prod."
  }
}
'''),
    ('0.14', 'sensitive input variables and outputs', '''
variable "token" {
  type      = string
  default   = "not-a-secret"
  sensitive = true
}

output "token_out" {
  value     = var.token
  sensitive = true
}
'''),
    ('0.15', 'sensitive() and nonsensitive(); provider configuration_aliases', '''
terraform {
  required_providers {
    aws = {
      source                = "hashicorp/aws"
      configuration_aliases = [aws.alt]
    }
  }
}

locals {
  hidden  = sensitive("x")
  visible = nonsensitive(local.hidden)
}
'''),
    ('1.1', 'moved blocks; nullable variables', '''
variable "maybe" {
  type     = string
  default  = "x"
  nullable = false
}

moved {
  from = aws_security_group.old_seed
  to   = aws_security_group.corpus_seed
}
'''),
    ('1.2', 'lifecycle preconditions, postconditions and replace_triggered_by', '''
variable "names" {
  type    = list(string)
  default = ["a"]
}

resource "aws_security_group" "checked" {
  name = "corpus-checked"
  lifecycle {
    precondition {
      condition     = length(var.names) > 0
      error_message = "At least one name is required."
    }
    postcondition {
      condition     = self.name != ""
      error_message = "The name must not be empty."
    }
    replace_triggered_by = [aws_security_group.corpus_seed.id]
  }
}
'''),
    ('1.3', 'optional object attributes with defaults; startswith()', '''
variable "settings" {
  type = object({
    name = string
    tier = optional(string, "standard")
  })
  default = { name = "x" }
}

locals {
  is_prod = startswith(var.settings.name, "prod")
}
'''),
    ('1.4', 'the terraform_data managed resource', '''
resource "terraform_data" "marker" {
  input = "corpus"
}
'''),
    ('1.5', 'import and check blocks; strcontains() and plantimestamp()', '''
import {
  to = aws_security_group.corpus_seed
  id = "sg-00000000000000000"
}

check "reachable" {
  assert {
    condition     = strcontains("corpus", "corp")
    error_message = "unreachable"
  }
}

locals {
  planned = plantimestamp()
}
'''),
    ('1.7', 'removed blocks; import blocks with for_each', '''
removed {
  from = aws_security_group.gone
  lifecycle {
    destroy = false
  }
}

import {
  for_each = toset(["sg-00000000000000001"])
  to       = aws_security_group.imported[each.key]
  id       = each.value
}
'''),
    ('1.8', 'provider-defined functions (provider::<name>::<function>); issensitive()', '''
locals {
  parsed = provider::aws::arn_parse("arn:aws:iam::123456789012:role/corpus")
  secret = issensitive(local.parsed)
}
'''),
    ('1.9', 'templatestring(); validations that reference other variables', '''
variable "low" {
  type    = number
  default = 1
}

variable "high" {
  type    = number
  default = 2
  validation {
    condition     = var.high > var.low
    error_message = "high must exceed low."
  }
}

locals {
  greeting = templatestring("hello $${name}", { name = "corpus" })
}
'''),
    ('1.10', 'ephemeral resources, variables and outputs; ephemeralasnull()', '''
variable "session" {
  type      = string
  default   = "x"
  ephemeral = true
}

ephemeral "random_password" "db" {
  length = 16
}

locals {
  durable = ephemeralasnull(var.session)
}
'''),
    ('1.11', 'write-only managed-resource attributes', '''
resource "aws_db_instance" "wo" {
  identifier          = "corpus-wo"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = "corpus"
  password_wo         = ephemeral.random_password.db.result
  password_wo_version = 1
}
'''),
    ('1.14', 'action blocks and lifecycle action_trigger', '''
action "aws_lambda_invoke" "notify" {
  config {
    function_name = "corpus"
    payload       = "{}"
  }
}

resource "aws_security_group" "triggered" {
  name = "corpus-triggered"
  lifecycle {
    action_trigger {
      events  = [after_create]
      actions = [action.aws_lambda_invoke.notify]
    }
  }
}
'''),
]

# Unbalanced braces before the seed: no HCL parser can read this file.
control_body = '''
locals {
  broken = [1, 2
'''


def family_names():
    return [f for f, _c, _b in FAMILIES]


def source(family):
    """-> the .tf text for one family (or the control). The seed comes LAST, after the construct,
    so a parser that gives up at the construct never reaches it."""
    if family == CONTROL:
        return '# corpus control: unparseable on purpose\n' + control_body + SEED
    for f, construct, body in FAMILIES:
        if f == family:
            return '# corpus family %s: %s\n%s%s' % (f, construct, body, SEED)
    raise KeyError(family)


def materialise(base, families=None):
    """Write one directory per family (and the control) under `base`, each holding main.tf only.
    -> {family: directory}. One directory per family, so one family's unreadable file can never
    hide or lend a finding to another."""
    out = {}
    for f in list(families or family_names()) + [CONTROL]:
        d = os.path.join(base, 'tf-' + f.replace('.', '_'))
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, 'main.tf'), 'w', encoding='utf-8', newline='\n') as fh:
            fh.write(source(f))
        out[f] = d
    return out
