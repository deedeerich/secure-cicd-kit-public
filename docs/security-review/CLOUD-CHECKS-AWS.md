# Cloud checks — AWS (read-only)

```
Truth State:  Authored, not field-tested (2026-11-03). Commands follow the AWS CLI v2 as documented;
              run them in a non-production account first and correct this sheet where an output
              differs. The kit has no AWS deploy adapter: an AWS release is outside the kit
              (modules/MOD-OUTSIDE-KIT.md), so these reads are the only cloud evidence there is.
Use with:     CAB-CHANGE-SAFETY-STEPS.md step 4. Run only the checks for the boundary rows that are yes.
Read-only:    every command is a get, list, describe, lookup, validate or simulate. None writes. The
              AWS managed policy SecurityAudit (or ReadOnlyAccess) is enough for almost all of them;
              never take a write role to review. Add --region <region> where the resource is regional.
Placeholders: <role>, <policyArn>, <bucket>, <keyId>, <fn> (Lambda), <apiId>, <sg>, <vpc>, <arn>.
```

**New to AWS?** A few words that help: an **IAM role** is an identity a service or pipeline assumes;
its **permissions policy** says what it may do and its **trust policy** says who may assume it. A
**security group** is a firewall around one resource; a **network ACL** is one around a subnet.
**S3 Block Public Access** is the account- and bucket-level switch that stops a bucket being public.
**CloudTrail** records API calls; **Config** records how resources looked over time. Start with the
console path for each check; run the command when you want the exact output for the ticket. If an
output doesn't make sense, ask the platform team to walk you through it: that is part of the review.

**Before and after.** Read the state before (production now, or the IaC plan's "before") and after
(the lower account where it already ran, or the plan's "after"), and write both on the ticket. Who
changed what, and when:

```sh
aws cloudtrail lookup-events --lookup-attributes AttributeKey=ResourceName,AttributeValue=<name> --max-results 50 \
  --query "Events[].{when:EventTime, event:EventName, who:Username}" --output table
aws configservice get-resource-config-history --resource-type <AWS::IAM::Role|AWS::EC2::SecurityGroup|AWS::S3::Bucket|...> --resource-id <id> --limit 5
```

Console: **CloudTrail** → **Event history**; **Config** → **Resources** → the resource → **Resource timeline**.

---

## W1 · IAM role and policy diff

```sh
aws iam list-attached-role-policies --role-name <role>
aws iam list-role-policies --role-name <role>                                   # inline policy names
aws iam get-role-policy --role-name <role> --policy-name <name>
aws iam get-policy --policy-arn <policyArn> --query Policy.DefaultVersionId --output text
aws iam list-policy-versions --policy-arn <policyArn>
aws iam get-policy-version --policy-arn <policyArn> --version-id <vN>           # read the new AND the previous version: that is the diff
aws accessanalyzer validate-policy --policy-type IDENTITY_POLICY --policy-document file://policy.json   # wildcards, PassRole to *, ...
aws iam simulate-principal-policy --policy-source-arn <roleArn> --action-names iam:PassRole s3:GetObject --resource-arns <arn>
```

Console: **IAM** → **Roles** → the role → **Permissions**; **Policies** → the policy → **Policy versions**
(compare). **IAM Access Analyzer** → **Findings**.

- **Safe:** the actions added are named (`s3:GetObject`, not `s3:*`) on named resources; conditions
  where they narrow (`aws:SourceAccount`, `aws:PrincipalOrgID`); `validate-policy` returns no
  `SECURITY_WARNING`.
- **Ask:** a service wildcard (`s3:*`) on one named resource; `Resource: "*"` for read-only describes.
- **Stop:** `"Action": "*"` or `"iam:*"`; `iam:PassRole` on `"*"`; `iam:CreatePolicyVersion`,
  `iam:AttachRolePolicy` or `iam:PutRolePolicy` on its own role (privilege escalation); an IAM user with
  an access key created for a workload (gotcha G2). Identity architecture owns wider designs (E3).

## W2 · Trust policy — who may assume the role

```sh
aws iam get-role --role-name <role> --query Role.AssumeRolePolicyDocument
```

Console: **IAM** → **Roles** → the role → **Trust relationships**.

- **Safe:** the principal is one named service, one named role, or GitHub OIDC
  (`token.actions.githubusercontent.com`) with `sub` pinned to `repo:<owner>/<repo>:environment:<env>`
  and `aud` `sts.amazonaws.com`.
- **Ask:** another AWS account as principal: whose is it, and is there an `sts:ExternalId` condition
  for a third party (E5)?
- **Stop:** `"Principal": {"AWS": "*"}` without a condition that narrows it; a GitHub OIDC trust with
  `sub` `repo:<owner>/*` or `StringLike` on `*`, or no `sub` condition at all (any repository on the host
  could assume it).

## W3 · Security groups and network ACLs

```sh
aws ec2 describe-security-group-rules --filters Name=group-id,Values=<sg> \
  --query "SecurityGroupRules[?IsEgress==\`false\`].{port:FromPort, to:ToPort, cidr:CidrIpv4, cidr6:CidrIpv6, src:ReferencedGroupInfo.GroupId}" --output table
aws ec2 describe-network-acls --filters Name=vpc-id,Values=<vpc> --query "NetworkAcls[].Entries"
```

Console: **EC2** → **Security Groups** → the group → **Inbound rules**; **VPC** → **Network ACLs**.

- **Safe:** inbound from a named security group or a narrow range, on the ports the service uses.
- **Ask:** a large private range (`10.0.0.0/8`) where one subnet would do.
- **Stop:** `0.0.0.0/0` or `::/0` inbound to 22, 3389 or a database or cache port; all ports (`-1`) from
  anywhere; a rule called temporary with no removal step (gotcha G1).

## W4 · S3 public access and bucket policy

```sh
aws s3control get-public-access-block --account-id <account>
aws s3api get-public-access-block --bucket <bucket>
aws s3api get-bucket-policy-status --bucket <bucket>                     # PolicyStatus.IsPublic
aws s3api get-bucket-policy --bucket <bucket> --query Policy --output text
aws s3api get-bucket-ownership-controls --bucket <bucket>
aws s3api get-bucket-location --bucket <bucket>                           # residency (DB-6)
aws s3api get-bucket-lifecycle-configuration --bucket <bucket>            # retention (DB-5)
```

Console: **S3** → the bucket → **Permissions** (Block public access, Bucket policy, Object
Ownership); **Management** (lifecycle).

- **Safe:** all four Block Public Access settings true at account and bucket; `IsPublic` false;
  ownership `BucketOwnerEnforced` (ACLs off); the region is one the data may sit in.
- **Ask:** a policy granting another account: whose, and what data?
- **Stop:** Block Public Access turned off for a bucket holding non-public data; `"Principal": "*"`
  with no narrowing condition; a lifecycle rule that deletes audit data early.

## W5 · S3 encryption

```sh
aws s3api get-bucket-encryption --bucket <bucket>
```

- **Safe:** SSE-KMS with a customer-managed key where the data class requires it; otherwise SSE-S3.
- **Stop:** encryption changed to a key in another account, or bucket keys disabled with no reason given.

## W6 · KMS key policy

```sh
aws kms describe-key --key-id <keyId> --query "KeyMetadata.{state:KeyState, manager:KeyManager, spec:KeySpec}"
aws kms get-key-policy --key-id <keyId> --policy-name default --output text
aws kms get-key-rotation-status --key-id <keyId>
aws kms list-grants --key-id <keyId>
```

Console: **KMS** → **Customer managed keys** → the key → **Key policy**, **Key rotation**, **Grants**.

- **Safe:** the users of the key (Encrypt, Decrypt, GenerateDataKey) are the app's role only;
  administrators (`kms:Put*`, `kms:ScheduleKeyDeletion`) are a separate role; rotation on.
- **Stop:** `kms:*` to a workload role; `"Principal": "*"` without a narrowing condition; a key
  scheduled for deletion as part of the change with data still under it (irreversible: step 6.3).

## W7 · CloudTrail and Config still on

```sh
aws cloudtrail describe-trails --query "trailList[].{name:Name, multiRegion:IsMultiRegionTrail, org:IsOrganizationTrail, validation:LogFileValidationEnabled}"
aws cloudtrail get-trail-status --name <trail> --query "{logging:IsLogging, latest:LatestDeliveryTime}"
aws cloudtrail get-event-selectors --trail-name <trail>
aws configservice describe-configuration-recorder-status --query "ConfigurationRecordersStatus[].{name:name, recording:recording, last:lastStatus}"
```

Console: **CloudTrail** → **Trails**; **Config** → **Settings**.

- **Safe:** `IsLogging` true, multi-region, log file validation on; the recorder `recording` true and
  `lastStatus` `SUCCESS`; event selectors unchanged.
- **Stop:** a trail stopped or its data events removed, or the recorder stopped, to cut cost or "during
  the change" (gotcha G4). Logging is the evidence every later review depends on.

## W8 · Lambda resource policy, function URL and execution role

```sh
aws lambda get-policy --function-name <fn> --query Policy --output text
aws lambda get-function-url-config --function-name <fn> --query "{auth:AuthType, cors:Cors}"
aws lambda get-function-configuration --function-name <fn> --query "{role:Role, kms:KMSKeyArn, vpc:VpcConfig.SubnetIds}"
```

Then W1 on the execution role named by `Role`. Console: **Lambda** → the function → **Configuration**
→ **Permissions** (execution role and resource-based policy), **Function URL**.

- **Safe:** no function URL, or `AuthType` `AWS_IAM`; the resource policy names the invoking service
  with `aws:SourceArn` and `aws:SourceAccount`; the execution role reaches only the function's own
  resources.
- **Stop:** a function URL with `AuthType` `NONE` on a function that is not deliberately public (gotcha
  G8); `lambda:InvokeFunction` to `"*"` with no source condition; the execution role shared by
  unrelated functions.

## W9 · Secrets in Lambda environment variables and task definitions

```sh
aws lambda get-function-configuration --function-name <fn> --query "keys(Environment.Variables)"     # names only
aws ecs describe-task-definition --task-definition <td> --query "taskDefinition.containerDefinitions[].{env:environment[].name, secrets:secrets[].name}"
```

**Do not paste values into the ticket.** Look at a value only to tell a literal from a reference.

- **Safe:** credentials come from Secrets Manager or SSM Parameter Store (`secrets` in a task
  definition; fetched at runtime in Lambda), and the role can read only its own.
- **Stop:** a literal password, token or connection string in an environment variable (gotcha G5);
  rotation is owed for it.

## W10 · API Gateway authorizers

```sh
aws apigateway get-authorizers --rest-api-id <apiId>
aws apigateway get-resources --rest-api-id <apiId> --embed methods \
  --query "items[].{path:path, methods:resourceMethods}"                  # look for authorizationType NONE
aws apigateway get-rest-api --rest-api-id <apiId> --query "{policy:policy, endpoint:endpointConfiguration.types}"
aws apigatewayv2 get-routes --api-id <apiId> --query "Items[].{route:RouteKey, auth:AuthorizationType}" --output table   # HTTP APIs
aws apigatewayv2 get-authorizers --api-id <apiId>
```

Console: **API Gateway** → the API → **Resources** → each method → **Method request**
(Authorization); **Authorizers**; for HTTP APIs **Routes** → **Authorization**.

- **Safe:** every new route has an authorizer (IAM, Cognito, JWT or a Lambda authorizer) or is listed
  in the ticket as deliberately public; `apiKeyRequired` is not the only control.
- **Stop:** a new route with `authorizationType` / `AuthorizationType` `NONE` that is not on the ticket
  as public; a resource policy that admits `"*"`.

## W11 · Security Hub and GuardDuty findings for the resource

```sh
aws securityhub get-findings --filters '{"ResourceId":[{"Value":"<arn>","Comparison":"EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' \
  --query "Findings[].{title:Title, severity:Severity.Label, status:Workflow.Status}" --output table
aws guardduty list-detectors
aws guardduty list-findings --detector-id <detector> --finding-criteria '{"Criterion":{"service.archived":{"Eq":["false"]}}}'
aws guardduty get-findings --detector-id <detector> --finding-ids <id> ... --query "Findings[].{type:Type, severity:Severity, resource:Resource.ResourceType}"
```

Console: **Security Hub** → **Findings** (filter Resource ID); **GuardDuty** → **Findings**.

- **Safe:** no active Critical or High finding on the resource that the change introduces or touches.
- **Ask:** an existing High finding the change touches: is it fixed by this change, or made worse?
- **Stop:** an active GuardDuty finding on the resource (credential misuse, unusual API calls): that is
  incident response first (E7), not a review. Security Hub or GuardDuty disabled in the account (SB-5).

## W12 · Route 53 records

```sh
aws route53 list-resource-record-sets --hosted-zone-id <zone> \
  --query "ResourceRecordSets[].{name:Name, type:Type, target:ResourceRecords[].Value, alias:AliasTarget.DNSName}" --output table
```

- **Safe:** each new record points at a resource this change creates or the team owns.
- **Stop:** a CNAME or alias to an S3 bucket, CloudFront distribution or Elastic Beanstalk name that
  does not exist or that another account could claim (dangling: subdomain takeover).
