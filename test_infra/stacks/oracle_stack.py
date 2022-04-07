import json

from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_glue as glue
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kms as kms
from aws_cdk import aws_lakeformation as lf
from aws_cdk import aws_rds as rds
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_secretsmanager as secrets
from aws_cdk import aws_ssm as ssm
from aws_cdk import core as cdk


class OracleStack(cdk.Stack):  # type: ignore
    def __init__(
        self,
        scope: cdk.Construct,
        construct_id: str,
        vpc: ec2.IVpc,
        bucket: s3.IBucket,
        key: kms.Key,
        **kwargs: str,
    ) -> None:
        """
        AWS Data Wrangler Development Databases Infrastructure.
        Includes Oracle.
        """
        super().__init__(scope, construct_id, **kwargs)

        self.vpc = vpc
        self.key = key
        self.bucket = bucket

        self._set_db_infra()
        self._set_catalog_encryption()
        self._setup_oracle()

    def _set_db_infra(self) -> None:
        self.db_username = "test"
        # fmt: off
        self.db_password_secret = secrets.Secret(
            self,
            "db-password-secret",
            secret_name="aws-data-wrangler/db_password",
            generate_secret_string=secrets.SecretStringGenerator(exclude_characters="/@\"\' \\", password_length=30),
        ).secret_value
        # fmt: on
        self.db_password = self.db_password_secret.to_string()
        self.db_security_group = ec2.SecurityGroup(
            self,
            "aws-data-wrangler-database-sg",
            vpc=self.vpc,
            description="AWS Data Wrangler Test Athena - Database security group",
        )
        self.db_security_group.add_ingress_rule(self.db_security_group, ec2.Port.all_traffic())
        ssm.StringParameter(
            self,
            "db-security-group-parameter",
            parameter_name="/Wrangler/EC2/DatabaseSecurityGroupId",
            string_value=self.db_security_group.security_group_id,
        )
        self.rds_subnet_group = rds.SubnetGroup(
            self,
            "aws-data-wrangler-rds-subnet-group",
            description="RDS Database Subnet Group",
            vpc=self.vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
        )
        self.rds_role = iam.Role(
            self,
            "aws-data-wrangler-rds-role",
            assumed_by=iam.ServicePrincipal("rds.amazonaws.com"),
            inline_policies={
                "S3": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            effect=iam.Effect.ALLOW,
                            actions=[
                                "s3:Get*",
                                "s3:List*",
                                "s3:Put*",
                                "s3:AbortMultipartUpload",
                            ],
                            resources=[
                                self.bucket.bucket_arn,
                                f"{self.bucket.bucket_arn}/*",
                            ],
                        )
                    ]
                ),
            },
        )
        cdk.CfnOutput(self, "DatabasesUsername", value=self.db_username)
        cdk.CfnOutput(
            self,
            "DatabaseSecurityGroupId",
            value=self.db_security_group.security_group_id,
        )

    def _set_catalog_encryption(self) -> None:
        glue.CfnDataCatalogEncryptionSettings(
            self,
            "aws-data-wrangler-catalog-encryption",
            catalog_id=cdk.Aws.ACCOUNT_ID,
            data_catalog_encryption_settings=glue.CfnDataCatalogEncryptionSettings.DataCatalogEncryptionSettingsProperty(  # noqa: E501
                encryption_at_rest=glue.CfnDataCatalogEncryptionSettings.EncryptionAtRestProperty(
                    catalog_encryption_mode="DISABLED",
                ),
                connection_password_encryption=glue.CfnDataCatalogEncryptionSettings.ConnectionPasswordEncryptionProperty(  # noqa: E501
                    kms_key_id=self.key.key_id,
                    return_connection_password_encrypted=True,
                ),
            ),
        )

    def _setup_oracle(self) -> None:
        port = 1521
        database = "ORCL"
        schema = "TEST"
        oracle = rds.DatabaseInstance(
            self,
            "aws-data-wrangler-oracle-instance",
            instance_identifier="oracle-instance-wrangler",
            engine=rds.DatabaseInstanceEngine.oracle_ee(version=rds.OracleEngineVersion.VER_19_0_0_0_2021_04_R1),
            license_model=rds.LicenseModel.BRING_YOUR_OWN_LICENSE,
            instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.SMALL),
            credentials=rds.Credentials.from_password(
                username=self.db_username,
                password=self.db_password_secret,
            ),
            port=port,
            vpc=self.vpc,
            subnet_group=self.rds_subnet_group,
            security_groups=[self.db_security_group],
            publicly_accessible=True,
            s3_import_role=self.rds_role,
            s3_export_role=self.rds_role,
        )
        glue.Connection(
            self,
            "aws-data-wrangler-oracle-glue-connection",
            description="Connect to Oracle.",
            type=glue.ConnectionType.JDBC,
            connection_name="aws-data-wrangler-oracle",
            properties={
                "JDBC_CONNECTION_URL": f"jdbc:oracle:thin://@{oracle.instance_endpoint.hostname}:{port}/{database}",  # noqa: E501
                "USERNAME": self.db_username,
                "PASSWORD": self.db_password,
            },
            subnet=self.vpc.private_subnets[0],
            security_groups=[self.db_security_group],
        )
        secrets.Secret(
            self,
            "aws-data-wrangler-oracle-secret",
            secret_name="aws-data-wrangler/oracle",
            description="Oracle credentials",
            generate_secret_string=secrets.SecretStringGenerator(
                generate_string_key="dummy",
                secret_string_template=json.dumps(
                    {
                        "username": self.db_username,
                        "password": self.db_password,
                        "engine": "oracle",
                        "host": oracle.instance_endpoint.hostname,
                        "port": port,
                        "dbClusterIdentifier": oracle.instance_identifier,
                        "dbname": database,
                    }
                ),
            ),
        )
        cdk.CfnOutput(self, "OracleAddress", value=oracle.instance_endpoint.hostname)
        cdk.CfnOutput(self, "OraclePort", value=str(port))
        cdk.CfnOutput(self, "OracleDatabase", value=database)
        cdk.CfnOutput(self, "OracleSchema", value=schema)
