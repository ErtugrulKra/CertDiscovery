using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CertificateDiscovery.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddEnterpriseDnsProviders : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "AccessKeySecretReference",
                table: "DnsProviders",
                type: "TEXT",
                maxLength: 512,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ApiTokenSecretReference",
                table: "DnsProviders",
                type: "TEXT",
                maxLength: 512,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "AwsAuthenticationMode",
                table: "DnsProviders",
                type: "TEXT",
                maxLength: 60,
                nullable: false,
                defaultValue: "DefaultCredentialChain");

            migrationBuilder.AddColumn<string>(
                name: "AzureAuthenticationMode",
                table: "DnsProviders",
                type: "TEXT",
                maxLength: 60,
                nullable: false,
                defaultValue: "DefaultAzureCredential");

            migrationBuilder.AddColumn<string>(
                name: "ClientId",
                table: "DnsProviders",
                type: "TEXT",
                maxLength: 255,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ClientSecretReference",
                table: "DnsProviders",
                type: "TEXT",
                maxLength: 512,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "HostedZoneId",
                table: "DnsProviders",
                type: "TEXT",
                maxLength: 255,
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "LastHealthCheckAtUtc",
                table: "DnsProviders",
                type: "TEXT",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "LastHealthCheckError",
                table: "DnsProviders",
                type: "TEXT",
                maxLength: 2048,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "LastHealthCheckStatus",
                table: "DnsProviders",
                type: "TEXT",
                maxLength: 80,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ManagedIdentityClientId",
                table: "DnsProviders",
                type: "TEXT",
                maxLength: 255,
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "PropagationPollingIntervalSeconds",
                table: "DnsProviders",
                type: "INTEGER",
                nullable: false,
                defaultValue: 10);

            migrationBuilder.AddColumn<int>(
                name: "PropagationTimeoutSeconds",
                table: "DnsProviders",
                type: "INTEGER",
                nullable: false,
                defaultValue: 300);

            migrationBuilder.AddColumn<string>(
                name: "Region",
                table: "DnsProviders",
                type: "TEXT",
                maxLength: 80,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ResourceGroup",
                table: "DnsProviders",
                type: "TEXT",
                maxLength: 255,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "RoleArn",
                table: "DnsProviders",
                type: "TEXT",
                maxLength: 512,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "SecretKeySecretReference",
                table: "DnsProviders",
                type: "TEXT",
                maxLength: 512,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "SessionTokenSecretReference",
                table: "DnsProviders",
                type: "TEXT",
                maxLength: 512,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "SubscriptionId",
                table: "DnsProviders",
                type: "TEXT",
                maxLength: 255,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "TenantId",
                table: "DnsProviders",
                type: "TEXT",
                maxLength: 255,
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "TtlSeconds",
                table: "DnsProviders",
                type: "INTEGER",
                nullable: false,
                defaultValue: 120);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "AccessKeySecretReference",
                table: "DnsProviders");

            migrationBuilder.DropColumn(
                name: "ApiTokenSecretReference",
                table: "DnsProviders");

            migrationBuilder.DropColumn(
                name: "AwsAuthenticationMode",
                table: "DnsProviders");

            migrationBuilder.DropColumn(
                name: "AzureAuthenticationMode",
                table: "DnsProviders");

            migrationBuilder.DropColumn(
                name: "ClientId",
                table: "DnsProviders");

            migrationBuilder.DropColumn(
                name: "ClientSecretReference",
                table: "DnsProviders");

            migrationBuilder.DropColumn(
                name: "HostedZoneId",
                table: "DnsProviders");

            migrationBuilder.DropColumn(
                name: "LastHealthCheckAtUtc",
                table: "DnsProviders");

            migrationBuilder.DropColumn(
                name: "LastHealthCheckError",
                table: "DnsProviders");

            migrationBuilder.DropColumn(
                name: "LastHealthCheckStatus",
                table: "DnsProviders");

            migrationBuilder.DropColumn(
                name: "ManagedIdentityClientId",
                table: "DnsProviders");

            migrationBuilder.DropColumn(
                name: "PropagationPollingIntervalSeconds",
                table: "DnsProviders");

            migrationBuilder.DropColumn(
                name: "PropagationTimeoutSeconds",
                table: "DnsProviders");

            migrationBuilder.DropColumn(
                name: "Region",
                table: "DnsProviders");

            migrationBuilder.DropColumn(
                name: "ResourceGroup",
                table: "DnsProviders");

            migrationBuilder.DropColumn(
                name: "RoleArn",
                table: "DnsProviders");

            migrationBuilder.DropColumn(
                name: "SecretKeySecretReference",
                table: "DnsProviders");

            migrationBuilder.DropColumn(
                name: "SessionTokenSecretReference",
                table: "DnsProviders");

            migrationBuilder.DropColumn(
                name: "SubscriptionId",
                table: "DnsProviders");

            migrationBuilder.DropColumn(
                name: "TenantId",
                table: "DnsProviders");

            migrationBuilder.DropColumn(
                name: "TtlSeconds",
                table: "DnsProviders");
        }
    }
}
