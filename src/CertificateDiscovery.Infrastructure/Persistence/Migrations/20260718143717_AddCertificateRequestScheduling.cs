using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CertificateDiscovery.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddCertificateRequestScheduling : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "LastRenewalRequestId",
                table: "AcmeCertificateRequests",
                type: "TEXT",
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "LastScheduleCheckAtUtc",
                table: "AcmeCertificateRequests",
                type: "TEXT",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "LastScheduleCheckMessage",
                table: "AcmeCertificateRequests",
                type: "TEXT",
                maxLength: 2048,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "LastScheduleCheckStatus",
                table: "AcmeCertificateRequests",
                type: "TEXT",
                maxLength: 120,
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "NextScheduleCheckAtUtc",
                table: "AcmeCertificateRequests",
                type: "TEXT",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "RenewalCronExpression",
                table: "AcmeCertificateRequests",
                type: "TEXT",
                maxLength: 120,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<int>(
                name: "RenewalThresholdDays",
                table: "AcmeCertificateRequests",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<Guid>(
                name: "RenewedFromRequestId",
                table: "AcmeCertificateRequests",
                type: "TEXT",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "ScheduleCheck",
                table: "AcmeCertificateRequests",
                type: "INTEGER",
                nullable: false,
                defaultValue: false);

            migrationBuilder.CreateIndex(
                name: "IX_AcmeCertificateRequests_NextScheduleCheckAtUtc",
                table: "AcmeCertificateRequests",
                column: "NextScheduleCheckAtUtc");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_AcmeCertificateRequests_NextScheduleCheckAtUtc",
                table: "AcmeCertificateRequests");

            migrationBuilder.DropColumn(
                name: "LastRenewalRequestId",
                table: "AcmeCertificateRequests");

            migrationBuilder.DropColumn(
                name: "LastScheduleCheckAtUtc",
                table: "AcmeCertificateRequests");

            migrationBuilder.DropColumn(
                name: "LastScheduleCheckMessage",
                table: "AcmeCertificateRequests");

            migrationBuilder.DropColumn(
                name: "LastScheduleCheckStatus",
                table: "AcmeCertificateRequests");

            migrationBuilder.DropColumn(
                name: "NextScheduleCheckAtUtc",
                table: "AcmeCertificateRequests");

            migrationBuilder.DropColumn(
                name: "RenewalCronExpression",
                table: "AcmeCertificateRequests");

            migrationBuilder.DropColumn(
                name: "RenewalThresholdDays",
                table: "AcmeCertificateRequests");

            migrationBuilder.DropColumn(
                name: "RenewedFromRequestId",
                table: "AcmeCertificateRequests");

            migrationBuilder.DropColumn(
                name: "ScheduleCheck",
                table: "AcmeCertificateRequests");
        }
    }
}
