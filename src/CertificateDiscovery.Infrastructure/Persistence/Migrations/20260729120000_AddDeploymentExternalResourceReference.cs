using CertificateDiscovery.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CertificateDiscovery.Infrastructure.Persistence.Migrations;

[DbContext(typeof(CertificateDiscoveryDbContext))]
[Migration("20260729120000_AddDeploymentExternalResourceReference")]
public partial class AddDeploymentExternalResourceReference : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.AddColumn<string>(
            name: "ExternalResourceReference",
            table: "CertificateDeployments",
            type: "TEXT",
            maxLength: 1024,
            nullable: true);
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropColumn(
            name: "ExternalResourceReference",
            table: "CertificateDeployments");
    }
}
