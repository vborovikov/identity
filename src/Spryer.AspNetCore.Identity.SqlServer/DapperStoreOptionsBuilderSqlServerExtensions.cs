namespace Spryer.AspNetCore.Identity.SqlServer;

using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

/// <summary>
/// Provides extension methods to <see cref="OptionsBuilder{DapperStoreOptions}"/> for adding Dapper stores.
/// </summary>
public static class DapperStoreOptionsBuilderSqlServerExtensions
{
    /// <summary>
    /// Configures the Dapper stores to use a SQL Server database.
    /// </summary>
    /// <param name="builder">The <see cref="OptionsBuilder{DapperStoreOptions}"/> to configure.</param>
    /// <returns>The <see cref="OptionsBuilder{DapperStoreOptions}"/> so that additional calls can be chained.</returns>
    public static OptionsBuilder<DapperStoreOptions> UseSqlServer(this OptionsBuilder<DapperStoreOptions> builder)
    {
        builder.Services.TryAddSingleton<IIdentityQueries, SqlServerIdentityQueries>();
        return builder;
    }

    /// <summary>
    /// Configures the Dapper stores to use a SQL Server database with a specific database schema.
    /// </summary>
    /// <param name="builder">The <see cref="OptionsBuilder{DapperStoreOptions}"/> to configure.</param>
    /// <param name="dbSchema">The database schema name to use.</param>
    /// <param name="tableNamePrefix">The table name prefix.</param>
    /// <returns>The <see cref="OptionsBuilder{DapperStoreOptions}"/> so that additional calls can be chained.</returns>
    public static OptionsBuilder<DapperStoreOptions> UseSqlServer(this OptionsBuilder<DapperStoreOptions> builder,
        string dbSchema, string? tableNamePrefix = default)
    {
        builder.Services.TryAddSingleton<IIdentityQueries>(_ => new SqlServerIdentityQueries
        {
            Schema = dbSchema,
            Prefix = tableNamePrefix ?? string.Empty,
        });

        return builder;
    }
}
