﻿namespace Spryer.AspNetCore.Identity.SqlServer;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

/// <summary>
/// Provides extension methods to <see cref="OptionsBuilder{DapperStoreOptions}"/> for adding Dapper stores.
/// </summary>
public static class DapperStoreOptionsBuilderExtensions
{
    /// <summary>
    /// Configures the Dapper stores to use a SQL Server database.
    /// </summary>
    /// <param name="builder">The <see cref="OptionsBuilder{DapperStoreOptions}"/> to configure.</param>
    /// <returns>The <see cref="OptionsBuilder{DapperStoreOptions}"/> so that additional calls can be chained.</returns>
    public static OptionsBuilder<DapperStoreOptions> UseSqlServer(this OptionsBuilder<DapperStoreOptions> builder)
    {
        builder.Services.AddScoped<IIdentityQueries, SqlServerIdentityQueries>();
        return builder;
    }
}
