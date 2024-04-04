namespace Spryer.AspNetCore.Identity.Sqlite;

using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

/// <summary>
/// Provides extension methods to <see cref="OptionsBuilder{DapperStoreOptions}"/> for adding Dapper stores.
/// </summary>
public static class DapperStoreOptionsBuilderSqliteExtensions
{
    /// <summary>
    /// Configures the Dapper stores to use a SQLite database.
    /// </summary>
    /// <param name="builder">The <see cref="OptionsBuilder{DapperStoreOptions}"/> to configure.</param>
    /// <returns>The <see cref="OptionsBuilder{DapperStoreOptions}"/> so that additional calls can be chained.</returns>
    public static OptionsBuilder<DapperStoreOptions> UseSqlite(this OptionsBuilder<DapperStoreOptions> builder)
    {
        builder.Services.TryAddSingleton<IIdentityQueries, SqliteIdentityQueries>();
        return builder;
    }
}
