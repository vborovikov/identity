namespace Spryer.AspNetCore.Identity;

using System.Data.Common;
using Dapper;

/// <summary>
/// Provides options for the Dapper identity stores.
/// </summary>
public class DapperStoreOptions
{
    /// <summary>
    /// Gets or sets the <see cref="DbDataSource"/> to use for the stores.
    /// </summary>
    internal DbDataSource? DataSource { get; set; }
    /// <summary>
    /// Gets or sets the <see cref="IIdentityQueries"/> to use for the stores.
    /// </summary>
    public IIdentityQueries? Queries { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the key parameter type requires a conversion to <see cref="DbString"/>.
    /// </summary>
    internal bool KeyRequiresDbString { get; set; }
}
