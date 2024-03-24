namespace Spryer.AspNetCore.Identity.SqlServer;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

public static class DapperStoreOptionsBuilderExtensions
{
    public static OptionsBuilder<DapperStoreOptions> UseSqlServer(this OptionsBuilder<DapperStoreOptions> builder)
    {
        builder.Services.AddScoped<IIdentityQueries, SqlServerIdentityQueries>();
        return builder;
    }
}
