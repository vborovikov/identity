The base library for ASP.NET Core Identity storage providers that use Dapper.

# Usage

```csharp
builder.Services
    .AddDefaultIdentity<IdentityUser>()
    .AddDapperStores(options => 
    {
        // Use SQLite (Spryer.AspNetCore.Identity.Sqlite)
        options.UseSqlite();
        // Use SQL Server (Spryer.AspNetCore.Identity.SqlServer)
        options.UseSqlServer();
    });
```
