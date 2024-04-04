The ASP.NET Core Identity storage provider that uses SQLite.

## Usage

```csharp
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ??
    throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");

builder.Services.AddScoped(_ => SqliteFactory.Instance.CreateDataSource(connectionString));

builder.Services
    .AddDefaultIdentity<IdentityUser>()
    .AddDapperStores(options => 
    {
        options.UseSqlite();
    });
```