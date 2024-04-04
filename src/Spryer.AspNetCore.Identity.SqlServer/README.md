The ASP.NET Core Identity storage provider that uses SQL Server.

## Usage

```csharp
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ??
    throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");

builder.Services.AddScoped(_ => SqlClientFactory.Instance.CreateDataSource(connectionString));

builder.Services
    .AddDefaultIdentity<IdentityUser>()
    .AddDapperStores(options => 
    {
        options.UseSqlServer();
    });
```