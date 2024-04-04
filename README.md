# Spryer.AspNetCore.Identity
ASP.NET Core Identity storage providers that use Dapper.

## Packages

| Package | Version | Downloads |
| --- | --- | --- |
| Spryer | [![NuGet](https://img.shields.io/nuget/v/Spryer.svg)](https://www.nuget.org/packages/Spryer) | [![Downloads](https://img.shields.io/nuget/dt/Spryer.svg)](https://www.nuget.org/packages/Spryer) |
| Spryer.AspNetCore.Identity | [![NuGet](https://img.shields.io/nuget/v/Spryer.AspNetCore.Identity.svg)](https://www.nuget.org/packages/Spryer.AspNetCore.Identity) | [![Downloads](https://img.shields.io/nuget/dt/Spryer.AspNetCore.Identity.svg)](https://www.nuget.org/packages/Spryer.AspNetCore.Identity) |
| Spryer.AspNetCore.Identity.SqlServer | [![NuGet](https://img.shields.io/nuget/v/Spryer.AspNetCore.Identity.SqlServer.svg)](https://www.nuget.org/packages/Spryer.AspNetCore.Identity.SqlServer) | [![Downloads](https://img.shields.io/nuget/dt/Spryer.AspNetCore.Identity.SqlServer.svg)](https://www.nuget.org/packages/Spryer.AspNetCore.Identity.SqlServer) |
| Spryer.AspNetCore.Identity.Sqlite | [![NuGet](https://img.shields.io/nuget/v/Spryer.AspNetCore.Identity.Sqlite.svg)](https://www.nuget.org/packages/Spryer.AspNetCore.Identity.Sqlite) | [![Downloads](https://img.shields.io/nuget/dt/Spryer.AspNetCore.Identity.Sqlite.svg)](https://www.nuget.org/packages/Spryer.AspNetCore.Identity.Sqlite) |


## Usage

```csharp
public sealed class AppUser : IdentityUser<Guid>
{
    public AppUser()
    {
        // default Identity UI uses this ctor when registering new users
        this.Id = Guid.NewGuid();
        this.SecurityStamp = Guid.NewGuid().ToString();
    }
}

public sealed class AppRole : IdentityRole<Guid>
{
    public AppRole()
    {
        // default Identity UI uses this ctor when creating new roles
        this.Id = Guid.NewGuid();
    }
}

// Program.cs

var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ??
    throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");

builder.Services.AddScoped(_ => SqlClientFactory.Instance.CreateDataSource(connectionString));

builder.Services
    .AddIdentity<AppUser, AppRole>(options => options.SignIn.RequireConfirmedAccount = true)
    .AddDapperStores(options => 
    {
        options.UseSqlServer();
    })
    .AddDefaultUI()
    .AddDefaultTokenProviders();
```
