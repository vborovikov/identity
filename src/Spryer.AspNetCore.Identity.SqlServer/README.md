The ASP.NET Core Identity storage provider that uses SQL Server.

## Usage

```csharp
builder.Services
    .AddDefaultIdentity<IdentityUser>()
    .AddDapperStores(options => 
    {
        options.UseSqlServer();
    });
```