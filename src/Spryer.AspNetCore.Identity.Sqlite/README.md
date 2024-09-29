The ASP.NET Core Identity storage provider that uses SQLite.

## Usage

```csharp
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ??
    throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");

builder.Services.AddSingleton(_ => SqliteFactory.Instance.CreateDataSource(connectionString));

builder.Services
    .AddDefaultIdentity<IdentityUser>()
    .AddDapperStores(options => 
    {
        options.UseSqlite();
    });
```

## Configuration

The database schema scripts can be generated using the following MSBuild properties: `IdentitySqlScriptFile` or `IdentitySqlScriptFolder`.

To generate the main script file:
```xml
<PropertyGroup>
    <IdentitySqlScriptFile>..\db\appdb.sql</IdentitySqlScriptFile>
</PropertyGroup>
```

To generate all the scripts (just `identity.sql` for now):
```xml
<PropertyGroup>
    <IdentitySqlScriptFolder>..\db</IdentitySqlScriptFolder>
</PropertyGroup>
```

The properties are mutually exclusive.