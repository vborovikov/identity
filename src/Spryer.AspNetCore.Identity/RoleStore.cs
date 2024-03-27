namespace Spryer.AspNetCore.Identity;

using System.Data.Common;
using System.Security.Claims;
using System.Threading;
using Dapper;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

/// <summary>
/// Creates a new instance of a persistence store for roles.
/// </summary>
/// <typeparam name="TRole">The type of the class representing a role.</typeparam>
/// <typeparam name="TKey">The type of the primary key for a role.</typeparam>
public class RoleStore<TRole, TKey> : RoleStoreBase<TRole, TKey, IdentityUserRole<TKey>, IdentityRoleClaim<TKey>>
    where TRole : IdentityRole<TKey>
    where TKey : IEquatable<TKey>
{
    private readonly DapperStoreOptions options;
    private readonly IIdentityQueries queries;
    private readonly DbDataSource db;

    /// <summary>
    /// Initializes a new instance of the <see cref="RoleStore{TRole, TKey}"/> class.
    /// </summary>
    /// <param name="options">The store options.</param>
    /// <param name="identityQueries">The SQL queries used to access the store.</param>
    /// <param name="dbDataSource">The <see cref="DbDataSource"/> used to access the store.</param>
    /// <param name="describer">The <see cref="IdentityErrorDescriber"/> used to describe store errors.</param>
    public RoleStore(IOptions<DapperStoreOptions> options, IIdentityQueries identityQueries, DbDataSource dbDataSource, IdentityErrorDescriber describer) : base(describer)
    {
        ArgumentNullException.ThrowIfNull(identityQueries);
        ArgumentNullException.ThrowIfNull(dbDataSource);
        this.options = options.Value;
        this.queries = identityQueries;
        this.db = dbDataSource;
    }

    /// <inheritdoc/>
    public override async Task AddClaimAsync(TRole role, Claim claim, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(role);
        ArgumentNullException.ThrowIfNull(claim);

        await using var cnn = await this.db.OpenConnectionAsync(cancellationToken);
        await using var tx = await cnn.BeginTransactionAsync(cancellationToken);
        try
        {
            await cnn.ExecuteAsync(this.queries.InsertRoleClaim,
                this.options.KeyRequiresDbString ?
                new
                {
                    RoleId = ConvertIdToDbString(role.Id),
                    ClaimType = claim.Type.AsVarChar(128),
                    ClaimValue = claim.Value.AsVarChar(128)
                } :
                new
                {
                    RoleId = role.Id,
                    ClaimType = claim.Type.AsVarChar(128),
                    ClaimValue = claim.Value.AsVarChar(128)
                }, tx);
            await tx.CommitAsync(cancellationToken);
        }
        catch (Exception x) when (x is not OperationCanceledException)
        {
            await tx.RollbackAsync(cancellationToken);
        }
    }

    /// <inheritdoc/>
    public override async Task<IdentityResult> CreateAsync(TRole role, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(role);

        await using var cnn = await this.db.OpenConnectionAsync(cancellationToken);
        await using var tx = await cnn.BeginTransactionAsync(cancellationToken);
        try
        {
            await cnn.ExecuteAsync(this.queries.InsertRole,
                this.options.KeyRequiresDbString ?
                new
                {
                    Id = ConvertIdToDbString(role.Id),
                    Name = role.Name.AsVarChar(128),
                    NormalizedName = role.NormalizedName.AsVarChar(128),
                    ConcurrencyStamp = role.ConcurrencyStamp.AsVarChar(128),
                } :
                new
                {
                    RoleId = role.Id,
                    Name = role.Name.AsVarChar(128),
                    NormalizedName = role.NormalizedName.AsVarChar(128),
                    ConcurrencyStamp = role.ConcurrencyStamp.AsVarChar(128),
                }, tx);

            await tx.CommitAsync(cancellationToken);
            return IdentityResult.Success;
        }
        catch (Exception x) when (x is not OperationCanceledException)
        {
            await tx.RollbackAsync(cancellationToken);
            return IdentityResult.Failed(this.ErrorDescriber.DefaultError());
        }
    }

    /// <inheritdoc/>
    public override async Task<IdentityResult> DeleteAsync(TRole role, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(role);

        await using var cnn = await this.db.OpenConnectionAsync(cancellationToken);
        await using var tx = await cnn.BeginTransactionAsync(cancellationToken);
        try
        {
            await cnn.ExecuteAsync(this.queries.DeleteRole,
                this.options.KeyRequiresDbString ?
                new
                {
                    RoleId = ConvertIdToDbString(role.Id)
                } :
                new
                {
                    RoleId = role.Id
                }, tx);

            await tx.CommitAsync(cancellationToken);
            return IdentityResult.Success;
        }
        catch (Exception x) when (x is not OperationCanceledException)
        {
            await tx.RollbackAsync(cancellationToken);
            return IdentityResult.Failed(this.ErrorDescriber.DefaultError());
        }
    }

    /// <inheritdoc/>
    public override async Task<TRole?> FindByIdAsync(string id, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(id);

        await using var cnn = await this.db.OpenConnectionAsync(cancellationToken);
        var roleId = ConvertIdFromString(id);
        var role = await cnn.QuerySingleOrDefaultAsync<TRole>(this.queries.SelectRoleById,
            this.options.KeyRequiresDbString ?
            new
            {
                RoleId = ConvertIdToDbString(roleId!)
            } :
            new
            {
                RoleId = roleId
            });
        return role;
    }

    /// <inheritdoc/>
    public override async Task<TRole?> FindByNameAsync(string normalizedName, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(normalizedName);

        await using var cnn = await this.db.OpenConnectionAsync(cancellationToken);
        var role = await cnn.QuerySingleOrDefaultAsync<TRole>(this.queries.SelectRoleByName,
            new
            {
                NormalizedName = normalizedName.AsVarChar(128)
            });
        return role;
    }

    /// <inheritdoc/>
    public override async Task<IList<Claim>> GetClaimsAsync(TRole role, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(role);

        await using var cnn = await this.db.OpenConnectionAsync(cancellationToken);
        var claims = await cnn.QueryAsync<IdentityRoleClaim<TKey>>(this.queries.SelectRoleClaims,
            this.options.KeyRequiresDbString ?
            new
            {
                RoleId = ConvertIdToDbString(role.Id)
            } :
            new
            {
                RoleId = role.Id
            });
        return claims.Select(rc => rc.ToClaim()).ToArray();
    }

    /// <inheritdoc/>
    public override async Task RemoveClaimAsync(TRole role, Claim claim, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(role);
        ArgumentNullException.ThrowIfNull(claim);

        await using var cnn = await this.db.OpenConnectionAsync(cancellationToken);
        await using var tx = await cnn.BeginTransactionAsync(cancellationToken);
        try
        {
            await cnn.ExecuteAsync(this.queries.DeleteRoleClaim,
                this.options.KeyRequiresDbString ?
                new
                {
                    RoleId = ConvertIdToDbString(role.Id),
                    ClaimType = claim.Type.AsVarChar(128),
                    ClaimValue = claim.Value.AsVarChar(128)
                } :
                new
                {
                    RoleId = role.Id,
                    ClaimType = claim.Type.AsVarChar(128),
                    ClaimValue = claim.Value.AsVarChar(128)
                }, tx);
            await tx.CommitAsync(cancellationToken);
        }
        catch (Exception x) when (x is not OperationCanceledException)
        {
            await tx.RollbackAsync(cancellationToken);
        }
    }

    /// <inheritdoc/>
    public override async Task<IdentityResult> UpdateAsync(TRole role, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(role);

        await using var cnn = await this.db.OpenConnectionAsync(cancellationToken);
        await using var tx = await cnn.BeginTransactionAsync(cancellationToken);
        try
        {
            role.ConcurrencyStamp = Guid.NewGuid().ToString();

            await cnn.ExecuteAsync(this.queries.UpdateRole,
                this.options.KeyRequiresDbString ?
                new
                {
                    Id = ConvertIdToDbString(role.Id),
                    Name = role.Name.AsVarChar(128),
                    NormalizedName = role.NormalizedName.AsVarChar(128),
                    ConcurrencyStamp = role.ConcurrencyStamp.AsVarChar(128),
                } :
                new
                {
                    RoleId = role.Id,
                    Name = role.Name.AsVarChar(128),
                    NormalizedName = role.NormalizedName.AsVarChar(128),
                    ConcurrencyStamp = role.ConcurrencyStamp.AsVarChar(128),
                }, tx);

            await tx.CommitAsync(cancellationToken);
            return IdentityResult.Success;
        }
        catch (Exception x) when (x is not OperationCanceledException)
        {
            await tx.RollbackAsync(cancellationToken);
            return IdentityResult.Failed(this.ErrorDescriber.DefaultError());
        }
    }
}
