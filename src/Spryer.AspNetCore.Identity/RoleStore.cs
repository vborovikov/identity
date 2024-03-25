namespace Spryer.AspNetCore.Identity;

using System.Data.Common;
using System.Security.Claims;
using System.Threading;
using Dapper;
using Microsoft.AspNetCore.Identity;

/// <summary>
/// Creates a new instance of a persistence store for roles.
/// </summary>
/// <typeparam name="TRole">The type of the class representing a role.</typeparam>
/// <typeparam name="TKey">The type of the primary key for a role.</typeparam>
public class RoleStore<TRole, TKey> : RoleStoreBase<TRole, TKey, IdentityUserRole<TKey>, IdentityRoleClaim<TKey>>
    where TRole : IdentityRole<TKey>
    where TKey : IEquatable<TKey>
{
    private readonly IIdentityQueries queries;
    private readonly DbDataSource _db;

    /// <summary>
    /// Initializes a new instance of the <see cref="RoleStore{TRole, TKey}"/> class.
    /// </summary>
    /// <param name="identityQueries">The SQL queries used to access the store.</param>
    /// <param name="dbDataSource">The <see cref="DbDataSource"/> used to access the store.</param>
    /// <param name="describer">The <see cref="IdentityErrorDescriber"/> used to describe store errors.</param>
    public RoleStore(IIdentityQueries identityQueries, DbDataSource dbDataSource, IdentityErrorDescriber describer) : base(describer)
    {
        this.queries = identityQueries;
        _db = dbDataSource;
    }

    /// <inheritdoc/>
    public override async Task AddClaimAsync(TRole role, Claim claim, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(role);
        ArgumentNullException.ThrowIfNull(claim);

        await using var cnn = await _db.OpenConnectionAsync(cancellationToken);
        await using var tx = await cnn.BeginTransactionAsync(cancellationToken);
        try
        {
            await cnn.ExecuteAsync(this.queries.InsertRoleClaim,
                new { RoleId = role.Id, ClaimType = claim.Type, ClaimValue = claim.Value }, tx);
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

        await using var cnn = await _db.OpenConnectionAsync(cancellationToken);
        await using var tx = await cnn.BeginTransactionAsync(cancellationToken);
        try
        {
            await cnn.ExecuteAsync(this.queries.InsertRole, role, tx);
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

        await using var cnn = await _db.OpenConnectionAsync(cancellationToken);
        await using var tx = await cnn.BeginTransactionAsync(cancellationToken);
        try
        {
            await cnn.ExecuteAsync(this.queries.DeleteRole, new { RoleId = role.Id }, tx);
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

        await using var cnn = await _db.OpenConnectionAsync(cancellationToken);
        var role = await cnn.QuerySingleOrDefaultAsync<TRole>(this.queries.SelectRoleById, new { RoleId = id });
        return role;
    }

    /// <inheritdoc/>
    public override async Task<TRole?> FindByNameAsync(string normalizedName, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(normalizedName);

        await using var cnn = await _db.OpenConnectionAsync(cancellationToken);
        var role = await cnn.QuerySingleOrDefaultAsync<TRole>(this.queries.SelectRoleByName, new { NormalizedName = normalizedName });
        return role;
    }

    /// <inheritdoc/>
    public override async Task<IList<Claim>> GetClaimsAsync(TRole role, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(role);

        await using var cnn = await _db.OpenConnectionAsync(cancellationToken);
        var claims = await cnn.QueryAsync<IdentityRoleClaim<TKey>>(this.queries.SelectRoleClaims, new { RoleId = role.Id });
        return claims.Select(rc => rc.ToClaim()).ToArray();
    }

    /// <inheritdoc/>
    public override async Task RemoveClaimAsync(TRole role, Claim claim, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(role);
        ArgumentNullException.ThrowIfNull(claim);

        await using var cnn = await _db.OpenConnectionAsync(cancellationToken);
        await using var tx = await cnn.BeginTransactionAsync(cancellationToken);
        try
        {
            await cnn.ExecuteAsync(this.queries.DeleteRoleClaim,
                new { RoleId = role.Id, ClaimType = claim.Type, ClaimValue = claim.Value }, tx);
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

        await using var cnn = await _db.OpenConnectionAsync(cancellationToken);
        await using var tx = await cnn.BeginTransactionAsync(cancellationToken);
        try
        {
            role.ConcurrencyStamp = Guid.NewGuid().ToString();
            await cnn.ExecuteAsync(this.queries.UpdateRole, role, tx);
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
