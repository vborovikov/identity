﻿namespace Spryer.AspNetCore.Identity;

using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Dapper;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

/// <summary>
/// Creates a new instance of a persistence store for the specified user type.
/// </summary>
/// <typeparam name="TUser">The type representing a user.</typeparam>
public class UserOnlyStore<TUser> : UserOnlyStore<TUser, string> where TUser : IdentityUser<string>, new()
{
    /// <summary>
    /// Constructs a new instance of <see cref="UserOnlyStore{TUser}"/>.
    /// </summary>
    /// <param name="options">The store options.</param>
    /// <param name="describer">The <see cref="IdentityErrorDescriber"/>.</param>
    public UserOnlyStore(IOptions<DapperStoreOptions> options, IdentityErrorDescriber? describer = null)
        : base(options, describer) { }
}

/// <summary>
/// Represents a new instance of a persistence store for the specified user and role types.
/// </summary>
/// <typeparam name="TUser">The type representing a user.</typeparam>
/// <typeparam name="TKey">The type of the primary key for a role.</typeparam>
public class UserOnlyStore<TUser, TKey> : UserOnlyStore<TUser, TKey, IdentityUserClaim<TKey>, IdentityUserLogin<TKey>, IdentityUserToken<TKey>>
    where TUser : IdentityUser<TKey>
    where TKey : IEquatable<TKey>
{
    /// <summary>
    /// Constructs a new instance of <see cref="UserOnlyStore{TUser, TKey}"/>.
    /// </summary>
    /// <param name="options">The store options.</param>
    /// <param name="describer">The <see cref="IdentityErrorDescriber"/>.</param>
    public UserOnlyStore(IOptions<DapperStoreOptions> options, IdentityErrorDescriber? describer = null)
        : base(options, describer) { }
}

/// <summary>
/// Represents a new instance of a persistence store for the specified user and role types.
/// </summary>
/// <typeparam name="TUser">The type representing a user.</typeparam>
/// <typeparam name="TKey">The type of the primary key for a role.</typeparam>
/// <typeparam name="TUserClaim">The type representing a claim.</typeparam>
/// <typeparam name="TUserLogin">The type representing a user external login.</typeparam>
/// <typeparam name="TUserToken">The type representing a user token.</typeparam>
public class UserOnlyStore<TUser, TKey, TUserClaim, TUserLogin, TUserToken> :
    UserStoreBase<TUser, TKey, TUserClaim, TUserLogin, TUserToken>,
    IUserLoginStore<TUser>,
    IUserClaimStore<TUser>,
    IUserPasswordStore<TUser>,
    IUserSecurityStampStore<TUser>,
    IUserEmailStore<TUser>,
    IUserLockoutStore<TUser>,
    IUserPhoneNumberStore<TUser>,
    IUserTwoFactorStore<TUser>,
    IUserAuthenticationTokenStore<TUser>,
    IUserAuthenticatorKeyStore<TUser>,
    IUserTwoFactorRecoveryCodeStore<TUser>,
    IProtectedUserStore<TUser>
    where TUser : IdentityUser<TKey>
    where TKey : IEquatable<TKey>
    where TUserClaim : IdentityUserClaim<TKey>, new()
    where TUserLogin : IdentityUserLogin<TKey>, new()
    where TUserToken : IdentityUserToken<TKey>, new()
{
    private readonly IIdentityStoreQueries queries;

    /// <summary>
    /// Creates a new instance of the store.
    /// </summary>
    /// <param name="options">The store options.</param>
    /// <param name="describer">The <see cref="IdentityErrorDescriber"/> used to describe store errors.</param>
    public UserOnlyStore(IOptions<DapperStoreOptions> options, IdentityErrorDescriber? describer = null)
        : base(options.Value, describer ?? new())
    {
        ArgumentNullException.ThrowIfNull(options.Value.StoreQueries);
        this.queries = options.Value.StoreQueries;
    }

    /// <summary>
    /// Creates the specified <paramref name="user"/> in the user store.
    /// </summary>
    /// <param name="user">The user to create.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/> of the creation operation.</returns>
    public override async Task<IdentityResult> CreateAsync(TUser user, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(user);

        await using var cnn = await OpenDbConnectionAsync(cancellationToken);
        await using var tx = await cnn.BeginTransactionAsync(cancellationToken);
        try
        {
            await cnn.ExecuteAsync(this.queries.InsertUser,
                this.KeyRequiresDbString ?
                new
                {
                    Id = ConvertIdToDbString(user.Id),
                    UserName = user.UserName.AsNVarChar(256),
                    NormalizedUserName = user.NormalizedUserName.AsNVarChar(256),
                    Email = user.Email.AsNVarChar(256),
                    NormalizedEmail = user.NormalizedEmail.AsVarChar(256),
                    EmailConfirmed = user.EmailConfirmed,
                    PasswordHash = user.PasswordHash.AsVarChar(128),
                    SecurityStamp = user.SecurityStamp.AsVarChar(128),
                    ConcurrencyStamp = user.ConcurrencyStamp.AsVarChar(128),
                    PhoneNumber = user.PhoneNumber.AsNVarChar(128),
                    PhoneNumberConfirmed = user.PhoneNumberConfirmed,
                    TwoFactorEnabled = user.TwoFactorEnabled,
                    LockoutEnd = user.LockoutEnd,
                    LockoutEnabled = user.LockoutEnabled,
                    AccessFailedCount = user.AccessFailedCount,
                } :
                new
                {
                    Id = user.Id,
                    UserName = user.UserName.AsNVarChar(256),
                    NormalizedUserName = user.NormalizedUserName.AsNVarChar(256),
                    Email = user.Email.AsNVarChar(256),
                    NormalizedEmail = user.NormalizedEmail.AsVarChar(256),
                    EmailConfirmed = user.EmailConfirmed,
                    PasswordHash = user.PasswordHash.AsVarChar(128),
                    SecurityStamp = user.SecurityStamp.AsVarChar(128),
                    ConcurrencyStamp = user.ConcurrencyStamp.AsVarChar(128),
                    PhoneNumber = user.PhoneNumber.AsNVarChar(128),
                    PhoneNumberConfirmed = user.PhoneNumberConfirmed,
                    TwoFactorEnabled = user.TwoFactorEnabled,
                    LockoutEnd = user.LockoutEnd,
                    LockoutEnabled = user.LockoutEnabled,
                    AccessFailedCount = user.AccessFailedCount,
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

    /// <summary>
    /// Updates the specified <paramref name="user"/> in the user store.
    /// </summary>
    /// <param name="user">The user to update.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/> of the update operation.</returns>
    public override async Task<IdentityResult> UpdateAsync(TUser user, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(user);

        await using var cnn = await OpenDbConnectionAsync(cancellationToken);
        await using var tx = await cnn.BeginTransactionAsync(cancellationToken);
        try
        {
            user.ConcurrencyStamp = Guid.NewGuid().ToString();

            await cnn.ExecuteAsync(this.queries.UpdateUser,
                this.KeyRequiresDbString ?
                new
                {
                    Id = ConvertIdToDbString(user.Id),
                    UserName = user.UserName.AsNVarChar(256),
                    NormalizedUserName = user.NormalizedUserName.AsNVarChar(256),
                    Email = user.Email.AsNVarChar(256),
                    NormalizedEmail = user.NormalizedEmail.AsVarChar(256),
                    EmailConfirmed = user.EmailConfirmed,
                    PasswordHash = user.PasswordHash.AsVarChar(128),
                    SecurityStamp = user.SecurityStamp.AsVarChar(128),
                    ConcurrencyStamp = user.ConcurrencyStamp.AsVarChar(128),
                    PhoneNumber = user.PhoneNumber.AsNVarChar(128),
                    PhoneNumberConfirmed = user.PhoneNumberConfirmed,
                    TwoFactorEnabled = user.TwoFactorEnabled,
                    LockoutEnd = user.LockoutEnd,
                    LockoutEnabled = user.LockoutEnabled,
                    AccessFailedCount = user.AccessFailedCount,
                } :
                new
                {
                    Id = user.Id,
                    UserName = user.UserName.AsNVarChar(256),
                    NormalizedUserName = user.NormalizedUserName.AsNVarChar(256),
                    Email = user.Email.AsNVarChar(256),
                    NormalizedEmail = user.NormalizedEmail.AsVarChar(256),
                    EmailConfirmed = user.EmailConfirmed,
                    PasswordHash = user.PasswordHash.AsVarChar(128),
                    SecurityStamp = user.SecurityStamp.AsVarChar(128),
                    ConcurrencyStamp = user.ConcurrencyStamp.AsVarChar(128),
                    PhoneNumber = user.PhoneNumber.AsNVarChar(128),
                    PhoneNumberConfirmed = user.PhoneNumberConfirmed,
                    TwoFactorEnabled = user.TwoFactorEnabled,
                    LockoutEnd = user.LockoutEnd,
                    LockoutEnabled = user.LockoutEnabled,
                    AccessFailedCount = user.AccessFailedCount,
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

    /// <summary>
    /// Deletes the specified <paramref name="user"/> from the user store.
    /// </summary>
    /// <param name="user">The user to delete.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/> of the update operation.</returns>
    public override async Task<IdentityResult> DeleteAsync(TUser user, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(user);

        await using var cnn = await OpenDbConnectionAsync(cancellationToken);
        await using var tx = await cnn.BeginTransactionAsync(cancellationToken);
        try
        {
            await cnn.ExecuteAsync(this.queries.DeleteUser,
                this.KeyRequiresDbString ?
                new
                {
                    UserId = ConvertIdToDbString(user.Id)
                } :
                new
                {
                    UserId = user.Id
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

    /// <summary>
    /// Finds and returns a user, if any, who has the specified <paramref name="userId"/>.
    /// </summary>
    /// <param name="userId">The user ID to search for.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>
    /// The <see cref="Task"/> that represents the asynchronous operation, containing the user matching the specified <paramref name="userId"/> if it exists.
    /// </returns>
    public override Task<TUser?> FindByIdAsync(string userId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        return FindUserAsync(ConvertIdFromString(userId)!, cancellationToken);
    }

    /// <summary>
    /// Finds and returns a user, if any, who has the specified normalized user name.
    /// </summary>
    /// <param name="normalizedUserName">The normalized user name to search for.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>
    /// The <see cref="Task"/> that represents the asynchronous operation, containing the user matching the specified <paramref name="normalizedUserName"/> if it exists.
    /// </returns>
    public override async Task<TUser?> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();

        await using var cnn = await OpenDbConnectionAsync(cancellationToken);
        var user = await cnn.QuerySingleOrDefaultAsync<TUser>(this.queries.SelectUserByName,
            new { NormalizedUserName = normalizedUserName.AsNVarChar(256) });
        return user;
    }

    /// <summary>
    /// Return a user with the matching userId if it exists.
    /// </summary>
    /// <param name="userId">The user's id.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The user if it exists.</returns>
    protected override async Task<TUser?> FindUserAsync(TKey userId, CancellationToken cancellationToken)
    {
        await using var cnn = await OpenDbConnectionAsync(cancellationToken);
        var user = await cnn.QuerySingleOrDefaultAsync<TUser>(this.queries.SelectUser,
            this.KeyRequiresDbString ?
            new
            {
                UserId = ConvertIdToDbString(userId)
            } :
            new
            {
                UserId = userId
            });
        return user;
    }

    /// <summary>
    /// Return a user login with the matching userId, provider, providerKey if it exists.
    /// </summary>
    /// <param name="userId">The user's id.</param>
    /// <param name="loginProvider">The login provider name.</param>
    /// <param name="providerKey">The key provided by the <paramref name="loginProvider"/> to identify a user.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The user login if it exists.</returns>
    protected override async Task<TUserLogin?> FindUserLoginAsync(TKey userId, string loginProvider, string providerKey, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(loginProvider);
        ArgumentNullException.ThrowIfNull(providerKey);

        await using var cnn = await OpenDbConnectionAsync(cancellationToken);
        var login = await cnn.QuerySingleOrDefaultAsync<TUserLogin>(this.queries.SelectUserLoginByUser,
            this.KeyRequiresDbString ?
            new
            {
                UserId = ConvertIdToDbString(userId),
                LoginProvider = loginProvider.AsVarChar(128),
                ProviderKey = providerKey.AsVarChar(128)
            } :
            new
            {
                UserId = userId,
                LoginProvider = loginProvider.AsVarChar(128),
                ProviderKey = providerKey.AsVarChar(128)
            });
        return login;
    }

    /// <summary>
    /// Return a user login with  provider, providerKey if it exists.
    /// </summary>
    /// <param name="loginProvider">The login provider name.</param>
    /// <param name="providerKey">The key provided by the <paramref name="loginProvider"/> to identify a user.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The user login if it exists.</returns>
    protected override async Task<TUserLogin?> FindUserLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(loginProvider);
        ArgumentNullException.ThrowIfNull(providerKey);

        await using var cnn = await OpenDbConnectionAsync(cancellationToken);
        var login = await cnn.QuerySingleOrDefaultAsync<TUserLogin>(this.queries.SelectUserLoginByProvider,
            new
            {
                LoginProvider = loginProvider.AsVarChar(128),
                ProviderKey = providerKey.AsVarChar(128)
            });
        return login;
    }

    /// <summary>
    /// Get the claims associated with the specified <paramref name="user"/> as an asynchronous operation.
    /// </summary>
    /// <param name="user">The user whose claims should be retrieved.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A <see cref="Task{TResult}"/> that contains the claims granted to a user.</returns>
    public override async Task<IList<Claim>> GetClaimsAsync(TUser user, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(user);

        await using var cnn = await OpenDbConnectionAsync(cancellationToken);
        var userClaims = await cnn.QueryAsync<TUserClaim>(this.queries.SelectUserClaims,
            this.KeyRequiresDbString ?
            new
            {
                UserId = ConvertIdToDbString(user.Id)
            } :
            new
            {
                UserId = user.Id
            });
        return userClaims.Select(uc => uc.ToClaim()).ToArray();
    }

    /// <summary>
    /// Adds the <paramref name="claims"/> given to the specified <paramref name="user"/>.
    /// </summary>
    /// <param name="user">The user to add the claim to.</param>
    /// <param name="claims">The claim to add to the user.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
    public override async Task AddClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(claims);

        await using var cnn = await OpenDbConnectionAsync(cancellationToken);
        await using var tx = await cnn.BeginTransactionAsync(cancellationToken);
        try
        {
            foreach (var claim in claims)
            {
                await cnn.ExecuteAsync(this.queries.InsertUserClaim,
                    this.KeyRequiresDbString ?
                    new
                    {
                        UserId = ConvertIdToDbString(user.Id),
                        ClaimType = claim.Type.AsVarChar(128),
                        ClaimValue = claim.Value.AsVarChar(128),
                    } :
                    new
                    {
                        UserId = user.Id,
                        ClaimType = claim.Type.AsVarChar(128),
                        ClaimValue = claim.Value.AsVarChar(128),
                    }, tx);
            }
            await tx.CommitAsync(cancellationToken);
        }
        catch (Exception x) when (x is not OperationCanceledException)
        {
            await tx.RollbackAsync(cancellationToken);
        }
    }

    /// <summary>
    /// Replaces the <paramref name="claim"/> on the specified <paramref name="user"/>, with the <paramref name="newClaim"/>.
    /// </summary>
    /// <param name="user">The user to replace the claim on.</param>
    /// <param name="claim">The claim replace.</param>
    /// <param name="newClaim">The new claim replacing the <paramref name="claim"/>.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
    public override async Task ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(claim);
        ArgumentNullException.ThrowIfNull(newClaim);

        await using var cnn = await OpenDbConnectionAsync(cancellationToken);
        await using var tx = await cnn.BeginTransactionAsync(cancellationToken);
        try
        {
            await cnn.ExecuteAsync(this.queries.UpdateUserClaim,
                this.KeyRequiresDbString ?
                new
                {
                    UserId = ConvertIdToDbString(user.Id),
                    OldClaimType = claim.Type.AsVarChar(128),
                    OldClaimValue = claim.Value.AsVarChar(128),
                    NewClaimType = newClaim.Type.AsVarChar(128),
                    NewClaimValue = newClaim.Value.AsVarChar(128),
                } :
                new
                {
                    UserId = user.Id,
                    OldClaimType = claim.Type.AsVarChar(128),
                    OldClaimValue = claim.Value.AsVarChar(128),
                    NewClaimType = newClaim.Type.AsVarChar(128),
                    NewClaimValue = newClaim.Value.AsVarChar(128),
                }, tx);
            await tx.CommitAsync(cancellationToken);
        }
        catch (Exception x) when (x is not OperationCanceledException)
        {
            await tx.RollbackAsync(cancellationToken);
        }
    }

    /// <summary>
    /// Removes the <paramref name="claims"/> given from the specified <paramref name="user"/>.
    /// </summary>
    /// <param name="user">The user to remove the claims from.</param>
    /// <param name="claims">The claim to remove.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
    public override async Task RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(claims);

        await using var cnn = await OpenDbConnectionAsync(cancellationToken);
        await using var tx = await cnn.BeginTransactionAsync(cancellationToken);
        try
        {
            foreach (var claim in claims)
            {
                await cnn.ExecuteAsync(this.queries.DeleteUserClaim,
                    this.KeyRequiresDbString ?
                    new
                    {
                        UserId = ConvertIdToDbString(user.Id),
                        ClaimType = claim.Type.AsVarChar(128),
                        ClaimValue = claim.Value.AsVarChar(128),
                    } :
                    new
                    {
                        UserId = user.Id,
                        ClaimType = claim.Type.AsVarChar(128),
                        ClaimValue = claim.Value.AsVarChar(128),
                    }, tx);
            }
            await tx.CommitAsync(cancellationToken);
        }
        catch (Exception x) when (x is not OperationCanceledException)
        {
            await tx.RollbackAsync(cancellationToken);
        }
    }

    /// <summary>
    /// Adds the <paramref name="login"/> given to the specified <paramref name="user"/>.
    /// </summary>
    /// <param name="user">The user to add the login to.</param>
    /// <param name="login">The login to add to the user.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
    public override async Task AddLoginAsync(TUser user, UserLoginInfo login, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(login);

        await using var cnn = await OpenDbConnectionAsync(cancellationToken);
        await using var tx = await cnn.BeginTransactionAsync(cancellationToken);
        try
        {
            await cnn.ExecuteAsync(this.queries.InsertUserLogin,
                this.KeyRequiresDbString ?
                new
                {
                    UserId = ConvertIdToDbString(user.Id),
                    LoginProvider = login.LoginProvider.AsVarChar(128),
                    ProviderKey = login.ProviderKey.AsVarChar(128),
                    ProviderDisplayName = login.ProviderDisplayName.AsNVarChar(128),
                } :
                new
                {
                    UserId = user.Id,
                    LoginProvider = login.LoginProvider.AsVarChar(128),
                    ProviderKey = login.ProviderKey.AsVarChar(128),
                    ProviderDisplayName = login.ProviderDisplayName.AsNVarChar(128),
                }, tx);
            await tx.CommitAsync(cancellationToken);
        }
        catch (Exception x) when (x is not OperationCanceledException)
        {
            await tx.RollbackAsync(cancellationToken);
        }
    }

    /// <summary>
    /// Removes the <paramref name="loginProvider"/> given from the specified <paramref name="user"/>.
    /// </summary>
    /// <param name="user">The user to remove the login from.</param>
    /// <param name="loginProvider">The login to remove from the user.</param>
    /// <param name="providerKey">The key provided by the <paramref name="loginProvider"/> to identify a user.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
    public override async Task RemoveLoginAsync(TUser user, string loginProvider, string providerKey,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(user);

        await using var cnn = await OpenDbConnectionAsync(cancellationToken);
        await using var tx = await cnn.BeginTransactionAsync(cancellationToken);
        try
        {
            await cnn.ExecuteAsync(this.queries.DeleteUserLogin,
                this.KeyRequiresDbString ?
                new
                {
                    UserId = ConvertIdToDbString(user.Id),
                    LoginProvider = loginProvider.AsVarChar(128),
                    ProviderKey = providerKey.AsVarChar(128)
                } :
                new
                {
                    UserId = user.Id,
                    LoginProvider = loginProvider.AsVarChar(128),
                    ProviderKey = providerKey.AsVarChar(128)
                }, tx);
            await tx.CommitAsync(cancellationToken);
        }
        catch (Exception x) when (x is not OperationCanceledException)
        {
            await tx.RollbackAsync(cancellationToken);
        }
    }

    /// <summary>
    /// Retrieves the associated logins for the specified <param ref="user"/>.
    /// </summary>
    /// <param name="user">The user whose associated logins to retrieve.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>
    /// The <see cref="Task"/> for the asynchronous operation, containing a list of <see cref="UserLoginInfo"/> for the specified <paramref name="user"/>, if any.
    /// </returns>
    public override async Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(user);

        await using var cnn = await OpenDbConnectionAsync(cancellationToken);
        var userLogins = await cnn.QueryAsync<TUserLogin>(this.queries.SelectUserLogins,
            this.KeyRequiresDbString ?
            new
            {
                UserId = ConvertIdToDbString(user.Id)
            } :
            new
            {
                UserId = user.Id
            });
        return userLogins.Select(ul => new UserLoginInfo(ul.LoginProvider, ul.ProviderKey, ul.ProviderDisplayName)).ToArray();
    }

    /// <summary>
    /// Retrieves the user associated with the specified login provider and login provider key.
    /// </summary>
    /// <param name="loginProvider">The login provider who provided the <paramref name="providerKey"/>.</param>
    /// <param name="providerKey">The key provided by the <paramref name="loginProvider"/> to identify a user.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>
    /// The <see cref="Task"/> for the asynchronous operation, containing the user, if any which matched the specified login provider and key.
    /// </returns>
    public override async Task<TUser?> FindByLoginAsync(string loginProvider, string providerKey,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        var userLogin = await FindUserLoginAsync(loginProvider, providerKey, cancellationToken);
        if (userLogin != null)
        {
            return await FindUserAsync(userLogin.UserId, cancellationToken);
        }
        return null;
    }

    /// <summary>
    /// Gets the user, if any, associated with the specified, normalized email address.
    /// </summary>
    /// <param name="normalizedEmail">The normalized email address to return the user for.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>
    /// The task object containing the results of the asynchronous lookup operation, the user if any associated with the specified normalized email address.
    /// </returns>
    public override async Task<TUser?> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();

        await using var cnn = await OpenDbConnectionAsync(cancellationToken);
        var user = await cnn.QuerySingleOrDefaultAsync<TUser>(this.queries.SelectUserByEmail,
            new { NormalizedEmail = normalizedEmail.AsVarChar(256) });
        return user;
    }

    /// <summary>
    /// Retrieves all users with the specified claim.
    /// </summary>
    /// <param name="claim">The claim whose users should be retrieved.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>
    /// The <see cref="Task"/> contains a list of users, if any, that contain the specified claim.
    /// </returns>
    public override async Task<IList<TUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(claim);

        await using var cnn = await OpenDbConnectionAsync(cancellationToken);
        var users = await cnn.QueryAsync<TUser>(this.queries.SelectUsersByClaim,
            new
            {
                ClaimValue = claim.Value.AsVarChar(128),
                ClaimType = claim.Type.AsVarChar(128)
            });
        return users.ToArray();
    }

    /// <summary>
    /// Find a user token if it exists.
    /// </summary>
    /// <param name="user">The token owner.</param>
    /// <param name="loginProvider">The login provider for the token.</param>
    /// <param name="name">The name of the token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The user token if it exists.</returns>
    protected override async Task<TUserToken?> FindTokenAsync(TUser user, string loginProvider, string name, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(loginProvider);
        ArgumentNullException.ThrowIfNull(name);

        await using var cnn = await OpenDbConnectionAsync(cancellationToken);
        var token = await cnn.QuerySingleOrDefaultAsync<TUserToken>(this.queries.SelectUserToken,
            this.KeyRequiresDbString ?
            new
            {
                UserId = ConvertIdToDbString(user.Id),
                LoginProvider = loginProvider.AsVarChar(128),
                TokenName = name.AsVarChar(128)
            } :
            new
            {
                UserId = user.Id,
                LoginProvider = loginProvider.AsVarChar(128),
                TokenName = name.AsVarChar(128)
            });
        return token;
    }

    /// <summary>
    /// Add a new user token.
    /// </summary>
    /// <param name="token">The token to be added.</param>
    /// <returns></returns>
    protected override async Task AddUserTokenAsync(TUserToken token)
    {
        ArgumentNullException.ThrowIfNull(token);

        await using var cnn = await OpenDbConnectionAsync(default);
        await using var tx = await cnn.BeginTransactionAsync(default);
        try
        {
            await cnn.ExecuteAsync(this.queries.InsertUserToken,
                this.KeyRequiresDbString ?
                new
                {
                    UserId = ConvertIdToDbString(token.UserId),
                    LoginProvider = token.LoginProvider.AsVarChar(128),
                    Name = token.Name.AsVarChar(128),
                    Value = token.Value.AsVarChar(128),
                } :
                new
                {
                    UserId = token.UserId,
                    LoginProvider = token.LoginProvider.AsVarChar(128),
                    Name = token.Name.AsVarChar(128),
                    Value = token.Value.AsVarChar(128),
                }, tx);
            await tx.CommitAsync();
        }
        catch (Exception x) when (x is not OperationCanceledException)
        {
            await tx.RollbackAsync();
        }
    }

    /// <summary>
    /// Remove a new user token.
    /// </summary>
    /// <param name="token">The token to be removed.</param>
    /// <returns></returns>
    protected override async Task RemoveUserTokenAsync(TUserToken token)
    {
        ArgumentNullException.ThrowIfNull(token);

        await using var cnn = await OpenDbConnectionAsync(default);
        await using var tx = await cnn.BeginTransactionAsync(default);
        try
        {
            await cnn.ExecuteAsync(this.queries.DeleteUserToken,
                this.KeyRequiresDbString ?
                new
                {
                    UserId = ConvertIdToDbString(token.UserId),
                    LoginProvider = token.LoginProvider.AsVarChar(128),
                    Name = token.Name.AsVarChar(128),
                } :
                new
                {
                    UserId = token.UserId,
                    LoginProvider = token.LoginProvider.AsVarChar(128),
                    Name = token.Name.AsVarChar(128),
                }, tx);
            await tx.CommitAsync();
        }
        catch (Exception x) when (x is not OperationCanceledException)
        {
            await tx.RollbackAsync();
        }
    }
}
