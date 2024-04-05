namespace Spryer.AspNetCore.Identity.SqlServer;

sealed class SqlServerIdentityQueries : IIdentityStoreQueries
{
    internal string Schema { get; init; } = "dbo";
    internal string Prefix { get; init; } = "AspNet";

    public string InsertUser =>
        $"""
        insert into {this.Schema}.{this.Prefix}Users (
            [Id],UserName,NormalizedUserName,Email,NormalizedEmail,EmailConfirmed,
            PasswordHash,SecurityStamp,ConcurrencyStamp,PhoneNumber,PhoneNumberConfirmed,
            TwoFactorEnabled,LockoutEnd,LockoutEnabled,AccessFailedCount)
        values (
            @Id,@UserName,@NormalizedUserName,@Email,@NormalizedEmail,@EmailConfirmed,
            @PasswordHash,@SecurityStamp,@ConcurrencyStamp,@PhoneNumber,@PhoneNumberConfirmed,
            @TwoFactorEnabled,@LockoutEnd,@LockoutEnabled,@AccessFailedCount);
        """;

    public string UpdateUser => 
        $"""
        update {this.Schema}.{this.Prefix}Users
        set Email = @Email,
            NormalizedEmail = @NormalizedEmail,
            EmailConfirmed = @EmailConfirmed,
            PasswordHash = @PasswordHash,
            SecurityStamp = @SecurityStamp,
            ConcurrencyStamp = @ConcurrencyStamp,
            PhoneNumber = @PhoneNumber,
            PhoneNumberConfirmed = @PhoneNumberConfirmed,
            TwoFactorEnabled = @TwoFactorEnabled,
            LockoutEnd = @LockoutEnd,
            LockoutEnabled = @LockoutEnabled,
            AccessFailedCount = @AccessFailedCount
        where [Id] = @Id;
        """;

    public string DeleteUser => 
        $"""
        delete from {this.Schema}.{this.Prefix}Users
        where Id = @UserId;
        """;

    public string SelectUser => 
        $"""
        select u.*
        from {this.Schema}.{this.Prefix}Users u
        where u.Id = @UserId;
        """;

    public string SelectUserByEmail => 
        $"""
        select u.* 
        from {this.Schema}.{this.Prefix}Users u 
        where u.NormalizedEmail = @NormalizedEmail;
        """;

    public string SelectUserByName => 
        $"""
        select u.* 
        from {this.Schema}.{this.Prefix}Users u 
        where u.NormalizedUserName = @NormalizedUserName;
        """;

    public string SelectUsersByClaim => 
        $"""
        select u.* 
        from {this.Schema}.{this.Prefix}Users u
        inner join {this.Schema}.{this.Prefix}UserClaims uc on u.Id = uc.UserId
        where uc.ClaimVlaue = @ClaimValue and uc.ClaimType = @ClaimType;
        """;

    public string SelectUsersInRole => 
        $"""
        select u.* 
        from {this.Schema}.{this.Prefix}Users u
        inner join {this.Schema}.{this.Prefix}UserRoles ur on u.Id = ur.UserId
        inner join {this.Schema}.{this.Prefix}Roles r on r.Id = ur.RoleId
        where r.NormalizedName = @NormalizedRoleName;
        """;

    public string InsertUserClaim =>
        $"""
        insert into {this.Schema}.{this.Prefix}UserClaims (UserId, ClaimType, ClaimValue)
        values (@UserId, @ClaimType, @ClaimValue);
        """;

    public string UpdateUserClaim => 
        $"""
        update {this.Schema}.{this.Prefix}UserClaims
        set ClaimType = @NewClaimType, ClaimValue = @NewClaimValue
        where UserId = @UserId and ClaimType = @OldClaimType and ClaimValue = @OldClaimValue;
        """;

    public string DeleteUserClaim => 
        $"""
        delete from {this.Schema}.{this.Prefix}UserClaims
        where UserId = @UserId and ClaimType = @ClaimType and ClaimValue = @ClaimValue;
        """;

    public string SelectUserClaims => 
        $"""
        select uc.*
        from {this.Schema}.{this.Prefix}UserClaims uc
        where uc.UserId = @UserId;
        """;

    public string InsertUserLogin =>
        $"""
        insert into {this.Schema}.{this.Prefix}UserLogins (UserId, LoginProvider, ProviderKey, ProviderDisplayName)
        values (@UserId, @LoginProvider, @ProviderKey, @ProviderDisplayName);
        """;

    public string DeleteUserLogin => 
        $"""
        delete from {this.Schema}.{this.Prefix}UserLogins
        where UserId = @UserId and LoginProvider = @LoginProvider and ProviderKey = @ProviderKey;
        """;

    public string SelectUserLogins => 
        $"""
        select ul.*
        from {this.Schema}.{this.Prefix}UserLogins ul
        where ul.UserId = @UserId;
        """;

    public string SelectUserLoginByUser => 
        $"""
        select ul.*
        from {this.Schema}.{this.Prefix}UserLogins ul
        where ul.UserId = @UserId and ul.LoginProvider = @LoginProvider and ul.ProviderKey = @ProviderKey;
        """;

    public string SelectUserLoginByProvider =>
        $"""
        select ul.*
        from {this.Schema}.{this.Prefix}UserLogins ul 
        where ul.LoginProvider = @LoginProvider and ul.ProviderKey = @ProviderKey;
        """;

    public string InsertUserToken =>
        $"""
        insert into {this.Schema}.{this.Prefix}UserTokens (UserId, LoginProvider, Name, [Value])
        values (@UserId, @LoginProvider, @Name, @Value);
        """;
    
    public string DeleteUserToken => 
        $"""
        delete from {this.Schema}.{this.Prefix}UserTokens
        where UserId = @UserId and LoginProvider = @LoginProvider and Name = @Name;
        """;

    public string SelectUserToken => 
        $"""
        select ut.*
        from {this.Schema}.{this.Prefix}UserTokens ut 
        where ut.UserId = @UserId and ut.LoginProvider = @LoginProvider and ut.Name = @TokenName;
        """;

    public string InsertRole => 
        $"""
        insert into {this.Schema}.{this.Prefix}Roles (Id, Name, NormalizedName, ConcurrencyStamp)
        values (@Id, @Name, @NormalizedName, @ConcurrencyStamp);
        """;

    public string UpdateRole => 
        $"""
        update {this.Schema}.{this.Prefix}Roles
        set Name = @Name, NormalizedName = @NormalizedName, ConcurrencyStamp = @ConcurrencyStamp
        where Id = @Id;
        """;

    public string DeleteRole => 
        $"""
        delete from {this.Schema}.{this.Prefix}Roles
        where Id = @RoleId;
        """;

    public string SelectRole => 
        $"""
        select r.*
        from {this.Schema}.{this.Prefix}Roles r 
        where r.NormalizedName = @NormalizedRoleName;
        """;

    public string SelectRoleById => 
        $"""
        select r.*
        from {this.Schema}.{this.Prefix}Roles r
        where r.Id = @RoleId;
        """;

    public string SelectRoleByName => 
        $"""
        select r.*
        from {this.Schema}.{this.Prefix}Roles r
        where r.NormalizedName = @NormalizedRoleName;
        """;

    public string InsertRoleClaim => 
        $"""
        insert into {this.Schema}.{this.Prefix}RoleClaims (RoleId, ClaimType, ClaimValue)
        values (@RoleId, @ClaimType, @ClaimValue);
        """;

    public string DeleteRoleClaim => 
        $"""
        delete from {this.Schema}.{this.Prefix}RoleClaims 
        where RoleId = @RoleId and ClaimType = @ClaimType and ClaimValue = @ClaimValue;
        """;

    public string SelectRoleClaims => 
        $"""
        select rc.*
        from {this.Schema}.{this.Prefix}RoleClaims rc
        where rc.RoleId = @RoleId;
        """;

    public string InsertUserRole =>
        $"""
        insert into {this.Schema}.{this.Prefix}UserRoles (UserId, RoleId)
        values (@UserId, @RoleId);
        """;

    public string DeleteUserRole => 
        $"""
        delete from {this.Schema}.{this.Prefix}UserRoles
        where UserId = @UserId and 
            RoleId = (select r.Id from {this.Schema}.{this.Prefix}Roles r where r.NormalizedName = @NormalizedRoleName);
        """;

    public string SelectUserRole => 
        $"""
        select ur.*
        from {this.Schema}.{this.Prefix}UserRoles ur
        inner join {this.Schema}.{this.Prefix}Roles r on r.Id = ur.RoleId
        where ur.UserId = @UserId and r.NormalizedName = @NormalizedRoleName;
        """;

    public string SelectUserRoles => 
        $"""
        select r.Name 
        from {this.Schema}.{this.Prefix}Roles r
        inner join {this.Schema}.{this.Prefix}UserRoles ur on ur.RoleId = r.Id
        where ur.UserId = @UserId;
        """;

    public string SelectUserRoleByIds =>
        $"""
        select ur.*
        from {this.Schema}.{this.Prefix}UserRoles ur 
        where ur.UserId = @UserId and ur.RoleId = @RoleId;
        """;
}
