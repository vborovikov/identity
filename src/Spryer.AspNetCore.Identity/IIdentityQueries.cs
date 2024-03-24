namespace Spryer.AspNetCore.Identity;

public interface IIdentityQueries
{
    string InsertUser { get; }
    string DeleteUser { get; }
    string SelectUserByEmail { get; }
    string SelectUserByName { get; }
    string SelectUserClaims { get; }
    string SelectUserLogins { get; }
    string SelectUserRoles { get; }
    string SelectUsersByClaim { get; }
    string SelectUsersInRole { get; }
    string SelectUserRole { get; }
    string DeleteUserClaims { get; }
    string DeleteUserRole { get; }
    string DeleteUserLogin { get; }
    string UpdateUserClaim { get; }
    string UpdateUser { get; }
    string InsertUserRole { get; }
    string InsertUserToken { get; }
    string InsertUserClaims { get; }
    string InsertUserLogin { get; }
    string SelectRole { get; }
    string SelectUserToken { get; }
    string SelectUser { get; }
    string SelectUserLoginByUser { get; }
    string SelectUserLoginByProvider { get; }
    string SelectUserRoleByIds { get; }
    string DeleteUserToken { get; }
    string InsertRoleClaim { get; }
    string InsertRole { get; }
    string DeleteRole { get; }
    string SelectRoleById { get; }
    string SelectRoleByName { get; }
    string SelectRoleClaims { get; }
    string DeleteRoleClaim { get; }
    string UpdateRole { get; }
}
