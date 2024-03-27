namespace Spryer.AspNetCore.Identity;

/// <summary>
/// Defines the SQL queries used to access the store.
/// </summary>
public interface IIdentityQueries
{
    /// <summary>
    /// Gets the SQL query to insert a new user.
    /// </summary>
    string InsertUser { get; }
    /// <summary>
    /// Gets the SQL query to update an existing user.
    /// </summary>
    string UpdateUser { get; }
    /// <summary>
    /// Gets the SQL query to delete an existing user.
    /// </summary>
    string DeleteUser { get; }
    /// <summary>
    /// Gets the SQL query to select an existing user.
    /// </summary>
    string SelectUser { get; }
    /// <summary>
    /// Gets the SQL query to select an existing user by email.
    /// </summary>
    string SelectUserByEmail { get; }
    /// <summary>
    /// Gets the SQL query to select an existing user by name.
    /// </summary>
    string SelectUserByName { get; }
    /// <summary>
    /// Gets the SQL query to select users by claim.
    /// </summary>
    string SelectUsersByClaim { get; }
    /// <summary>
    /// Gets the SQL query to select users in a role.
    /// </summary>
    string SelectUsersInRole { get; }

    /// <summary>
    /// Gets the SQL query to insert a new user claim.
    /// </summary>
    string InsertUserClaim { get; }
    /// <summary>
    /// Gets the SQL query to update an existing user claim.
    /// </summary>
    string UpdateUserClaim { get; }
    /// <summary>
    /// Gets the SQL query to delete an existing user claim.
    /// </summary>
    string DeleteUserClaim { get; }
    /// <summary>
    /// Gets the SQL query to select user claims.
    /// </summary>
    string SelectUserClaims { get; }
    
    /// <summary>
    /// Gets the SQL query to insert a new user login.
    /// </summary>
    string InsertUserLogin { get; }
    /// <summary>
    /// Gets the SQL query to delete an existing user login.
    /// </summary>
    string DeleteUserLogin { get; }
    /// <summary>
    /// Gets the SQL query to select user logins.
    /// </summary>
    string SelectUserLogins { get; }
    /// <summary>
    /// Gets the SQL query to select user login by user.
    /// </summary>
    string SelectUserLoginByUser { get; }
    /// <summary>
    /// Gets the SQL query to select user login by provider.
    /// </summary>
    string SelectUserLoginByProvider { get; }

    /// <summary>
    /// Gets the SQL query to insert a new user role.
    /// </summary>
    string InsertUserRole { get; }
    /// <summary>
    /// Gets the SQL query to delete an existing user role.
    /// </summary>
    string DeleteUserRole { get; }
    /// <summary>
    /// Gets the SQL query to select a single user role.
    /// </summary>
    string SelectUserRole { get; }
    /// <summary>
    /// Gets the SQL query to select user roles.
    /// </summary>
    string SelectUserRoles { get; }
    /// <summary>
    /// Gets the SQL query to select user roles by IDs.
    /// </summary>
    string SelectUserRoleByIds { get; }

    /// <summary>
    /// Gets the SQL query to insert a new user token.
    /// </summary>
    string InsertUserToken { get; }
    /// <summary>
    /// Gets the SQL query to delete an existing user token.
    /// </summary>
    string DeleteUserToken { get; }
    /// <summary>
    /// Gets the SQL query to select user token.
    /// </summary>
    string SelectUserToken { get; }

    /// <summary>
    /// Gets the SQL query to insert a new role.
    /// </summary>
    string InsertRole { get; }
    /// <summary>
    /// Gets the SQL query to update an existing role.
    /// </summary>
    string UpdateRole { get; }
    /// <summary>
    /// Gets the SQL query to delete an existing role.
    /// </summary>
    string DeleteRole { get; }
    /// <summary>
    /// Gets the SQL query to select an existing role.
    /// </summary>
    string SelectRole { get; }
    /// <summary>
    /// Gets the SQL query to select an existing role by ID.
    /// </summary>
    string SelectRoleById { get; }
    /// <summary>
    /// Gets the SQL query to select an existing role by name.
    /// </summary>
    string SelectRoleByName { get; }

    /// <summary>
    /// Gets the SQL query to insert a new role claim.
    /// </summary>
    string InsertRoleClaim { get; }
    /// <summary>
    /// Gets the SQL query to delete an existing role claim.
    /// </summary>
    string DeleteRoleClaim { get; }
    /// <summary>
    /// Gets the SQL query to select role claims.
    /// </summary>
    string SelectRoleClaims { get; }
}
