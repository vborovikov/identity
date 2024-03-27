namespace Spryer.AspNetCore.Identity;

using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using Dapper;
using Microsoft.AspNetCore.Identity;

/// <summary>
/// Represents a new instance of a persistence store using Dapper.
/// </summary>
public abstract class DapperStoreBase<TKey> : IDisposable
    where TKey : IEquatable<TKey>
{
    private bool disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="DapperStoreBase{TKey}"/> class.
    /// </summary>
    /// <param name="describer">The <see cref="IdentityErrorDescriber"/> used to describe store errors.</param>
    protected DapperStoreBase(IdentityErrorDescriber describer)
    {
        ArgumentNullException.ThrowIfNull(describer);
        this.ErrorDescriber = describer;
    }

    /// <summary>
    /// Gets or sets the <see cref="IdentityErrorDescriber"/> for any error that occurred with the current operation.
    /// </summary>
    public IdentityErrorDescriber ErrorDescriber { get; set; }

    /// <summary>
    /// Dispose the store
    /// </summary>
    public void Dispose()
    {
        this.disposed = true;
    }

    /// <summary>
    /// Throws if this class has been disposed.
    /// </summary>
    protected void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(this.disposed, this);
    }

    /// <summary>
    /// Converts the provided <paramref name="id"/> to a strongly typed key object.
    /// </summary>
    /// <param name="id">The id to convert.</param>
    /// <returns>An instance of <typeparamref name="TKey"/> representing the provided <paramref name="id"/>.</returns>
    [UnconditionalSuppressMessage("Trimming", "IL2026:Members annotated with 'RequiresUnreferencedCodeAttribute' require dynamic access otherwise can break functionality when trimming application code",
        Justification = "TKey is annoated with RequiresUnreferencedCodeAttribute.All.")]
    public virtual TKey? ConvertIdFromString(string? id)
    {
        if (id == null)
        {
            return default;
        }

        return (TKey?)TypeDescriptor.GetConverter(typeof(TKey)).ConvertFromInvariantString(id);
    }

    /// <summary>
    /// Converts the provided <paramref name="id"/> to its string representation.
    /// </summary>
    /// <param name="id">The id to convert.</param>
    /// <returns>An <see cref="string"/> representation of the provided <paramref name="id"/>.</returns>
    public virtual string? ConvertIdToString(TKey id)
    {
        if (object.Equals(id, default(TKey)))
        {
            return null;
        }
        return id.ToString();
    }

    /// <summary>
    /// Converts the provided <paramref name="id"/> to its SQL string representation.
    /// </summary>
    /// <param name="id">The id to convert.</param>
    /// <returns>An <see cref="DbString"/> representation of the provided <paramref name="id"/>.</returns>
    protected virtual DbString ConvertIdToDbString(TKey id)
    {
        return ConvertIdToString(id).AsChar(36);
    }
}
