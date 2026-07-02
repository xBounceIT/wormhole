using System.Data;
using Dapper;

namespace Wormhole.Data;

/// <summary>
/// Dapper type handlers that map .NET <see cref="Guid"/> values to SQLite TEXT columns.
/// Microsoft.Data.Sqlite has no native Guid storage class, so we serialize as "D"-format strings.
/// Register once at startup via <see cref="Register"/>.
/// </summary>
public static class SqliteTypeHandlers
{
    private static bool _registered;
    private static readonly object Lock = new();

    public static void Register()
    {
        lock (Lock)
        {
            if (_registered) return;
            SqlMapper.AddTypeHandler(new GuidHandler());
            SqlMapper.AddTypeHandler(new NullableGuidHandler());
            SqlMapper.AddTypeHandler(new DateTimeOffsetHandler());
            SqlMapper.AddTypeHandler(new NullableDateTimeOffsetHandler());
            _registered = true;
        }
    }

    private sealed class GuidHandler : SqlMapper.TypeHandler<Guid>
    {
        public override Guid Parse(object value) => Guid.Parse((string)value);

        public override void SetValue(IDbDataParameter parameter, Guid value)
        {
            parameter.DbType = DbType.String;
            parameter.Value = value.ToString("D");
        }
    }

    private sealed class NullableGuidHandler : SqlMapper.TypeHandler<Guid?>
    {
        public override Guid? Parse(object value) => value is null ? null : Guid.Parse((string)value);

        public override void SetValue(IDbDataParameter parameter, Guid? value)
        {
            parameter.DbType = DbType.String;
            parameter.Value = value?.ToString("D") ?? (object)DBNull.Value;
        }
    }
    private sealed class DateTimeOffsetHandler : SqlMapper.TypeHandler<DateTimeOffset>
    {
        public override DateTimeOffset Parse(object value) =>
            DateTimeOffset.Parse((string)value, null, System.Globalization.DateTimeStyles.RoundtripKind);

        public override void SetValue(IDbDataParameter parameter, DateTimeOffset value)
        {
            parameter.DbType = DbType.String;
            parameter.Value = value.ToString("O");
        }
    }

    private sealed class NullableDateTimeOffsetHandler : SqlMapper.TypeHandler<DateTimeOffset?>
    {
        public override DateTimeOffset? Parse(object value) =>
            value is null or DBNull
                ? null
                : DateTimeOffset.Parse((string)value, null, System.Globalization.DateTimeStyles.RoundtripKind);

        public override void SetValue(IDbDataParameter parameter, DateTimeOffset? value)
        {
            parameter.DbType = DbType.String;
            parameter.Value = value?.ToString("O") ?? (object)DBNull.Value;
        }
    }
}
