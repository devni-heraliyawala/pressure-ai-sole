using MongoDB.Bson.Serialization.Attributes;
using MongoDB.Bson;

namespace AI.Sole.WebAPI
{
    public class Device
    {
        [BsonId]
        [BsonRepresentation(BsonType.ObjectId)]
        public string Id { get; set; }
        public string UserId { get; set; } // Assume UserId from the user management system
        public string RegisteredBy { get; set; }
        public string Location { get; set; } // Left or Right
        public string ModelNumber { get; set; }
        public string Manufacturer { get; set; }

        [BsonDateTimeOptions(Kind = DateTimeKind.Unspecified)] // Important to avoid automatic time zone conversion
        public DateTime ManufactureDate { get; set; }
        public string HardwareVersion { get; set; }
        public DeviceConnectivityType ConnectivityType { get; set; }
        public DateTime RegisteredOn { get; set; }

        [BsonDateTimeOptions(Kind = DateTimeKind.Unspecified)] // Important to avoid automatic time zone conversion
        public DateTime ModifiedOn { get; set; }
        public DateTime LastActiveTime { get; set; }
        public DeviceStatus Status { get; set; }
        public bool IsActive { get; set; }
    }

    public class SensorData
    {
        [BsonId]
        [BsonRepresentation(BsonType.ObjectId)]
        public string Id { get; set; }
        public string DeviceId { get; set; }
        public DateTime CreatedTime { get; set; }
        public Dictionary<string, object> Data { get; set; } = new Dictionary<string, object>();
    }

    public class Report
    {
        [BsonId]
        [BsonRepresentation(BsonType.ObjectId)]
        public string Id { get; set; }

        public string UserId { get; set; }  // Reference to the ApplicationUser who owns the report

        public DateTime CreatedOn { get; set; }
        public DateTime UpdatedOn { get; set; }
        public string Title { get; set; }
        public string Description { get; set; }

        // Data specific to pressure soles
        public List<PressureData> PressurePoints { get; set; } = new List<PressureData>();
    }

    public class PressureData
    {
        public DateTime Timestamp { get; set; }
        public double LeftFootPressure { get; set; }
        public double RightFootPressure { get; set; }
    }

}
