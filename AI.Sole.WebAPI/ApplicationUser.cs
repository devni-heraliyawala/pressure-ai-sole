using AspNetCore.Identity.Mongo.Model;
using Microsoft.AspNetCore.Identity;
using MongoDB.Bson.Serialization.Attributes;

namespace AI.Sole.WebAPI
{
    public class ApplicationUser : MongoUser<Guid>
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Address { get; set; }
        public DateTime RegistredOn { get; set; }
        public DateTime ModifiedOn { get; set; }

        public UserSettings Settings { get; set; } = new UserSettings();

    }
    public class ApplicationRole : MongoRole<Guid>
    {
        // Add additional properties here if necessary
    }

    public class Doctor : ApplicationUser
    {
        public string MedicalLicenseNumber { get; set; }
        public string Specialization { get; set; }
    }

    public class Patient : ApplicationUser
    {
        [BsonDateTimeOptions(Kind = DateTimeKind.Unspecified)] 
        public DateTime DateOfBirth { get; set; }
        public string MedicalRecordNumber { get; set; }  // Unique identifier for medical records
        public string EmergencyContactName { get; set; }
        public string EmergencyContactPhone { get; set; }
        public List<string> Allergies { get; set; } = new List<string>();  
    }

    public class UserSettings
    {
        public bool EnableNotifications { get; set; }
        public string Theme { get; set; }
        // Add more settings as necessary
    }


}
