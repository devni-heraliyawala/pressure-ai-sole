using MongoDB.Bson.Serialization.Attributes;
using MongoDB.Bson;

namespace AI.Sole.WebAPI
{

    #region User Management
    public class UserRegistrationDto
    {
        public string Username { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Address { get; set; }
        public string Role { get; set; }

    }
    public class LoginDto
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }

    public class ChangePasswordDto
    {
        public string CurrentPassword { get; set; }
        public string NewPassword { get; set; }
    }

    public class ForgotPasswordDto
    {
        public string Email { get; set; }
    }
    public class ResetPasswordDto
    {
        public string Email { get; set; }
        public string Token { get; set; }
        public string NewPassword { get; set; }
    }
    public class UnlockEmailRequestDto
    {
        public string Email { get; set; }

    }

    public class UnlockAccountDto
    {
        public string UserId { get; set; }
        public string Token { get; set; }
    }

    public class UserProfileDto
    {
        public string UserId { get; set; }
        public string Username { get; set; }
        public string Email { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string PhoneNumber { get; set; }
        public string Address { get; set; }
        public bool IsPhoneNumberConfirmed { get; set; }
        public string Role { get; set; }

        // Include other fields as necessary
    }

    public class UpdateProfileDto
    {
        public string Email { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string? PhoneNumber { get; set; }
        public string? Address { get; set; }
        public string Role { get; set; }


        // Include other fields as necessary
    }
    #endregion

    #region Device Management
    public class RegisterDeviceDto
    {
        public string? UserId { get; set; }
        public string Location { get; set; } // Left or Right
        public string ModelNumber { get; set; }
        public string Manufacturer { get; set; }
        public DateTime ManufactureDate { get; set; }
        public string HardwareVersion { get; set; }
        public DeviceConnectivityType ConnectivityType { get; set; }
        public DeviceStatus Status { get; set; }
    }

    public class UpdateDeviceDto
    {
        public string? UserId { get; set; }
        public string Location { get; set; } // Left or Right
        public string ModelNumber { get; set; }
        public string Manufacturer { get; set; }
        public DateTime ManufactureDate { get; set; }
        public string HardwareVersion { get; set; }
        public DeviceConnectivityType ConnectivityType { get; set; }
        public DeviceStatus Status { get; set; }
        public bool IsActive { get; set; }
    }
    #endregion

    #region Doctor & Patient Management
    public class DoctorRegistrationDto
    {
        public string Username { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Address { get; set; }
        public string MedicalLicenseNumber { get; set; }
        public string Specialization { get; set; }
    }

    public class DoctorUpdateDto
    {
        public string Email { get; set; }
        public string Password { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Address { get; set; }
        public string MedicalLicenseNumber { get; set; }
        public string Specialization { get; set; }
    }
    public class PatientRegistrationDto
    {
        public string Username { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Address { get; set; }
        public DateTime DateOfBirth { get; set; }
        public string MedicalRecordNumber { get; set; }
        public string EmergencyContactName { get; set; }
        public string EmergencyContactPhone { get; set; }
        public List<string> Allergies { get; set; } = new List<string>();
    }
    public class PatientUpdateDto
    {
        public string Email { get; set; }
        public string Password { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Address { get; set; }
        public DateTime DateOfBirth { get; set; }
        public string MedicalRecordNumber { get; set; }
        public string EmergencyContactName { get; set; }
        public string EmergencyContactPhone { get; set; }
        public List<string> Allergies { get; set; } = new List<string>();
    }
    #endregion

    #region Settings 
    public class UserSettingsDto
    {
        public bool EnableNotifications { get; set; }
        public string Theme { get; set; }
        // Add more settings as necessary
    }
    #endregion

    #region Data Management
    public class SensorDataDto
    {
        public string DeviceId { get; set; }
        public Dictionary<string, object> Data { get; set; } = new Dictionary<string, object>();
    }
    #endregion

    #region Report Management
    public class ReportDto
    {
        public string Title { get; set; }
        public string Description { get; set; }

        public List<PressureData> PressurePoints { get; set; } = new List<PressureData>();
    }

    public class ReportUpdateDto
    {
        public string Title { get; set; }
        public string Description { get; set; }

        public List<PressureData> PressurePoints { get; set; } = new List<PressureData>();
    }
    #endregion

    #region Notifications
    public class NotificationDto
    {
        public string DeviceToken { get; set; }  // ID of the user to receive the notification
        public string Message { get; set; }  // Message content of the notification
        public string Title { get; set; }  // Title of the notification
    }

    #endregion
}
