using Amazon.Runtime.Internal;
using Duende.IdentityServer.Services;
using FirebaseAdmin.Messaging;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using MongoDB.Bson;
using MongoDB.Bson.IO;
using MongoDB.Driver;
using MongoDB.Driver.Linq;
using SendGrid.Helpers.Mail;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Numerics;
using System.Security.Claims;
using System.Threading;
using static AI.Sole.WebAPI.PatientRegistrationDto;

namespace AI.Sole.WebAPI.Controllers
{
    [ApiController]
    [Route("api")]
    public class MainController : ControllerBase
    {

        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly RoleManager<ApplicationRole> _roleManager;
        private readonly MongoDbContext _context;
        private readonly IEmailService _emailService;


        public MainController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, RoleManager<ApplicationRole> roleManager
            , IEmailService emailService, MongoDbContext context)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
            _emailService = emailService;
            _context = context;
        }

        // User Management
        #region User Management

        #region Register User
        // User Management
        [HttpPost("users/register")]
        [AllowAnonymous]
        public async Task<IActionResult> RegisterUser([FromBody] UserRegistrationDto dto)
        {
            if (!await _roleManager.RoleExistsAsync(dto.Role))
            {
                return StatusCode(StatusCodes.Status406NotAcceptable, "Role doesn't exists");
            }

            var user = new ApplicationUser { UserName = dto.Username, Email = dto.Email, FirstName = dto.FirstName, LastName = dto.LastName, Address = dto.Address, RegistredOn = DateTime.UtcNow };
            var result = await _userManager.CreateAsync(user, dto.Password);

            if (result.Succeeded)
            {
                await _userManager.AddToRoleAsync(user, dto.Role);
                //await _signInManager.SignInAsync(user, isPersistent: false);
                // Optionally sign-in the user or confirm email
                return Ok(new { userId = user.Id });
            }

            return BadRequest(result.Errors);
        }
        #endregion

        #region Login User
        [HttpPost("users/login")]
        [AllowAnonymous]

        public async Task<IActionResult> Login([FromBody] LoginDto dto)
        {
            var user = await _userManager.FindByNameAsync(dto.Username);
            if (user != null)
            {
                // Check if the account is locked out
                if (await _userManager.IsLockedOutAsync(user))
                {
                    return StatusCode(StatusCodes.Status403Forbidden, new { message = "Your account is locked out. Please try again later." });
                }

                if (await _userManager.CheckPasswordAsync(user, dto.Password))
                {
                    // Reset access failed count on successful login
                    await _userManager.ResetAccessFailedCountAsync(user);

                    var roles = await _userManager.GetRolesAsync(user);
                    var userRole = roles.FirstOrDefault(); // Assuming the user has only one role

                    var tokenHandler = new JwtSecurityTokenHandler();
                    var secretKey = Globals.JWT_SECRET_KEY;
                    if (string.IsNullOrEmpty(secretKey))
                    {
                        return StatusCode(StatusCodes.Status500InternalServerError, "Secret key not configured.");
                    }
                    var key = Convert.FromBase64String(secretKey);
                    var tokenDescriptor = new SecurityTokenDescriptor
                    {
                        Subject = new ClaimsIdentity(new[]
                        {
                        new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()), // Ensure this claim is added
                        new Claim(ClaimTypes.Name, user.UserName),
                        new Claim(ClaimTypes.Role, userRole??string.Empty),
                        new Claim("scope", "api1")  // Ensure this claim is added if required by your policy
                    }),

                        Expires = DateTime.UtcNow.AddHours(1),
                        Issuer = Globals.JWT_ISSUER,
                        Audience = Globals.JWT_ISSUER,
                        SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
                    };
                    var token = tokenHandler.CreateToken(tokenDescriptor);
                    var tokenString = tokenHandler.WriteToken(token);

                    return Ok(new { Token = tokenString });
                }
                else
                {
                    // Increment access failed count on failed login attempt
                    await _userManager.AccessFailedAsync(user);

                    // Check if the account is locked out after incrementing the failed attempts
                    if (await _userManager.IsLockedOutAsync(user))
                    {
                        return StatusCode(StatusCodes.Status403Forbidden, new { message = "Your account is locked out. Please try again later." });
                    }

                    return Unauthorized("Invalid login attempt.");
                }
            }

            return Unauthorized();
        }

        #endregion

        #region Logout User
        [HttpPost("users/logout")]
        [Authorize]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return Ok(new { message = "Logged out successfully" });
        }

        #endregion

        #region Forgot Password
        [HttpPost("users/forgot-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordDto dto)
        {
            var request = HttpContext.Request;
            var user = await _userManager.FindByEmailAsync(dto.Email);
            if (user == null)
            {
                // Do not reveal that the user does not exist
                return Ok();

            }
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var baseUrl = $"{request.Scheme}://{request.Host}";
            var resetLink = $"{baseUrl}/Account/ResetPassword?token={Uri.EscapeDataString(token)}&email={Uri.EscapeDataString(dto.Email)}";

            await _emailService.SendPasswordResetEmailAsync(dto.Email, resetLink);
            return Ok("Password reset link has been sent to your email.");
        }

        #endregion

        #region Reset Password
        [HttpPost("users/reset-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword(ResetPasswordDto dto)
        {
            var user = await _userManager.FindByEmailAsync(dto.Email);
            if (user == null)
            {
                // Do not reveal that the user does not exist
                return Ok();
            }

            var decodedToken = WebUtility.UrlDecode(dto.Token);

            var result = await _userManager.ResetPasswordAsync(user, decodedToken, dto.NewPassword);
            if (!result.Succeeded)
            {
                return BadRequest(result?.Errors);
            }
            return Ok("Password has been reset successfully.");
        }

        #endregion

        #region Send Unlock Email
        [HttpPost("users/send-unlock-email")]
        [AllowAnonymous]
        public async Task<IActionResult> SendUnlockEmail(UnlockEmailRequestDto dto)
        {
            var request = HttpContext.Request;

            var user = await _userManager.FindByEmailAsync(dto.Email);
            if (user == null)
            {
                return NotFound("User not found");
            }

            if (!await _userManager.IsLockedOutAsync(user))
            {
                return BadRequest("User account is not locked.");
            }

            var token = await _userManager.GenerateUserTokenAsync(user, "Default", "AccountUnlock");
            var baseUrl = $"{request.Scheme}://{request.Host}";
            var callbackUrl = $"{baseUrl}/Account/UnlockAccount?userId={Uri.EscapeDataString(user.Id.ToString())}&token={Uri.EscapeDataString(token)}";

            await _emailService.SendAccountUnlockEmailAsync(user.Email, callbackUrl);

            return Ok(new { message = "Unlock email sent successfully." });
        }
        #endregion

        #region Unlock User
        [HttpPost("users/unlock")]
        [AllowAnonymous]
        public async Task<IActionResult> UnlockAccount(UnlockAccountDto dto)
        {
            var user = await _userManager.FindByIdAsync(dto.UserId);
            if (user == null)
            {
                return NotFound("User not found");
            }

            var decodedToken = WebUtility.UrlDecode(dto.Token);
            var result = await _userManager.VerifyUserTokenAsync(user, "Default", "AccountUnlock", decodedToken);
            if (!result)
            {
                return BadRequest("Invalid token.");
            }

            user.LockoutEnd = null;
            await _userManager.ResetAccessFailedCountAsync(user);
            await _userManager.UpdateAsync(user);

            return Ok(new { message = "Account unlocked successfully." });
        }

        #endregion

        #region Change Password
        [HttpPost("users/change-password")]
        public async Task<IActionResult> ChangePassword(ChangePasswordDto dto)
        {
            var userId = HttpContext?.User.FindFirstValue(ClaimTypes.NameIdentifier);
            var user = await _userManager.FindByIdAsync(userId);

            if (user == null)
            {
                return NotFound("User not found");
            }

            var result = await _userManager.ChangePasswordAsync(user, dto.CurrentPassword, dto.NewPassword);

            if (!result.Succeeded)
            {
                return BadRequest(result.Errors);
            }

            return Ok("Password changed successfully");
        }
        #endregion

        #region Get Profile
        [HttpGet("users/profile")]
        public async Task<IActionResult> GetProfile()
        {
            var userId = HttpContext?.User.FindFirstValue(ClaimTypes.NameIdentifier);
            var user = await _userManager.FindByIdAsync(userId);

            if (user == null)
            {
                return NotFound("User not found");
            }
            var userRoles = await _userManager.GetRolesAsync(user);

            var userProfile = new UserProfileDto
            {
                UserId = user.Id.ToString(),
                Username = user.UserName,
                Email = user.Email,
                FirstName = user.FirstName,
                LastName = user.LastName,
                PhoneNumber = user.PhoneNumber,
                IsPhoneNumberConfirmed = user.PhoneNumberConfirmed,
                Address = user.Address,
                Role = userRoles.FirstOrDefault()
            };

            return Ok(userProfile);
        }
        #endregion

        #region Update Profile
        [HttpPut("users/profile")]
        [Authorize]
        public async Task<IActionResult> UpdateProfile(UpdateProfileDto dto)
        {
            var userId = HttpContext?.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userId == null)
            {
                return Unauthorized("User ID not found in token.");
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return NotFound("User not found.");
            }

            if (!await _roleManager.RoleExistsAsync(dto.Role))
            {
                return BadRequest("The specified role does not exist.");
            }

            user.Email = dto.Email ?? user.Email;
            user.FirstName = dto.FirstName ?? user.FirstName;
            user.LastName = dto.LastName ?? user.LastName;
            user.PhoneNumber = dto.PhoneNumber ?? user.PhoneNumber;
            user.Address = dto.Address ?? user.Address;
            user.ModifiedOn = DateTime.UtcNow;

            // Update other user fields as necessary

            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
            {
                return BadRequest("Failed to update user profile.");
            }

            var currentRoles = await _userManager.GetRolesAsync(user);
            if (currentRoles.Any())
            {
                var removeResult = await _userManager.RemoveFromRolesAsync(user, currentRoles);
                if (!removeResult.Succeeded)
                {
                    return BadRequest("Failed to update user role");
                }
            }

            var addResult = await _userManager.AddToRoleAsync(user, dto.Role);
            if (!addResult.Succeeded)
            {
                return BadRequest("Failed to add user to the new role.");
            }

            return Ok("User profile updated successfully.");
        }
        #endregion

        #endregion

        #region Admin Management

        #region List All Users
        // GET: api/admin/users
        [HttpGet("admin/users")]
        [Authorize(Roles = "systemAdmin")]
        public async Task<IActionResult> GetAllUsers()
        {
            var users = await _context.Users.AsQueryable().ToListAsync();
            return Ok(users);
        }
        #endregion

        #region Manage User Accounts - Update Account
        // PUT: api/admin/users/{userId}
        [HttpPut("admin/users/{userId}")]
        [Authorize(Roles = "systemAdmin")]
        public async Task<IActionResult> UpdateUser(string userId, [FromBody] UpdateProfileDto dto)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return NotFound("User not found.");
            }

            if (!await _roleManager.RoleExistsAsync(dto.Role))
            {
                return BadRequest("The specified role does not exist.");
            }

            user.Email = dto.Email ?? user.Email;
            user.FirstName = dto.FirstName ?? user.FirstName;
            user.LastName = dto.LastName ?? user.LastName;
            user.PhoneNumber = dto.PhoneNumber ?? user.PhoneNumber;
            user.Address = dto.Address ?? user.Address;
            user.ModifiedOn = DateTime.UtcNow;
            // Update other user fields as necessary
            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
            {
                return BadRequest("Failed to update user profile.");
            }

            var currentRoles = await _userManager.GetRolesAsync(user);
            if (currentRoles.Any())
            {
                var removeResult = await _userManager.RemoveFromRolesAsync(user, currentRoles);
                if (!removeResult.Succeeded)
                {
                    return BadRequest("Failed to update user role");
                }
            }

            var addResult = await _userManager.AddToRoleAsync(user, dto.Role);
            if (!addResult.Succeeded)
            {
                return BadRequest("Failed to add user to the new role.");
            }

            return Ok("User profile updated successfully.");

        }
        #endregion

        #region List All Devices
        // GET: api/admin/devices
        [HttpGet("admin/devices")]
        [Authorize(Roles = "systemAdmin")]
        public async Task<IActionResult> GetAllDevices()
        {
            var devices = await _context.Devices.Find(_ => true).ToListAsync();
            return Ok(devices);
        }
        #endregion
        #endregion

        #region Device Management

        #region Device Register
        // POST: api/devices/register
        [HttpPost("devices/register")]
        [Authorize(Roles = "doctor,systemAdmin")]
        public async Task<IActionResult> RegisterDevice([FromBody] RegisterDeviceDto dto)
        {
            var newDevice = new Device
            {
                Id = ObjectId.GenerateNewId().ToString(),
                UserId = dto.UserId,
                RegisteredBy = User.FindFirstValue(ClaimTypes.NameIdentifier),
                Location = dto.Location,
                ModelNumber = dto.ModelNumber,
                Manufacturer = dto.Manufacturer,
                ManufactureDate = dto.ManufactureDate.ToUniversalTime(),
                HardwareVersion = dto.HardwareVersion,
                ConnectivityType = dto.ConnectivityType,
                Status = dto.Status,
                RegisteredOn = DateTime.UtcNow,
                IsActive = true
            };

            await _context.Devices.InsertOneAsync(newDevice);

            return Ok(new { device = newDevice });
        }

        #endregion

        #region List User Devices

        // GET: api/devices
        [HttpGet("devices")]
        [Authorize]
        public async Task<IActionResult> ListUserDevices()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var devices = await _context.Devices.Find(d => d.UserId == userId).ToListAsync();
            return Ok(devices);
        }
        #endregion

        #region Update Device
        // PUT: api/devices/{deviceId}
        [HttpPut("devices/{deviceId}")]
        [Authorize(Roles = "doctor,systemAdmin")]
        public async Task<IActionResult> UpdateDevice(string deviceId, [FromBody] UpdateDeviceDto dto)
        {
            if (!ObjectId.TryParse(deviceId, out ObjectId validObjectId))
            {
                return BadRequest("Invalid device ID format.");
            }

            deviceId = validObjectId.ToString();
            var filter = Builders<Device>.Filter.Eq(d => d.Id, deviceId);
            var device = await _context.Devices.Find(filter).FirstOrDefaultAsync();
            if (device == null)
            {
                return NotFound();
            }
            device.UserId = dto.UserId ?? device.UserId;
            device.Location = dto.Location ?? device.Location;
            device.ModelNumber = dto.ModelNumber ?? device.ModelNumber;
            device.Manufacturer = dto.Manufacturer ?? device.Manufacturer;
            device.ManufactureDate = dto.ManufactureDate;
            device.HardwareVersion = dto.HardwareVersion ?? device.HardwareVersion;
            device.ConnectivityType = dto.ConnectivityType;
            device.Status = dto.Status;
            device.IsActive = dto.IsActive;
            device.ModifiedOn = DateTime.UtcNow;
            await _context.Devices.ReplaceOneAsync(filter, device);

            return Ok(device);
        }
        #endregion

        #region Delete Device
        // DELETE: api/devices/{deviceId}
        [HttpDelete("devices/{deviceId}")]
        [Authorize(Roles = "doctor,systemAdmin")]

        public async Task<IActionResult> DeleteDevice(string deviceId)
        {
            if (!ObjectId.TryParse(deviceId, out ObjectId validObjectId))
            {
                return BadRequest("Invalid device ID format.");
            }

            deviceId = validObjectId.ToString();
            var filter = Builders<Device>.Filter.Eq(d => d.Id, deviceId);
            var device = await _context.Devices.Find(filter).FirstOrDefaultAsync();
            if (device == null)
            {
                return NotFound();
            }

            await _context.Devices.DeleteOneAsync(d => d.Id == deviceId);

            return Ok("Device deleted successfully.");
        }

        #endregion
        #endregion

        #region Doctor & Patient Management

        #region Register Doctor
        [HttpPost("doctors/register")]
        [AllowAnonymous]
        public async Task<IActionResult> RegisterDoctor([FromBody] DoctorRegistrationDto dto)
        {
            string role = "doctor";
            var user = new Doctor
            {
                UserName = dto.Username,
                Email = dto.Email,
                FirstName = dto.FirstName,
                LastName = dto.LastName,
                Address = dto.Address,
                Specialization = dto.Specialization,
                MedicalLicenseNumber = dto.MedicalLicenseNumber,
                RegistredOn = DateTime.UtcNow
            };

            var result = await _userManager.CreateAsync(user, dto.Password);

            if (result.Succeeded)
            {
                await _userManager.AddToRoleAsync(user, role);
                //await _signInManager.SignInAsync(user, isPersistent: false);
                // Optionally sign-in the user or confirm email
                return Ok(new { userId = user.Id });
            }

            return BadRequest(result.Errors);
        }
        #endregion

        #region List Doctors
        [HttpGet("doctors")]
        public async Task<IActionResult> GetDoctors()
        {
            var role = await _roleManager.FindByNameAsync("doctor");
            var roleFilter = Builders<ApplicationUser>.Filter.AnyEq(u => u.Roles, role.Id.ToString());
            var doctors = await _context.Users.Find(roleFilter).ToListAsync();

            return Ok(doctors);
        }
        #endregion

        #region Get Doctor
        // GET: api/doctors/{doctorId}
        [HttpGet("doctors/{doctorId}")]
        public async Task<IActionResult> GetDoctor(string doctorId)
        {
            var role = await _roleManager.FindByNameAsync("doctor");

            var doctor = await _context.Users.Find(d => d.Id == Guid.Parse(doctorId) && d.Roles.Contains(role.Id.ToString())).FirstOrDefaultAsync();
            if (doctor == null)
            {
                return NotFound();
            }
            return Ok(doctor);
        }
        #endregion

        #region Update Doctor Profile

        // PUT: api/doctors/{doctorId}
        [HttpPut("doctors/{doctorId}")]
        [Authorize(Roles = "doctor,systemAdmin")]

        public async Task<IActionResult> UpdateDoctor(string doctorId, [FromBody] DoctorUpdateDto dto)
        {
            var role = await _roleManager.FindByNameAsync("doctor");

            var doctor_doc = await _context.Users.OfType<Doctor>().Find(d => d.Id == Guid.Parse(doctorId) && d.Roles.Contains(role.Id.ToString())).FirstOrDefaultAsync();
            ApplicationUser doctor_app = new ApplicationUser();
            if (doctor_doc == null)
            {
                // check doctor is from application user
                doctor_app = await _context.Users.Find(d => d.Id == Guid.Parse(doctorId) && d.Roles.Contains(role.Id.ToString())).FirstOrDefaultAsync();
            }

            if (doctor_doc == null && string.IsNullOrEmpty(doctor_app?.UserName))
            {
                return NotFound($"No doctor found with ID {doctorId}");
            }

            // Retrieve the current user ID from the token
            var currentUserId = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;

            // Retrieve the current user's roles
            var currentUser = await _userManager.FindByIdAsync(currentUserId);
            var roles = await _userManager.GetRolesAsync(currentUser);

            // Check if the user is an admin or the doctor themselves
            if (!roles.Contains("systemAdmin") && doctorId != currentUserId)
            {
                return StatusCode(StatusCodes.Status403Forbidden, new { message = "You are not allowed to update this doctor." });
            }

            if (doctor_doc != null)
            {
                // Map the updated fields to the existing doctor object
                doctor_doc.FirstName = dto.FirstName ?? doctor_doc.FirstName;
                doctor_doc.LastName = dto.LastName ?? doctor_doc.LastName;
                doctor_doc.Email = dto.Email ?? doctor_doc.Email;
                doctor_doc.Specialization = dto.Specialization ?? doctor_doc.Specialization;
                doctor_doc.MedicalLicenseNumber = dto.MedicalLicenseNumber ?? doctor_doc.MedicalLicenseNumber;
                doctor_doc.ModifiedOn = DateTime.UtcNow;

                // Create a replace operation to update the whole document
                var result = await _context.Users.ReplaceOneAsync(d => d.Id == Guid.Parse(doctorId), doctor_doc);

                if (result.IsAcknowledged && result.ModifiedCount == 1)
                {
                    return Ok(doctor_doc);
                }
                else
                {
                    return StatusCode(StatusCodes.Status500InternalServerError, "Update operation failed");
                }
            }
            else
            {

                var doctor = new Doctor
                {
                    UserName = doctor_app.UserName,
                    Email = dto.Email ?? doctor_app.Email,
                    FirstName = dto.FirstName ?? doctor_app.FirstName,
                    LastName = dto.LastName ?? doctor_app.LastName,
                    Address = dto.Address ?? doctor_app.Address,
                    Specialization = dto.Specialization,
                    MedicalLicenseNumber = dto.MedicalLicenseNumber,
                    RegistredOn = doctor_app.RegistredOn,
                    ModifiedOn = DateTime.UtcNow
                };
                var isDeleted = await _context.Users.DeleteOneAsync(u => u.Id == Guid.Parse(currentUserId));
                if (isDeleted.IsAcknowledged && isDeleted.DeletedCount == 1)
                {
                    var result = await _userManager.CreateAsync(doctor, dto.Password ?? doctor.PasswordHash);
                    await _userManager.AddToRoleAsync(doctor, "doctor");

                }
                else
                {
                    return StatusCode(StatusCodes.Status500InternalServerError, "Update operation failed");

                }

                return Ok(doctor);
            }


        }
        #endregion

        #region Delete Doctor
        [HttpDelete("doctors/{doctorId}")]
        [Authorize(Roles = "doctor,systemAdmin")]

        public async Task<IActionResult> DeleteDoctor(string doctorId)
        {
            var role = await _roleManager.FindByNameAsync("doctor");

            var doctor = await _context.Users.Find(d => d.Id == Guid.Parse(doctorId) && d.Roles.Contains(role.Id.ToString())).FirstOrDefaultAsync();
            if (doctor == null)
            {
                return NotFound($"No doctor found with ID {doctorId}");
            }

            // Retrieve the current user ID from the token
            var currentUserId = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;

            // Retrieve the current user's roles
            var currentUser = await _userManager.FindByIdAsync(currentUserId);
            var roles = await _userManager.GetRolesAsync(currentUser);

            // Check if the user is an admin or the doctor themselves
            if (!roles.Contains("systemAdmin") && doctorId != currentUserId)
            {
                return StatusCode(StatusCodes.Status403Forbidden, new { message = "You are not allowed to delete this doctor." });
            }

            await _context.Users.DeleteOneAsync(d => d.Id == Guid.Parse(doctorId));

            return Ok(new {message="Doctor deleted!"});
        }
        #endregion

        #region Register Patient
        [HttpPost("patients/register")]
        [AllowAnonymous]
        public async Task<IActionResult> RegisterPatient([FromBody] PatientRegistrationDto dto)
        {
            string role = "patient";
            var user = new Patient
            {
                UserName = dto.Username,
                Email = dto.Email,
                FirstName = dto.FirstName,
                LastName = dto.LastName,
                Address = dto.Address,
                DateOfBirth = dto.DateOfBirth,
                MedicalRecordNumber = dto.MedicalRecordNumber,
                EmergencyContactName = dto.EmergencyContactName,
                EmergencyContactPhone = dto.EmergencyContactPhone,
                Allergies = dto.Allergies,
                RegistredOn = DateTime.UtcNow
            };

            var result = await _userManager.CreateAsync(user, dto.Password);

            if (result.Succeeded)
            {
                await _userManager.AddToRoleAsync(user, role);
                //await _signInManager.SignInAsync(user, isPersistent: false);
                // Optionally sign-in the user or confirm email
                return Ok(new { userId = user.Id });
            }

            return BadRequest(result.Errors);
        }
        #endregion
        #region List Patients
        [HttpGet("patients")]
        [Authorize(Roles = "doctor,systemAdmin")]

        public async Task<IActionResult> GetPatients()
        {
            var role = await _roleManager.FindByNameAsync("patient");
            var roleFilter = Builders<ApplicationUser>.Filter.AnyEq(u => u.Roles, role.Id.ToString());
            var patients = await _context.Users.Find(roleFilter).ToListAsync();

            return Ok(patients);
        }

        #endregion
        #region Get Patient
        // GET: api/patients/{patientId}
        [HttpGet("patients/{patientId}")]
        public async Task<IActionResult> GetPatient(string patientId)
        {
            var role = await _roleManager.FindByNameAsync("patient");

            var patient = await _context.Users.Find(d => d.Id == Guid.Parse(patientId) && d.Roles.Contains(role.Id.ToString())).FirstOrDefaultAsync();
            if (patient == null)
            {
                return NotFound();
            }
            return Ok(patient);
        }
        #endregion

        #region Update Patient Profile

        [HttpPut("patients/{patientId}")]
        [Authorize(Roles = "patient,systemAdmin")]

        public async Task<IActionResult> UpdatePatient(string patientId, [FromBody] PatientUpdateDto dto)
        {
            var role = await _roleManager.FindByNameAsync("patient");

            var patient_doc = await _context.Users.OfType<Patient>().Find(d => d.Id == Guid.Parse(patientId) && d.Roles.Contains(role.Id.ToString())).FirstOrDefaultAsync();
            ApplicationUser patient_app = new ApplicationUser();
            if (patient_doc == null)
            {
                // check doctor is from application user
                patient_app = await _context.Users.Find(d => d.Id == Guid.Parse(patientId) && d.Roles.Contains(role.Id.ToString())).FirstOrDefaultAsync();
            }

            if (patient_doc == null && string.IsNullOrEmpty(patient_app?.UserName))
            {
                return NotFound($"No patient found with ID {patientId}");
            }

            // Retrieve the current user ID from the token
            var currentUserId = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;

            // Retrieve the current user's roles
            var currentUser = await _userManager.FindByIdAsync(currentUserId);
            var roles = await _userManager.GetRolesAsync(currentUser);

            // Check if the user is an admin or the patient themselves
            if (!roles.Contains("systemAdmin") && patientId != currentUserId)
            {
                return StatusCode(StatusCodes.Status403Forbidden, new { message = "You are not allowed to update this patient." });
            }

            if (patient_doc != null)
            {
                // Map the updated fields to the existing doctor object
                patient_doc.FirstName = dto.FirstName ?? patient_doc.FirstName;
                patient_doc.LastName = dto.LastName ?? patient_doc.LastName;
                patient_doc.Email = dto.Email ?? patient_doc.Email;
                patient_doc.Address = dto.Address ?? patient_doc.Address;
                patient_doc.DateOfBirth = dto.DateOfBirth;
                patient_doc.MedicalRecordNumber = dto.MedicalRecordNumber ?? patient_doc.MedicalRecordNumber;
                patient_doc.EmergencyContactName = dto.EmergencyContactName ?? patient_doc.EmergencyContactName;
                patient_doc.EmergencyContactPhone = dto.EmergencyContactPhone ?? patient_doc.EmergencyContactPhone;
                patient_doc.Allergies = dto.Allergies;
                patient_doc.ModifiedOn = DateTime.UtcNow;

                // Create a replace operation to update the whole document
                var result = await _context.Users.ReplaceOneAsync(d => d.Id == Guid.Parse(patientId), patient_doc);

                if (result.IsAcknowledged && result.ModifiedCount == 1)
                {
                    return Ok(patient_doc);
                }
                else
                {
                    return StatusCode(StatusCodes.Status500InternalServerError, "Update operation failed");
                }
            }
            else
            {

                var patient = new Patient
                {
                    UserName = patient_app.UserName,
                    FirstName = dto.FirstName ?? patient_app.FirstName,
                    LastName = dto.LastName ?? patient_app.LastName,
                    Email = dto.Email ?? patient_app.Email,
                    Address = dto.Address ?? patient_app.Address,
                    DateOfBirth = dto.DateOfBirth,
                    MedicalRecordNumber = dto.MedicalRecordNumber,
                    EmergencyContactName = dto.EmergencyContactName,
                    EmergencyContactPhone = dto.EmergencyContactPhone,
                    Allergies = dto.Allergies,
                    ModifiedOn = DateTime.UtcNow,
                };
                var isDeleted = await _context.Users.DeleteOneAsync(u => u.Id == Guid.Parse(patientId));
                if (isDeleted.IsAcknowledged && isDeleted.DeletedCount == 1)
                {
                    var result = await _userManager.CreateAsync(patient, dto.Password ?? patient.PasswordHash);
                    await _userManager.AddToRoleAsync(patient, "patient");

                }
                else
                {
                    return StatusCode(StatusCodes.Status500InternalServerError, "Update operation failed");

                }

                return Ok(patient);
            }


        }
        #endregion

        #region Delete Patient
        [HttpDelete("patients/{patientId}")]
        [Authorize(Roles = "patient,systemAdmin")]

        public async Task<IActionResult> DeletePatient(string patientId)
        {
            var role = await _roleManager.FindByNameAsync("patient");

            var patient = await _context.Users.Find(d => d.Id == Guid.Parse(patientId) && d.Roles.Contains(role.Id.ToString())).FirstOrDefaultAsync();
            if (patient == null)
            {
                return NotFound($"No patient found with ID {patientId}");
            }

            // Retrieve the current user ID from the token
            var currentUserId = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;

            // Retrieve the current user's roles
            var currentUser = await _userManager.FindByIdAsync(currentUserId);
            var roles = await _userManager.GetRolesAsync(currentUser);

            // Check if the user is an admin or the patient themselves
            if (!roles.Contains("systemAdmin") && patientId != currentUserId)
            {
                return StatusCode(StatusCodes.Status403Forbidden, new { message = "You are not allowed to delete this patient." });
            }

            await _context.Users.DeleteOneAsync(d => d.Id == Guid.Parse(patientId));

            return Ok(new{ message="Patient deleted!"});
        }
        #endregion
        #endregion

        #region Setting Management
        [HttpGet("settings")]

        #region Get Settings
        public async Task<IActionResult> GetSettings()
        {
            var userId = HttpContext?.User.FindFirstValue(ClaimTypes.NameIdentifier);
            var user = await _userManager.FindByIdAsync(userId);
            
            if (user == null)
            {
                return NotFound("User not found.");
            }

            return Ok(user.Settings);
        }
        #endregion

        #region Update Settings
        [HttpPut("settings")]
        public async Task<IActionResult> UpdateSettings([FromBody] UserSettingsDto dto)
        {
            var userId = HttpContext?.User.FindFirstValue(ClaimTypes.NameIdentifier);
            var user = await _userManager.FindByIdAsync(userId);

            if (user == null)
            {
                return NotFound("User not found.");
            }

            user.Settings = new UserSettings { EnableNotifications = dto.EnableNotifications,Theme=dto.Theme};

            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, "Failed to update user settings.");
            }

            return Ok("Settings updated successfully.");
        }
        #endregion

        #endregion

        #region Data Management

        #region Send Sensor Data
        // POST: api/data
        [HttpPost("data")]
        public async Task<IActionResult> SendSensorData([FromBody] SensorDataDto dto)
        {
            var userId = HttpContext?.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userId == null)
            {
                return Unauthorized("User ID not found in token.");
            }

            // check whether the device belongs to the user
            var device = await _context.Devices.Find(d => d.Id == dto.DeviceId).FirstOrDefaultAsync();
            if (device == null)
            {
                return NotFound("Device not found.");
            }

            if (device.UserId != userId)
            {
                return StatusCode(StatusCodes.Status403Forbidden,"You do not have permission to update this device.");
            }
            var sensorData = new SensorData
            {
                Id = ObjectId.GenerateNewId().ToString(),
                DeviceId = dto.DeviceId,
                CreatedTime = DateTime.UtcNow,
                Data = dto.Data,

            };
            await _context.SensorsData.InsertOneAsync(sensorData);

            return Ok(new { data = sensorData });
        }
        #endregion

        #region Get All Sensor Data
        [HttpGet("data")]
        public async Task<IActionResult> GetSensorData()
        {
            var sensorData = await _context.SensorsData.Find(_ => true).ToListAsync();
            return Ok(sensorData);
        }
        #endregion

        #region Get Sensor Data by ID
        // GET: api/data/{id}
        [HttpGet("data/{id}")]
        public async Task<IActionResult> GetSensorDataById(string id)
        {
            var sensorData = await _context.SensorsData.Find(x => x.Id == id).FirstOrDefaultAsync();
            if (sensorData == null)
            {
                return NotFound();
            }
            return Ok(sensorData);
        }
        #endregion

        #endregion

        #region Report Management
        #region Create Report
        [HttpPost("reports")]
        public async Task<IActionResult> CreateReport([FromBody] ReportDto dto)
        {
            var userId = HttpContext?.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userId == null)
            {
                return Unauthorized("User ID not found in token.");
            }
            var report = new Report()
            {
                Id = ObjectId.GenerateNewId().ToString(),
                UserId = userId,    
                Title = dto.Title,
                Description = dto.Description,
                PressurePoints = dto.PressurePoints,
                CreatedOn = DateTime.UtcNow,
            };

            await _context.Reports.InsertOneAsync(report);

            return Ok(new { data = report });
        }
        #endregion

        #region List All Reports
        [HttpGet("reports")]
        public async Task<IActionResult> GetReports()
        {
            var reports = await _context.Reports.Find(_ => true).ToListAsync();
            return Ok(reports);
        }
        #endregion

        #region Get Report
        [HttpGet("reports/{reportId}")]
        public async Task<IActionResult> GetReport(string reportId)
        {
            var report = await _context.Reports.Find(r => r.Id == reportId).FirstOrDefaultAsync();
            if (report == null)
            {
                return NotFound();
            }
            return Ok(report);
        }
        #endregion

        #region Update Report
        [HttpPut("reports/{reportId}")]
        public async Task<IActionResult> UpdateReport(string reportId, [FromBody] ReportUpdateDto dto)
        {
            var filter = Builders<Report>.Filter.Eq(r => r.Id, reportId);
            var update = Builders<Report>.Update
                .Set(r => r.Title, dto.Title)
                .Set(r => r.Description, dto.Description)
                .Set(r => r.UpdatedOn, DateTime.UtcNow);

            if (dto.PressurePoints != null)
            {
                update = update.Set(r => r.PressurePoints, dto.PressurePoints);
            }

            var result = await _context.Reports.UpdateOneAsync(filter, update);

            if (result.ModifiedCount == 1)
            {
                return Ok("Report updated successfully");
            }
            else if (result.MatchedCount == 0)
            {
                return NotFound($"No report found with ID {reportId}");
            }
            else
            {
                return StatusCode(StatusCodes.Status500InternalServerError, "Update operation failed");
            }
        }
        #endregion

        #region Delete Report
        [HttpDelete("reports/{reportId}")]
        public async Task<IActionResult> DeleteReport(string reportId)
        {
            var result = await _context.Reports.DeleteOneAsync(r => r.Id == reportId);
            if (result.DeletedCount == 0)
            {
                return NotFound("Report not found");
            }
            return Ok("Report deleted!");
        }
        #endregion
        #endregion


        #region Notifications
        [HttpPost("notifications")]
        public async Task<IActionResult> SendNotification([FromBody] NotificationDto notificationDto)
        {
            if (notificationDto == null || string.IsNullOrEmpty(notificationDto.DeviceToken))
            {
                return BadRequest("Invalid notification data.");
            }

            var message = new Message()
            {
                
                Notification = new Notification
                {
                    Title = notificationDto.Title,
                    Body = notificationDto.Message

                },
               Token = notificationDto.DeviceToken
            };

            // Send the message using Firebase Messaging
            try
            {
                string response = await FirebaseMessaging.DefaultInstance.SendAsync(message);
                return Ok(new { message = "Notification sent successfully.", response });
            }
            catch (FirebaseMessagingException e)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, $"Failed to send message: {e.Message}");

            }
        }

        #endregion
    }
}
