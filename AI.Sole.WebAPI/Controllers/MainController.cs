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
        private readonly ILogger<MainController> _logger;

        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly RoleManager<ApplicationRole> _roleManager;
        private readonly MongoDbContext _context;
        private readonly IEmailService _emailService;


        public MainController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, RoleManager<ApplicationRole> roleManager
            , IEmailService emailService, MongoDbContext context, ILogger<MainController> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
            _emailService = emailService;
            _context = context;
            _logger = logger;
        }

        // User Management
        #region User Management

        #region Register User
        // User Management
        [HttpPost("users/register")]
        [AllowAnonymous]
        public async Task<ApiResponse<GenericResponse<ApplicationUser>>> RegisterUser([FromBody] UserRegistrationDto dto)
        {
            _logger.LogInformation("Registering a user!");

            if (!await _roleManager.RoleExistsAsync(dto.Role))
            {
                return new ApiResponse<GenericResponse<ApplicationUser>>
                {
                    Success = false,
                    Message = "Role doesn't exist",
                    Data = new GenericResponse<ApplicationUser> { Result = null, Status = "NotAcceptable" }
                };
            }

            var user = new ApplicationUser { UserName = dto.Username, Email = dto.Email, FirstName = dto.FirstName, LastName = dto.LastName, Address = dto.Address, RegistredOn = DateTime.UtcNow };
            var result = await _userManager.CreateAsync(user, dto.Password);

            if (result.Succeeded)
            {
                await _userManager.AddToRoleAsync(user, dto.Role);
                //await _signInManager.SignInAsync(user, isPersistent: false);
                // Optionally sign-in the user or confirm email
                return new ApiResponse<GenericResponse<ApplicationUser>>
                {
                    Success = true,
                    Message = "User registered successfully",
                    Data = new GenericResponse<ApplicationUser> { Result = user, Status = "OK" }
                };
            }
            var errorDescriptions = string.Join(", ", result.Errors.Select(e => e.Description));

            return new ApiResponse<GenericResponse<ApplicationUser>>
            {
                Success = false,
                Message = $"User registration failed. {errorDescriptions}",
                Data = new GenericResponse<ApplicationUser> { Result = null, Status = "BadRequest" }
            };
        }
        #endregion

        #region Login User
        [HttpPost("users/login")]
        [AllowAnonymous]

        public async Task<ApiResponse<GenericResponse<string>>> Login([FromBody] LoginDto dto)
        {
            var user = await _userManager.FindByNameAsync(dto.Username);
            if (user != null)
            {
                // Check if the account is locked out
                if (await _userManager.IsLockedOutAsync(user))
                {
                    return new ApiResponse<GenericResponse<string>>
                    {
                        Success = false,
                        Message = "Your account is locked out. Please try again later.",
                        Data = new GenericResponse<string> { Result = null, Status = "Forbidden" }
                    };
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
                        return new ApiResponse<GenericResponse<string>>
                        {
                            Success = false,
                            Message = "Secret key not configured.",
                            Data = new GenericResponse<string> { Result = null, Status = "InternalServerError" }
                        };
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

                    return new ApiResponse<GenericResponse<string>>
                    {
                        Success = true,
                        Message = string.Empty,
                        Data = new GenericResponse<string> { Result = tokenString, Status = "Ok" }
                    };
                }
                else
                {
                    // Increment access failed count on failed login attempt
                    await _userManager.AccessFailedAsync(user);

                    // Check if the account is locked out after incrementing the failed attempts
                    if (await _userManager.IsLockedOutAsync(user))
                    {
                        return new ApiResponse<GenericResponse<string>>
                        {
                            Success = false,
                            Message = "Your account is locked out. Please try again later.",
                            Data = new GenericResponse<string> { Result = null, Status = "Forbidden" }
                        };
                    }
                    return new ApiResponse<GenericResponse<string>>
                    {
                        Success = false,
                        Message = "Invalid login attempt.",
                        Data = new GenericResponse<string> { Result = null, Status = "Unauthorized" }
                    };
                }
            }

            return new ApiResponse<GenericResponse<string>>
            {
                Success = false,
                Message = "Unauthorized",
                Data = new GenericResponse<string> { Result = null, Status = "Unauthorized" }
            };
        }

        #endregion

        #region Logout User
        [HttpPost("users/logout")]
        [Authorize]
        public async Task<ApiResponse<GenericResponse<string>>> Logout()
        {
            await _signInManager.SignOutAsync();
            return new ApiResponse<GenericResponse<string>>
            {
                Success = true,
                Message = "User logged out successfully!",
                Data = new GenericResponse<string> { Result = null, Status = "Ok" }
            };
        }

        #endregion

        #region Forgot Password
        [HttpPost("users/forgot-password")]
        [AllowAnonymous]
        public async Task<ApiResponse<GenericResponse<string>>> ForgotPassword(ForgotPasswordDto dto)
        {
            var request = HttpContext.Request;
            var user = await _userManager.FindByEmailAsync(dto.Email);
            if (user == null)
            {
                // Do not reveal that the user does not exist
                return new ApiResponse<GenericResponse<string>>
                {
                    Success = true,
                    Message = string.Empty,
                    Data = new GenericResponse<string> { Result = null, Status = "Ok" }
                };
            }
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var baseUrl = $"{request.Scheme}://{request.Host}";
            var resetLink = $"{baseUrl}/Account/ResetPassword?token={Uri.EscapeDataString(token)}&email={Uri.EscapeDataString(dto.Email)}";

            await _emailService.SendPasswordResetEmailAsync(dto.Email, resetLink);
            return new ApiResponse<GenericResponse<string>>
            {
                Success = true,
                Message = "Password reset link has been sent to your email.",
                Data = new GenericResponse<string> { Result = null, Status = "Ok" }
            };
        }

        #endregion

        #region Reset Password
        [HttpPost("users/reset-password")]
        [AllowAnonymous]
        public async Task<ApiResponse<GenericResponse<string>>> ResetPassword(ResetPasswordDto dto)
        {
            var user = await _userManager.FindByEmailAsync(dto.Email);
            if (user == null)
            {
                // Do not reveal that the user does not exist
                return new ApiResponse<GenericResponse<string>>
                {
                    Success = true,
                    Message = string.Empty,
                    Data = new GenericResponse<string> { Result = null, Status = "Ok" }
                };
            }

            var decodedToken = WebUtility.UrlDecode(dto.Token);

            var result = await _userManager.ResetPasswordAsync(user, decodedToken, dto.NewPassword);
            if (!result.Succeeded)
            {
                var errorDescriptions = string.Join(", ", result.Errors.Select(e => e.Description));
                return new ApiResponse<GenericResponse<string>>
                {
                    Success = false,
                    Message = $"Password reset failed!,{errorDescriptions}",
                    Data = new GenericResponse<string> { Result = null, Status = "BadRequest" }
                };
            }

            return new ApiResponse<GenericResponse<string>>
            {
                Success = true,
                Message = "Password has been reset successfully.",
                Data = new GenericResponse<string> { Result = null, Status = "Ok" }
            };
        }

        #endregion

        #region Send Unlock Email
        [HttpPost("users/send-unlock-email")]
        [AllowAnonymous]
        public async Task<ApiResponse<GenericResponse<string>>> SendUnlockEmail(UnlockEmailRequestDto dto)
        {
            var request = HttpContext.Request;

            var user = await _userManager.FindByEmailAsync(dto.Email);
            if (user == null)
            {
                return new ApiResponse<GenericResponse<string>>
                {
                    Success = false,
                    Message = "User not found",
                    Data = new GenericResponse<string> { Result = null, Status = "NotFound" }
                };
            }

            if (!await _userManager.IsLockedOutAsync(user))
            {
                return new ApiResponse<GenericResponse<string>>
                {
                    Success = false,
                    Message = "User account is not locked.",
                    Data = new GenericResponse<string> { Result = null, Status = "BadRequest" }
                };
            }

            var token = await _userManager.GenerateUserTokenAsync(user, "Default", "AccountUnlock");
            var baseUrl = $"{request.Scheme}://{request.Host}";
            var callbackUrl = $"{baseUrl}/Account/UnlockAccount?userId={Uri.EscapeDataString(user.Id.ToString())}&token={Uri.EscapeDataString(token)}";

            await _emailService.SendAccountUnlockEmailAsync(user.Email, callbackUrl);

            return new ApiResponse<GenericResponse<string>>
            {
                Success = true,
                Message = "Unlock email sent successfully.",
                Data = new GenericResponse<string> { Result = null, Status = "Ok" }
            };
        }
        #endregion

        #region Unlock User
        [HttpPost("users/unlock")]
        [AllowAnonymous]
        public async Task<ApiResponse<GenericResponse<string>>> UnlockAccount(UnlockAccountDto dto)
        {
            var user = await _userManager.FindByIdAsync(dto.UserId);
            if (user == null)
            {
                return new ApiResponse<GenericResponse<string>>
                {
                    Success = false,
                    Message = "User not found",
                    Data = new GenericResponse<string> { Result = null, Status = "NotFound" }
                };
            }

            var decodedToken = WebUtility.UrlDecode(dto.Token);
            var result = await _userManager.VerifyUserTokenAsync(user, "Default", "AccountUnlock", decodedToken);
            if (!result)
            {
                return new ApiResponse<GenericResponse<string>>
                {
                    Success = false,
                    Message = "Invalid token.",
                    Data = new GenericResponse<string> { Result = null, Status = "BadRequest" }
                };
            }

            user.LockoutEnd = null;
            await _userManager.ResetAccessFailedCountAsync(user);
            await _userManager.UpdateAsync(user);

            return new ApiResponse<GenericResponse<string>>
            {
                Success = true,
                Message = "Account unlocked successfully.",
                Data = new GenericResponse<string> { Result = null, Status = "Ok" }
            };
        }

        #endregion

        #region Change Password
        [HttpPost("users/change-password")]
        public async Task<ApiResponse<GenericResponse<string>>> ChangePassword(ChangePasswordDto dto)
        {
            var userId = HttpContext?.User.FindFirstValue(ClaimTypes.NameIdentifier);
            var user = await _userManager.FindByIdAsync(userId);

            if (user == null)
            {
                return new ApiResponse<GenericResponse<string>>
                {
                    Success = false,
                    Message = "User not found",
                    Data = new GenericResponse<string> { Result = null, Status = "NotFound" }
                };
            }

            var result = await _userManager.ChangePasswordAsync(user, dto.CurrentPassword, dto.NewPassword);

            if (!result.Succeeded)
            {
                var errorDescriptions = string.Join(", ", result.Errors.Select(e => e.Description));
                return new ApiResponse<GenericResponse<string>>
                {
                    Success = false,
                    Message = $"Password change failed!,{errorDescriptions}",
                    Data = new GenericResponse<string> { Result = null, Status = "BadRequest" }
                };
            }

            return new ApiResponse<GenericResponse<string>>
            {
                Success = true,
                Message = $"Password reset successfully!",
                Data = new GenericResponse<string> { Result = null, Status = "Ok" }
            };
        }
        #endregion

        #region Get Profile
        [HttpGet("users/profile")]
        public async Task<ApiResponse<GenericResponse<UserProfileDto>>> GetProfile()
        {
            var userId = HttpContext?.User.FindFirstValue(ClaimTypes.NameIdentifier);
            var user = await _userManager.FindByIdAsync(userId);

            if (user == null)
            {
                return new ApiResponse<GenericResponse<UserProfileDto>>
                {
                    Success = false,
                    Message = "User not found",
                    Data = new GenericResponse<UserProfileDto> { Result = null, Status = "NotFound" }
                };
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

            return new ApiResponse<GenericResponse<UserProfileDto>>
            {
                Success = false,
                Message = string.Empty,
                Data = new GenericResponse<UserProfileDto> { Result = userProfile, Status = "Pk" }
            };
        }
        #endregion

        #region Update Profile
        [HttpPut("users/profile")]
        [Authorize]
        public async Task<ApiResponse<GenericResponse<ApplicationUser>>> UpdateProfile(UpdateProfileDto dto)
        {
            var userId = HttpContext?.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userId == null)
            {
                return new ApiResponse<GenericResponse<ApplicationUser>>
                {
                    Success = false,
                    Message = "User ID not found in token.",
                    Data = new GenericResponse<ApplicationUser> { Result = null, Status = "Unauthorized" }
                };
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return new ApiResponse<GenericResponse<ApplicationUser>>
                {
                    Success = false,
                    Message = "User not found",
                    Data = new GenericResponse<ApplicationUser> { Result = null, Status = "NotFound" }
                };
            }

            if (!await _roleManager.RoleExistsAsync(dto.Role))
            {
                return new ApiResponse<GenericResponse<ApplicationUser>>
                {
                    Success = false,
                    Message = "The specified role does not exist.",
                    Data = new GenericResponse<ApplicationUser> { Result = user, Status = "BadRequest" }
                };
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
                var errorDescriptions = string.Join(", ", result.Errors.Select(e => e.Description));

                return new ApiResponse<GenericResponse<ApplicationUser>>
                {
                    Success = false,
                    Message = $"Failed to update user profile.{errorDescriptions}",
                    Data = new GenericResponse<ApplicationUser> { Result = user, Status = "BadRequest" }
                };
            }

            var currentRoles = await _userManager.GetRolesAsync(user);
            if (currentRoles.Any())
            {
                var removeResult = await _userManager.RemoveFromRolesAsync(user, currentRoles);
                if (!removeResult.Succeeded)
                {
                    var errorDescriptions = string.Join(", ", result.Errors.Select(e => e.Description));

                    return new ApiResponse<GenericResponse<ApplicationUser>>
                    {
                        Success = false,
                        Message = $"Failed to update user role. {errorDescriptions}",
                        Data = new GenericResponse<ApplicationUser> { Result = user, Status = "BadRequest" }
                    };
                }
            }

            var addResult = await _userManager.AddToRoleAsync(user, dto.Role);
            if (!addResult.Succeeded)
            {
                var errorDescriptions = string.Join(", ", result.Errors.Select(e => e.Description));

                return new ApiResponse<GenericResponse<ApplicationUser>>
                {
                    Success = false,
                    Message = $"Failed to add user to the new role. {errorDescriptions}",
                    Data = new GenericResponse<ApplicationUser> { Result = user, Status = "BadRequest" }
                };
            }

            return new ApiResponse<GenericResponse<ApplicationUser>>
            {
                Success = true,
                Message = "User profile updated successfully.",
                Data = new GenericResponse<ApplicationUser> { Result = user, Status = "Ok" }
            };
        }
        #endregion

        #endregion

        #region Admin Management

        #region List All Users
        // GET: api/admin/users
        [HttpGet("admin/users")]
        [Authorize(Roles = "systemAdmin")]
        public async Task<ApiResponse<GenericResponse<List<ApplicationUser>>>> GetAllUsers()
        {
            var users = await _context.Users.AsQueryable().ToListAsync();
            return new ApiResponse<GenericResponse<List<ApplicationUser>>>
            {
                Success = true,
                Message = string.Empty,
                Data = new GenericResponse<List<ApplicationUser>> { Result = users, Status = "Ok" }
            };
        }
        #endregion

        #region Manage User Accounts - Update Account
        // PUT: api/admin/users/{userId}
        [HttpPut("admin/users/{userId}")]
        [Authorize(Roles = "systemAdmin")]
        public async Task<ApiResponse<GenericResponse<ApplicationUser>>> UpdateUser(string userId, [FromBody] UpdateProfileDto dto)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return new ApiResponse<GenericResponse<ApplicationUser>>
                {
                    Success = false,
                    Message = "User not found",
                    Data = new GenericResponse<ApplicationUser> { Result = null, Status = "NotFound" }
                };
            }

            if (!await _roleManager.RoleExistsAsync(dto.Role))
            {
                return new ApiResponse<GenericResponse<ApplicationUser>>
                {
                    Success = false,
                    Message = "The specified role does not exist.",
                    Data = new GenericResponse<ApplicationUser> { Result = user, Status = "BadRequest" }
                };
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
                var errorDescriptions = string.Join(", ", result.Errors.Select(e => e.Description));

                return new ApiResponse<GenericResponse<ApplicationUser>>
                {
                    Success = false,
                    Message = $"Failed to update user profile.{errorDescriptions}",
                    Data = new GenericResponse<ApplicationUser> { Result = user, Status = "BadRequest" }
                };
            }

            var currentRoles = await _userManager.GetRolesAsync(user);
            if (currentRoles.Any())
            {
                var removeResult = await _userManager.RemoveFromRolesAsync(user, currentRoles);
                if (!removeResult.Succeeded)
                {
                    var errorDescriptions = string.Join(", ", result.Errors.Select(e => e.Description));

                    return new ApiResponse<GenericResponse<ApplicationUser>>
                    {
                        Success = false,
                        Message = $"Failed to update user role. {errorDescriptions}",
                        Data = new GenericResponse<ApplicationUser> { Result = user, Status = "BadRequest" }
                    };
                }
            }

            var addResult = await _userManager.AddToRoleAsync(user, dto.Role);
            if (!addResult.Succeeded)
            {
                var errorDescriptions = string.Join(", ", result.Errors.Select(e => e.Description));

                return new ApiResponse<GenericResponse<ApplicationUser>>
                {
                    Success = false,
                    Message = $"Failed to add user to the new role. {errorDescriptions}",
                    Data = new GenericResponse<ApplicationUser> { Result = user, Status = "BadRequest" }
                };
            }

            return new ApiResponse<GenericResponse<ApplicationUser>>
            {
                Success = true,
                Message = "User profile updated successfully.",
                Data = new GenericResponse<ApplicationUser> { Result = user, Status = "Ok" }
            };
        }
        #endregion

        #region List All Devices
        // GET: api/admin/devices
        [HttpGet("admin/devices")]
        [Authorize(Roles = "systemAdmin")]
        public async Task<ApiResponse<GenericResponse<List<Device>>>> GetAllDevices()
        {
            var devices = await _context.Devices.Find(_ => true).ToListAsync();
            return new ApiResponse<GenericResponse<List<Device>>>
            {
                Success = true,
                Message = string.Empty,
                Data = new GenericResponse<List<Device>> { Result = devices, Status = "Ok" }
            };
        }
        #endregion
        #endregion

        #region Device Management

        #region Device Register
        // POST: api/devices/register
        [HttpPost("devices/register")]
        [Authorize(Roles = "doctor,systemAdmin")]
        public async Task<ApiResponse<GenericResponse<Device>>> RegisterDevice([FromBody] RegisterDeviceDto dto)
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

            return new ApiResponse<GenericResponse<Device>>
            {
                Success = true,
                Message = string.Empty,
                Data = new GenericResponse<Device> { Result = newDevice, Status = "Ok" }
            };
        }

        #endregion

        #region List User Devices

        // GET: api/devices
        [HttpGet("devices")]
        [Authorize]
        public async Task<ApiResponse<GenericResponse<List<Device>>>> ListUserDevices()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            if (userId == null)
            {
                return new ApiResponse<GenericResponse<List<Device>>>
                {
                    Success = false,
                    Message = "User not found",
                    Data = new GenericResponse<List<Device>> { Result = null, Status = "NotFound" }
                };
            }
           
            var devices = await _context.Devices.Find(d => d.UserId == userId).ToListAsync();
            return new ApiResponse<GenericResponse<List<Device>>>
            {
                Success = true,
                Message = string.Empty,
                Data = new GenericResponse<List<Device>> { Result = devices, Status = "Ok" }
            };
        }
        #endregion

        #region Update Device
        // PUT: api/devices/{deviceId}
        [HttpPut("devices/{deviceId}")]
        [Authorize(Roles = "doctor,systemAdmin")]
        public async Task<ApiResponse<GenericResponse<Device>>> UpdateDevice(string deviceId, [FromBody] UpdateDeviceDto dto)
        {
            if (!ObjectId.TryParse(deviceId, out ObjectId validObjectId))
            {
                return new ApiResponse<GenericResponse<Device>>
                {
                    Success = false,
                    Message = "Invalid device ID format.",
                    Data = new GenericResponse<Device> { Result = null, Status = "BadRequest" }
                };
            }

            deviceId = validObjectId.ToString();
            var filter = Builders<Device>.Filter.Eq(d => d.Id, deviceId);
            var device = await _context.Devices.Find(filter).FirstOrDefaultAsync();
            if (device == null)
            {
                return new ApiResponse<GenericResponse<Device>>
                {
                    Success = false,
                    Message = "Device not found.",
                    Data = new GenericResponse<Device> { Result = null, Status = "Notfound" }
                };
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

            return new ApiResponse<GenericResponse<Device>>
            {
                Success = false,
                Message = string.Empty,
                Data = new GenericResponse<Device> { Result = device, Status = "Ok" }
            };
        }
        #endregion

        #region Delete Device
        // DELETE: api/devices/{deviceId}
        [HttpDelete("devices/{deviceId}")]
        [Authorize(Roles = "doctor,systemAdmin")]

        public async Task<ApiResponse<GenericResponse<string>>> DeleteDevice(string deviceId)
        {
            if (!ObjectId.TryParse(deviceId, out ObjectId validObjectId))
            {
                return new ApiResponse<GenericResponse<string>>
                {
                    Success = false,
                    Message = "Invalid device ID format.",
                    Data = new GenericResponse<string> { Result = null, Status = "BadRequest" }
                };
            }

            deviceId = validObjectId.ToString();
            var filter = Builders<Device>.Filter.Eq(d => d.Id, deviceId);
            var device = await _context.Devices.Find(filter).FirstOrDefaultAsync();
            if (device == null)
            {
                return new ApiResponse<GenericResponse<string>>
                {
                    Success = false,
                    Message = "Device not found.",
                    Data = new GenericResponse<string> { Result = null, Status = "Notfound" }
                };
            }

            await _context.Devices.DeleteOneAsync(d => d.Id == deviceId);

            return new ApiResponse<GenericResponse<string>>
            {
                Success = true,
                Message = "Device deleted!.",
                Data = new GenericResponse<string> { Result = null, Status = "Ok" }
            };
        }

        #endregion
        #endregion

        #region Doctor & Patient Management

        #region Register Doctor
        [HttpPost("doctors/register")]
        [AllowAnonymous]
        public async Task<ApiResponse<GenericResponse<Doctor>>> RegisterDoctor([FromBody] DoctorRegistrationDto dto)
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
                return new ApiResponse<GenericResponse<Doctor>>
                {
                    Success = true,
                    Message = $"Doctor registration success.",
                    Data = new GenericResponse<Doctor> { Result = user, Status = "Ok" }
                };
            }

            var errorDescriptions = string.Join(", ", result.Errors.Select(e => e.Description));

            return new ApiResponse<GenericResponse<Doctor>>
            {
                Success = false,
                Message = $"Doctor registration failed. {errorDescriptions}",
                Data = new GenericResponse<Doctor> { Result = null, Status = "BadRequest" }
            };
        }
        #endregion

        #region List Doctors
        [HttpGet("doctors")]
        public async Task<ApiResponse<GenericResponse<List<ApplicationUser>>>> GetDoctors()
        {
            var role = await _roleManager.FindByNameAsync("doctor");
            var roleFilter = Builders<ApplicationUser>.Filter.AnyEq(u => u.Roles, role.Id.ToString());
            var doctors = await _context.Users.Find(roleFilter).ToListAsync();

            return new ApiResponse<GenericResponse<List<ApplicationUser>>>
            {
                Success = true,
                Message = string.Empty,
                Data = new GenericResponse<List<ApplicationUser>> { Result = doctors, Status = "Ok" }
            };
        }
        #endregion

        #region Get Doctor
        // GET: api/doctors/{doctorId}
        [HttpGet("doctors/{doctorId}")]
        public async Task<ApiResponse<GenericResponse<ApplicationUser>>> GetDoctor(string doctorId)
        {
            var role = await _roleManager.FindByNameAsync("doctor");

            var doctor = await _context.Users.Find(d => d.Id == Guid.Parse(doctorId) && d.Roles.Contains(role.Id.ToString())).FirstOrDefaultAsync();
            if (doctor == null)
            {
                return new ApiResponse<GenericResponse<ApplicationUser>>
                {
                    Success = false,
                    Message = "Doctor not found",
                    Data = new GenericResponse<ApplicationUser> { Result = null, Status = "Notfound" }
                };
            }
            return new ApiResponse<GenericResponse<ApplicationUser>>
            {
                Success = true,
                Message = string.Empty,
                Data = new GenericResponse<ApplicationUser> { Result = doctor, Status = "Ok" }
            };
        }
        #endregion

        #region Update Doctor Profile

        // PUT: api/doctors/{doctorId}
        [HttpPut("doctors/{doctorId}")]
        [Authorize(Roles = "doctor,systemAdmin")]

        public async Task<ApiResponse<GenericResponse<Doctor>>> UpdateDoctor(string doctorId, [FromBody] DoctorUpdateDto dto)
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
                return new ApiResponse<GenericResponse<Doctor>>
                {
                    Success = false,
                    Message = $"No doctor found with ID {doctorId}",
                    Data = new GenericResponse<Doctor> { Result = null, Status = "Notfound" }
                };
            }

            // Retrieve the current user ID from the token
            var currentUserId = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;

            // Retrieve the current user's roles
            var currentUser = await _userManager.FindByIdAsync(currentUserId);
            var roles = await _userManager.GetRolesAsync(currentUser);

            // Check if the user is an admin or the doctor themselves
            if (!roles.Contains("systemAdmin") && doctorId != currentUserId)
            {
                return new ApiResponse<GenericResponse<Doctor>>
                {
                    Success = false,
                    Message = "You are not allowed to update this doctor.",
                    Data = new GenericResponse<Doctor> { Result = null, Status = "Forbidden" }
                };
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
                    return new ApiResponse<GenericResponse<Doctor>>
                    {
                        Success = true,
                        Message = string.Empty,
                        Data = new GenericResponse<Doctor> { Result = doctor_doc, Status = "Ok" }
                    };
                }
                else
                {
                    return new ApiResponse<GenericResponse<Doctor>>
                    {
                        Success = false,
                        Message = "Update operation failed",
                        Data = new GenericResponse<Doctor> { Result = null, Status = "InternalServerError" }
                    };
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
                    return new ApiResponse<GenericResponse<Doctor>>
                    {
                        Success = false,
                        Message = "Update operation failed",
                        Data = new GenericResponse<Doctor> { Result = null, Status = "InternalServerError" }
                    };

                }

                return new ApiResponse<GenericResponse<Doctor>>
                {
                    Success = true,
                    Message = string.Empty,
                    Data = new GenericResponse<Doctor> { Result = doctor, Status = "Ok" }
                };
            }


        }
        #endregion

        #region Delete Doctor
        [HttpDelete("doctors/{doctorId}")]
        [Authorize(Roles = "doctor,systemAdmin")]

        public async Task<ApiResponse<GenericResponse<string>>> DeleteDoctor(string doctorId)
        {
            var role = await _roleManager.FindByNameAsync("doctor");

            var doctor = await _context.Users.Find(d => d.Id == Guid.Parse(doctorId) && d.Roles.Contains(role.Id.ToString())).FirstOrDefaultAsync();
            if (doctor == null)
            {
                return new ApiResponse<GenericResponse<string>>
                {
                    Success = false,
                    Message = $"No doctor found with ID {doctorId}",
                    Data = new GenericResponse<string> { Result = null, Status = "Notfound" }
                };
            }

            // Retrieve the current user ID from the token
            var currentUserId = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;

            // Retrieve the current user's roles
            var currentUser = await _userManager.FindByIdAsync(currentUserId);
            var roles = await _userManager.GetRolesAsync(currentUser);

            // Check if the user is an admin or the doctor themselves
            if (!roles.Contains("systemAdmin") && doctorId != currentUserId)
            {

                return new ApiResponse<GenericResponse<string>>
                {
                    Success = false,
                    Message = "You are not allowed to delete this doctor.",
                    Data = new GenericResponse<string> { Result = null, Status = "Forbidden" }
                };

            }

            await _context.Users.DeleteOneAsync(d => d.Id == Guid.Parse(doctorId));

            return new ApiResponse<GenericResponse<string>>
            {
                Success = true,
                Message = "Doctor deleted!",
                Data = new GenericResponse<string> { Result = null, Status = "Ok" }
            };
        }
        #endregion

        #region Register Patient
        [HttpPost("patients/register")]
        [AllowAnonymous]
        public async Task<ApiResponse<GenericResponse<Patient>>> RegisterPatient([FromBody] PatientRegistrationDto dto)
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
                return new ApiResponse<GenericResponse<Patient>>
                {
                    Success = true,
                    Message = $"Patient registration success.",
                    Data = new GenericResponse<Patient> { Result = user, Status = "Ok" }
                };
            }

            var errorDescriptions = string.Join(", ", result.Errors.Select(e => e.Description));

            return new ApiResponse<GenericResponse<Patient>>
            {
                Success = false,
                Message = $"Patient registration failed. {errorDescriptions}",
                Data = new GenericResponse<Patient> { Result = null, Status = "BadRequest" }
            };
        }
        #endregion
      
        #region List Patients
        [HttpGet("patients")]
        [Authorize(Roles = "doctor,systemAdmin")]

        public async Task<ApiResponse<GenericResponse<List<ApplicationUser>>>> GetPatients()
        {
            var role = await _roleManager.FindByNameAsync("patient");
            var roleFilter = Builders<ApplicationUser>.Filter.AnyEq(u => u.Roles, role.Id.ToString());
            var patients = await _context.Users.Find(roleFilter).ToListAsync();

            return new ApiResponse<GenericResponse<List<ApplicationUser>>>
            {
                Success = true,
                Message = string.Empty,
                Data = new GenericResponse<List<ApplicationUser>> { Result = patients, Status = "Ok" }
            };
        }

        #endregion
        
        #region Get Patient
        // GET: api/patients/{patientId}
        [HttpGet("patients/{patientId}")]
        public async Task<ApiResponse<GenericResponse<ApplicationUser>>> GetPatient(string patientId)
        {
            var role = await _roleManager.FindByNameAsync("patient");

            var patient = await _context.Users.Find(d => d.Id == Guid.Parse(patientId) && d.Roles.Contains(role.Id.ToString())).FirstOrDefaultAsync();
            if (patient == null)
            {
                return new ApiResponse<GenericResponse<ApplicationUser>>
                {
                    Success = false,
                    Message = "Patient not found",
                    Data = new GenericResponse<ApplicationUser> { Result = null, Status = "Notfound" }
                };
            }
            return new ApiResponse<GenericResponse<ApplicationUser>>
            {
                Success = true,
                Message = string.Empty,
                Data = new GenericResponse<ApplicationUser> { Result = patient, Status = "Ok" }
            };
        }
        #endregion

        #region Update Patient Profile

        [HttpPut("patients/{patientId}")]
        [Authorize(Roles = "patient,systemAdmin")]

        public async Task<ApiResponse<GenericResponse<Patient>>> UpdatePatient(string patientId, [FromBody] PatientUpdateDto dto)
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
                return new ApiResponse<GenericResponse<Patient>>
                {
                    Success = false,
                    Message = $"No patient found with ID {patientId}",
                    Data = new GenericResponse<Patient> { Result = null, Status = "Notfound" }
                };
            }

            // Retrieve the current user ID from the token
            var currentUserId = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;

            // Retrieve the current user's roles
            var currentUser = await _userManager.FindByIdAsync(currentUserId);
            var roles = await _userManager.GetRolesAsync(currentUser);

            // Check if the user is an admin or the patient themselves
            if (!roles.Contains("systemAdmin") && patientId != currentUserId)
            {
                return new ApiResponse<GenericResponse<Patient>>
                {
                    Success = false,
                    Message = "You are not allowed to update this patient.",
                    Data = new GenericResponse<Patient> { Result = null, Status = "Forbidden" }
                };
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
                    return new ApiResponse<GenericResponse<Patient>>
                    {
                        Success = true,
                        Message = string.Empty,
                        Data = new GenericResponse<Patient> { Result = patient_doc, Status = "Ok" }
                    };
                }
                else
                {
                    return new ApiResponse<GenericResponse<Patient>>
                    {
                        Success = false,
                        Message = "Update operation failed",
                        Data = new GenericResponse<Patient> { Result = null, Status = "InternalServerError" }
                    };
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
                    return new ApiResponse<GenericResponse<Patient>>
                    {
                        Success = false,
                        Message = "Update operation failed",
                        Data = new GenericResponse<Patient> { Result = null, Status = "InternalServerError" }
                    };
                }

                return new ApiResponse<GenericResponse<Patient>>
                {
                    Success = true,
                    Message = string.Empty,
                    Data = new GenericResponse<Patient> { Result = patient, Status = "Ok" }
                };
            }


        }
        #endregion

        #region Delete Patient
        [HttpDelete("patients/{patientId}")]
        [Authorize(Roles = "patient,systemAdmin")]

        public async Task<ApiResponse<GenericResponse<string>>> DeletePatient(string patientId)
        {
            var role = await _roleManager.FindByNameAsync("patient");

            var patient = await _context.Users.Find(d => d.Id == Guid.Parse(patientId) && d.Roles.Contains(role.Id.ToString())).FirstOrDefaultAsync();
            if (patient == null)
            {
                return new ApiResponse<GenericResponse<string>>
                {
                    Success = false,
                    Message = $"No patient found with ID {patientId}",
                    Data = new GenericResponse<string> { Result = null, Status = "Notfound" }
                };
            }

            // Retrieve the current user ID from the token
            var currentUserId = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;

            // Retrieve the current user's roles
            var currentUser = await _userManager.FindByIdAsync(currentUserId);
            var roles = await _userManager.GetRolesAsync(currentUser);

            // Check if the user is an admin or the patient themselves
            if (!roles.Contains("systemAdmin") && patientId != currentUserId)
            {
                return new ApiResponse<GenericResponse<string>>
                {
                    Success = false,
                    Message = "You are not allowed to delete this patient.",
                    Data = new GenericResponse<string> { Result = null, Status = "Forbidden" }
                };
            }

            await _context.Users.DeleteOneAsync(d => d.Id == Guid.Parse(patientId));

            return new ApiResponse<GenericResponse<string>>
            {
                Success = true,
                Message = "Patient deleted!",
                Data = new GenericResponse<string> { Result = null, Status = "Ok" }
            };
        }
        #endregion
        
        #endregion

        #region Setting Management
        [HttpGet("settings")]

        #region Get Settings
        public async Task<ApiResponse<GenericResponse<UserSettings>>> GetSettings()
        {
            var userId = HttpContext?.User.FindFirstValue(ClaimTypes.NameIdentifier);
            var user = await _userManager.FindByIdAsync(userId);

            if (user == null)
            {
                return new ApiResponse<GenericResponse<UserSettings>>
                {
                    Success = false,
                    Message = "User not found",
                    Data = new GenericResponse<UserSettings> { Result = null, Status = "NotFound" }
                };
            }

            return new ApiResponse<GenericResponse<UserSettings>>
            {
                Success = true,
                Message = string.Empty,
                Data = new GenericResponse<UserSettings> { Result = user.Settings, Status = "Ok" }
            };
        }
        #endregion

        #region Update Settings
        [HttpPut("settings")]
        public async Task<ApiResponse<GenericResponse<UserSettings>>> UpdateSettings([FromBody] UserSettingsDto dto)
        {
            var userId = HttpContext?.User.FindFirstValue(ClaimTypes.NameIdentifier);
            var user = await _userManager.FindByIdAsync(userId);

            if (user == null)
            {
                return new ApiResponse<GenericResponse<UserSettings>>
                {
                    Success = false,
                    Message = "User not found",
                    Data = new GenericResponse<UserSettings> { Result = null, Status = "NotFound" }
                };
            }

            user.Settings = new UserSettings { EnableNotifications = dto.EnableNotifications, Theme = dto.Theme };

            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
            {
                return new ApiResponse<GenericResponse<UserSettings>>
                {
                    Success = false,
                    Message = "Failed to update user settings.",
                    Data = new GenericResponse<UserSettings> { Result = user.Settings, Status = "InternalServerError" }
                };
            }

            return new ApiResponse<GenericResponse<UserSettings>>
            {
                Success = true,
                Message = "User settings updated successfully!",
                Data = new GenericResponse<UserSettings> { Result = user.Settings, Status = "Ok" }
            };
        }
        #endregion

        #endregion

        #region Data Management

        #region Send Sensor Data
        // POST: api/data
        [HttpPost("data")]
        public async Task<ApiResponse<GenericResponse<SensorData>>> SendSensorData([FromBody] SensorDataDto dto)
        {
            var userId = HttpContext?.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userId == null)
            {
                return new ApiResponse<GenericResponse<SensorData>>
                {
                    Success = false,
                    Message = "User ID not found in token.",
                    Data = new GenericResponse<SensorData> { Result = null, Status = "Unauthorized" }
                };
            }

            // check whether the device belongs to the user
            var device = await _context.Devices.Find(d => d.Id == dto.DeviceId).FirstOrDefaultAsync();
            if (device == null)
            {
                return new ApiResponse<GenericResponse<SensorData>>
                {
                    Success = false,
                    Message = "Device not found",
                    Data = new GenericResponse<SensorData> { Result = null, Status = "NotFound" }
                };
            }

            if (device.UserId != userId)
            {
                return new ApiResponse<GenericResponse<SensorData>>
                {
                    Success = false,
                    Message = "You do not have permission to update this device.",
                    Data = new GenericResponse<SensorData> { Result = null, Status = "Forbidden" }
                };
            }
            var sensorData = new SensorData
            {
                Id = ObjectId.GenerateNewId().ToString(),
                DeviceId = dto.DeviceId,
                CreatedTime = DateTime.UtcNow,
                Data = dto.Data,

            };
            await _context.SensorsData.InsertOneAsync(sensorData);

            return new ApiResponse<GenericResponse<SensorData>>
            {
                Success = true,
                Message = string.Empty,
                Data = new GenericResponse<SensorData> { Result = sensorData, Status = "Ok" }
            };
        }
        #endregion

        #region Get All Sensor Data
        [HttpGet("data")]
        public async Task<ApiResponse<GenericResponse<List<SensorData>>>> GetSensorData()
        {
            var sensorData = await _context.SensorsData.Find(_ => true).ToListAsync();
            return new ApiResponse<GenericResponse<List<SensorData>>>
            {
                Success = true,
                Message = string.Empty,
                Data = new GenericResponse<List<SensorData>> { Result = sensorData, Status = "Ok" }
            };
        }
        #endregion

        #region Get Sensor Data by ID
        // GET: api/data/{id}
        [HttpGet("data/{id}")]
        public async Task<ApiResponse<GenericResponse<SensorData>>> GetSensorDataById(string id)
        {
            var sensorData = await _context.SensorsData.Find(x => x.Id == id).FirstOrDefaultAsync();
            if (sensorData == null)
            {
                return new ApiResponse<GenericResponse<SensorData>>
                {
                    Success = false,
                    Message = "Sensor data not found",
                    Data = new GenericResponse<SensorData> { Result = null, Status = "NotFound" }
                };
            }
            return new ApiResponse<GenericResponse<SensorData>>
            {
                Success = true,
                Message = string.Empty,
                Data = new GenericResponse<SensorData> { Result = sensorData, Status = "Ok" }
            };
        }
        #endregion

        #endregion

        #region Report Management
        #region Create Report
        [HttpPost("reports")]
        public async Task<ApiResponse<GenericResponse<Report>>> CreateReport([FromBody] ReportDto dto)
        {
            var userId = HttpContext?.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userId == null)
            {
                return new ApiResponse<GenericResponse<Report>>
                {
                    Success = false,
                    Message = "User not found",
                    Data = new GenericResponse<Report> { Result = null, Status = "NotFound" }
                };
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

            return new ApiResponse<GenericResponse<Report>>
            {
                Success = true,
                Message = string.Empty,
                Data = new GenericResponse<Report> { Result = report, Status = "Ok" }
            };
        }
        #endregion

        #region List All Reports
        [HttpGet("reports")]
        public async Task<ApiResponse<GenericResponse<List<Report>>>> GetReports()
        {
            var reports = await _context.Reports.Find(_ => true).ToListAsync();
            return new ApiResponse<GenericResponse<List<Report>>>
            {
                Success = true,
                Message = string.Empty,
                Data = new GenericResponse<List<Report>> { Result = reports, Status = "Ok" }
            };
        }
        #endregion

        #region Get Report
        [HttpGet("reports/{reportId}")]
        public async Task<ApiResponse<GenericResponse<Report>>> GetReport(string reportId)
        {
            var report = await _context.Reports.Find(r => r.Id == reportId).FirstOrDefaultAsync();
            if (report == null)
            {
                return new ApiResponse<GenericResponse<Report>>
                {
                    Success = false,
                    Message = "Report not found!",
                    Data = new GenericResponse<Report> { Result = report, Status = "Notfound" }
                };
            }
            return new ApiResponse<GenericResponse<Report>>
            {
                Success = true,
                Message = string.Empty,
                Data = new GenericResponse<Report> { Result = report, Status = "Ok" }
            };
        }
        #endregion

        #region Update Report
        [HttpPut("reports/{reportId}")]
        public async Task<ApiResponse<GenericResponse<string>>> UpdateReport(string reportId, [FromBody] ReportUpdateDto dto)
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
                return new ApiResponse<GenericResponse<string>>
                {
                    Success = true,
                    Message = "Report updated successfully",
                    Data = new GenericResponse<string> { Result = null, Status = "Ok" }
                };
            }
            else if (result.MatchedCount == 0)
            {
                return new ApiResponse<GenericResponse<string>>
                {
                    Success = false,
                    Message = $"No report found with ID {reportId}",
                    Data = new GenericResponse<string> { Result = null, Status = "Ok" }
                };
            }
            else
            {
                return new ApiResponse<GenericResponse<string>>
                {
                    Success = false,
                    Message = "Update operation failed",
                    Data = new GenericResponse<string> { Result = null, Status = "InternalServerError" }
                };

            }
        }
        #endregion

        #region Delete Report
        [HttpDelete("reports/{reportId}")]
        public async Task<ApiResponse<GenericResponse<string>>> DeleteReport(string reportId)
        {
            var result = await _context.Reports.DeleteOneAsync(r => r.Id == reportId);
            if (result.DeletedCount == 0)
            {
                return new ApiResponse<GenericResponse<string>>
                {
                    Success = false,
                    Message = "Report not found!",
                    Data = new GenericResponse<string> { Result = null, Status = "Notfound" }
                };
            }
            return new ApiResponse<GenericResponse<string>>
            {
                Success = true,
                Message = "Report deleted!",
                Data = new GenericResponse<string> { Result = null, Status = "Ok" }
            };
        }
        #endregion
        #endregion

        #region Notifications
        [HttpPost("notifications")]
        public async Task<ApiResponse<GenericResponse<string>>> SendNotification([FromBody] NotificationDto notificationDto)
        {
            if (notificationDto == null || string.IsNullOrEmpty(notificationDto.DeviceToken))
            {
                return new ApiResponse<GenericResponse<string>>
                {
                    Success = false,
                    Message = $"Invalid notification data.",
                    Data = new GenericResponse<string> { Result = null, Status = "BadRequest" }
                };
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
                return new ApiResponse<GenericResponse<string>>
                {
                    Success = true,
                    Message = $"Notification sent successfully",
                    Data = new GenericResponse<string> { Result = response, Status = "Ok" }
                };
            }
            catch (FirebaseMessagingException e)
            {
                return new ApiResponse<GenericResponse<string>>
                {
                    Success = false,
                    Message = $"Failed to send message: {e.Message}",
                    Data = new GenericResponse<string> { Result = null, Status = "InternalServerError" }
                };
            }
        }

        #endregion
    }
}
