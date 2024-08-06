namespace AI.Sole.WebAPI
{
    public static class Globals
    {
        //Appsetting

        public static readonly string JWT_SECRET_KEY = AppSettingsHelper.Setting("Jwt:SecretKey");
        public static readonly string JWT_ISSUER = AppSettingsHelper.Setting("Jwt:Issuer");
        public static readonly string MONGO_CONNECTION = AppSettingsHelper.Setting("MongoDbSettings:ConnectionString");
        public static readonly string MONGO_DBNAME = AppSettingsHelper.Setting("MongoDbSettings:DatabaseName");

        // SMTP Settings
        public static readonly string SMTP_HOST = AppSettingsHelper.Setting("Smtp:Host");
        public static readonly string SMTP_PORT = AppSettingsHelper.Setting("Smtp:Port");
        public static readonly string SMTP_API_KEY = AppSettingsHelper.Setting("Smtp:ApiKey");
        public static readonly string SMTP_SENDER_DISPLAY_NAME = AppSettingsHelper.Setting("Smtp:SenderDisplayName");
        public static readonly string SMTP_SENDER_EMAIL = AppSettingsHelper.Setting("Smtp:SenderEmail");


        public static readonly string ENCRYPTION_PASSPHRASE = AppSettingsHelper.Setting("EncryptionPassphrase");
        public static readonly string REDIS_URL = AppSettingsHelper.Setting("RedisConfigurations:Url");
        public static readonly string IS_WRITE_LOG = AppSettingsHelper.Setting("ConsoleLog:Log");

    }

    public static class AppSettingsHelper
    {
        private static IConfiguration? _configuration;

        public static void AppSettingsConfigure(IConfiguration configuration)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        }

        public static string Setting(string key)
        {
            return _configuration?[key] ?? string.Empty;
        }
    }
}
