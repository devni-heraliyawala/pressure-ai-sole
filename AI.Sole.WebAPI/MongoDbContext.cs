using MongoDB.Driver;

namespace AI.Sole.WebAPI
{
    public class MongoDbContext
    {
        private readonly IMongoDatabase _database;

        public MongoDbContext(IConfiguration configuration)
        {
            var client = new MongoClient(Globals.MONGO_CONNECTION);
            _database = client.GetDatabase(Globals.MONGO_DBNAME);
        }

        public IMongoCollection<Report> Reports => _database.GetCollection<Report>("Reports");
        public IMongoCollection<SensorData> SensorsData => _database.GetCollection<SensorData>("SensorsData");
        public IMongoCollection<Device> Devices => _database.GetCollection<Device>("Devices");
        public IMongoCollection<ApplicationUser> Users => _database.GetCollection<ApplicationUser>("Users");
    }
}
