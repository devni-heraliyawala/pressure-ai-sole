using Duende.IdentityServer.Models;
using Duende.IdentityServer.Stores;
using MongoDB.Driver;

namespace AI.Sole.WebAPI
{
    public class ClientStore : IClientStore
    {
        private readonly IMongoCollection<Client> _clients;

        public ClientStore(IMongoDatabase database)
        {
            _clients = database.GetCollection<Client>("Clients");
        }

        public Task<Client> FindClientByIdAsync(string clientId)
        {
            return _clients.Find(c => c.ClientId == clientId).FirstOrDefaultAsync();
        }
    }

}
