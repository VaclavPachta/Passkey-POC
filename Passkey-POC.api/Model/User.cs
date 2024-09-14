namespace Passkey_POC.api.Model;

public class User
{
    public string CompanyId { get; set; }
    public string UserName { get; set; }
    public DateTime Created { get; set; }

    public IList<StoredCredential> Credentials { get; set; } = new List<StoredCredential>();
}