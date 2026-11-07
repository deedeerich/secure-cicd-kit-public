using System.Data.SqlClient;
public class Vuln {
    public void Query(string userInput) {
        // semgrep p/csharp: SQL injection via concatenation
        var sql = "SELECT * FROM Users WHERE Name = '" + userInput + "'";
        using var conn = new SqlConnection("Server=x;Database=y;User Id=sa;Password=P@ssw0rd;");
        using var cmd = new SqlCommand(sql, conn);
        cmd.ExecuteNonQuery();
    }
}
// An entry point: CodeQL's buildless C# extraction compiles this project as an executable.
public static class Program {
    public static void Main() { }
}
