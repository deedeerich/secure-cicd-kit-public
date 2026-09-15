import java.sql.*;
public class Vuln {
    public void query(Connection c, String userInput) throws SQLException {
        // semgrep p/java: SQL injection
        Statement s = c.createStatement();
        s.executeQuery("SELECT * FROM t WHERE n='" + userInput + "'");
    }
    public void exec(String cmd) throws Exception {
        Runtime.getRuntime().exec(cmd);   // command injection
    }
}
