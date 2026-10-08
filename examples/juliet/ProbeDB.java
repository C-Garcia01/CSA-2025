package testcasesupport;
import java.lang.reflect.*;
import java.sql.*;
import java.util.*;

/** H2 executes SQL; the catalog-only case uses an explicitly simulated sink. */
public class ProbeDB {
    public static boolean catalogMode;
    public static List<String> names = new ArrayList<>();
    public static void seed() throws SQLException {
        try (Connection c = DriverManager.getConnection("jdbc:h2:mem:juliet;DB_CLOSE_DELAY=-1")) {
            c.createStatement().execute("create table users(name varchar primary key)");
            c.createStatement().execute("insert into users values ('Alice'), ('Bob'), ('O''Brien')");
        }
    }
    public static Connection connect() throws SQLException {
        if (catalogMode) return (Connection) Proxy.newProxyInstance(ProbeDB.class.getClassLoader(), new Class[]{Connection.class},
            (p, m, a) -> {
                if (m.getName().equals("setCatalog")) { System.out.println("CATALOG:" + a[0]); return null; }
                if (m.getName().equals("close")) return null;
                throw new UnsupportedOperationException(m.getName());
            });
        Connection real = DriverManager.getConnection("jdbc:h2:mem:juliet;DB_CLOSE_DELAY=-1");
        return (Connection) Proxy.newProxyInstance(ProbeDB.class.getClassLoader(), new Class[]{Connection.class},
            (p, m, a) -> {
                if (m.getName().equals("createStatement")) return wrap(real.createStatement(ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_READ_ONLY), Statement.class);
                if (m.getName().equals("prepareStatement")) return wrap(real.prepareStatement((String)a[0], ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_READ_ONLY), PreparedStatement.class);
                return invoke(m, real, a);
            });
    }
    private static Object invoke(Method m, Object target, Object[] args) throws Throwable {
        try { return m.invoke(target, args); }
        catch (InvocationTargetException e) { throw e.getCause(); }
    }
    private static Object wrap(Statement real, Class<?> type) {
        return Proxy.newProxyInstance(ProbeDB.class.getClassLoader(), new Class[]{type}, (p, m, a) -> {
            Object result = invoke(m, real, a);
            if (result instanceof ResultSet) {
                ResultSet rows = (ResultSet)result;
                while (rows.next()) names.add(rows.getString("name"));
                rows.beforeFirst();
            }
            return result;
        });
    }
}
