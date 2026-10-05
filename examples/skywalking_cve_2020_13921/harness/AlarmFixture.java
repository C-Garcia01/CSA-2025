package org.apache.skywalking.oap.server.storage.plugin.jdbc.vccprobe;

import java.sql.Connection;
import java.sql.Statement;
import java.util.Properties;
import org.apache.skywalking.oap.server.core.query.enumeration.Scope;
import org.apache.skywalking.oap.server.library.client.jdbc.hikaricp.JDBCHikariCPClient;

// Builds an in-memory H2 alarm_record table for the CVE-2020-13921 probe.
final class AlarmFixture {

    static JDBCHikariCPClient seeded(String name) throws Exception {
        Scope.All.name(); // initialize the enum so Scope.Finder is populated
        Properties properties = new Properties();
        properties.setProperty("jdbcUrl", "jdbc:h2:mem:" + name + ";DB_CLOSE_DELAY=-1");
        properties.setProperty("driverClassName", "org.h2.Driver");
        properties.setProperty("username", "sa");
        JDBCHikariCPClient client = new JDBCHikariCPClient(properties);
        client.connect();
        try (Connection connection = client.getConnection();
             Statement statement = connection.createStatement()) {
            statement.execute("create table alarm_record (id0 varchar(255), alarm_message varchar(4096), "
                + "start_time bigint, scope int, _time_bucket bigint)");
            statement.execute("insert into alarm_record values ('1', 'SECRET breach detected', 1000, 0, 0)");
        }
        return client;
    }

    private AlarmFixture() {
    }
}
