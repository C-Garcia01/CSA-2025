package org.apache.skywalking.oap.server.storage.plugin.jdbc.vccprobe;

import static org.junit.Assert.assertTrue;

import org.apache.skywalking.oap.server.core.query.type.Alarms;
import org.apache.skywalking.oap.server.storage.plugin.jdbc.h2.dao.H2AlarmQueryDAO;
import org.junit.Test;

public class SqlInjectionProbeTest {

    // A keyword that is not a substring of any message. If it is bound, nothing
    // matches; if it is concatenated, the injected "or like '%%'" returns the row.
    private static final String INJECTION = "no-such-text%' or alarm_message like '%";

    @Test
    public void keywordCannotBreakOutOfTheLikePredicate() throws Exception {
        H2AlarmQueryDAO dao = new H2AlarmQueryDAO(AlarmFixture.seeded("security"));
        Alarms result = dao.getAlarm(null, INJECTION, 10, 0, 0, 0);
        assertTrue("SQL injection through keyword returned a non-matching alarm",
            result.getMsgs().isEmpty());
    }
}
