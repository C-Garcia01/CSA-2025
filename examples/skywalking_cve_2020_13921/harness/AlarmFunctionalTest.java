package org.apache.skywalking.oap.server.storage.plugin.jdbc.vccprobe;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.apache.skywalking.oap.server.core.query.type.Alarms;
import org.apache.skywalking.oap.server.storage.plugin.jdbc.h2.dao.H2AlarmQueryDAO;
import org.junit.Test;

public class AlarmFunctionalTest {

    @Test
    public void keywordSearchReturnsMatchingAlarms() throws Exception {
        H2AlarmQueryDAO dao = new H2AlarmQueryDAO(AlarmFixture.seeded("functional"));
        Alarms hit = dao.getAlarm(null, "SECRET", 10, 0, 0, 0);
        assertEquals(1, hit.getMsgs().size());
        assertTrue(hit.getMsgs().get(0).getMessage().contains("SECRET"));
        Alarms miss = dao.getAlarm(null, "no-such-text", 10, 0, 0, 0);
        assertEquals(0, miss.getMsgs().size());
    }
}
