import java.io.*;
import java.lang.reflect.*;
import javax.servlet.http.*;
import testcasesupport.ProbeDB;

/** Invokes only the extracted bad entry point, with observable servlet sinks. */
public class Probe {
    public static void main(String[] args) throws Throwable {
        String className = args[0], value = args[1];
        HttpServletRequest request = (HttpServletRequest) Proxy.newProxyInstance(
            Probe.class.getClassLoader(), new Class[]{HttpServletRequest.class},
            (proxy, method, values) -> {
                if (method.getName().equals("getParameter")) return value;
                throw new UnsupportedOperationException(method.getName());
            });
        HttpServletResponse response = (HttpServletResponse) Proxy.newProxyInstance(
            Probe.class.getClassLoader(), new Class[]{HttpServletResponse.class},
            (proxy, method, values) -> {
                switch (method.getName()) {
                    case "getWriter": return new PrintWriter(System.out, true);
                    case "sendError":
                        System.out.println("ERROR:" + values[0] + ":" + values[1]); return null;
                    case "addHeader": case "setHeader":
                        System.out.println("HEADER:" + values[0] + ":" + values[1]); return null;
                    default: throw new UnsupportedOperationException(method.getName());
                }
            });
        System.setIn(new ByteArrayInputStream((value + "\n").getBytes("UTF-8")));
        ProbeDB.catalogMode = className.contains("CWE15_");
        if (className.contains("CWE89_")) ProbeDB.seed();
        Object target = Class.forName(className).newInstance();
        try {
            if (className.contains("CWE134_")) target.getClass().getMethod("bad").invoke(target);
            else target.getClass().getMethod("bad", HttpServletRequest.class, HttpServletResponse.class).invoke(target, request, response);
        } catch (InvocationTargetException error) {
            Throwable cause = error.getCause();
            if (cause instanceof ArrayIndexOutOfBoundsException || cause instanceof java.util.IllegalFormatException) {
                System.out.println("OBSERVED_WEAKNESS:" + cause.getClass().getSimpleName());
                return;
            }
            throw cause;
        }
        if (className.contains("CWE89_")) System.out.println("ROWS:" + ProbeDB.names);
    }
}
