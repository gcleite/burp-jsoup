package burp;

import mjson.Json;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.ClipboardOwner;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Transferable;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.UnsupportedEncodingException;
import java.util.*;
import java.util.List;

public class ExportAsJsoup implements IBurpExtender, IContextMenuFactory, ClipboardOwner {
    private static final String MENU_ITEM = "Copy as jsoup";
    private IExtensionHelpers helpers;

    private enum BodyType {JSON, DATA};

    private final static String[] JAVA_ESCAPE = new String[256];
    private final static String SESSION_VAR = "session";

    static {
        for (int i = 0x00; i <= 0xFF; i++) JAVA_ESCAPE[i] = String.format("\\x%02x", i);
        for (int i = 0x20; i < 0x80; i++) JAVA_ESCAPE[i] = String.valueOf((char)i);
        JAVA_ESCAPE['\n'] = "\\n";
        JAVA_ESCAPE['\r'] = "\\r";
        JAVA_ESCAPE['\t'] = "\\t";
        JAVA_ESCAPE['"'] = "\\\"";
        JAVA_ESCAPE['\\'] = "\\\\";
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        final IHttpRequestResponse[] messages = invocation.getSelectedMessages();
        if (messages == null || messages.length == 0) return null;
        JMenuItem i1 = new JMenuItem(MENU_ITEM);
        i1.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                copyMessages(messages);
            }
        });
        return Arrays.asList(i1);
    }

    private void copyMessages(IHttpRequestResponse[] messages) {
        StringBuilder sb = new StringBuilder();

        for (IHttpRequestResponse message : messages) {
            IRequestInfo requestInfo = helpers.analyzeRequest(message);

            sb.append("Connection conn = Jsoup.connect(\"").append(requestInfo.getUrl()).append("\");\n");

            for (IParameter parameter : requestInfo.getParameters()) {
                sb.append("conn.data(\"").append(parameter.getName()).append("\", \"").append(parameter.getValue()).append("\");\n");
            }

            for (String header : requestInfo.getHeaders()) {
                if (header.startsWith("Cookie:")) {
                    String[] cookies = header.substring(8).split(";");

                    for (String cookie : cookies) {
                        String[] parts = cookie.split("=");

                        if (parts.length == 2) {
                            sb.append("conn.cookie(\"").append(parts[0].trim()).append("\", \"").append(parts[1].trim()).append("\");\n");
                        }
                    }
                } else {
                    sb.append("conn.header(\"").append(header.split(":")[0].trim()).append("\", \"").append(header.split(":")[1].trim()).append("\");\n");
                }
            }

            sb.append("Connection.Response res = conn.method(Connection.Method.").append(requestInfo.getMethod()).append(").execute();\n");
            sb.append("String body = res.body();\n");

            // Print the generated Java code to the console for debugging
            System.out.println(sb.toString());

            // Copy the generated Java code to the clipboard
            Toolkit.getDefaultToolkit().getSystemClipboard()
                    .setContents(new StringSelection(sb.toString()), this);
        }
    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        helpers = callbacks.getHelpers();
        callbacks.setExtensionName(MENU_ITEM);
        callbacks.registerContextMenuFactory(this);
    }

    private BodyType processBody(String prefix, StringBuilder py,
                                 byte[] req, IRequestInfo ri) {
        int bo = ri.getBodyOffset();
        if (bo >= req.length - 2) return null;
        py.append('\n').append(prefix);
        byte contentType = ri.getContentType();
        if (contentType == IRequestInfo.CONTENT_TYPE_JSON) {
            try {
                Json root = Json.read(byteSliceToString(req, bo, req.length));
                py.append("json=");
                escapeJson(root, py);
                return BodyType.JSON;
            } catch (Exception e) {
                // not valid JSON, treat it like any other kind of data
            }
        }
        py.append("data = ");
        if (contentType == IRequestInfo.CONTENT_TYPE_URL_ENCODED) {
            py.append('{');
            boolean firstKey = true;
            int keyStart = bo, keyEnd = -1;
            for (int pos = bo; pos < req.length; pos++) {
                byte b = req[pos];
                if (keyEnd == -1) {
                    if (b == (byte)'=') {
                        if (pos == req.length - 1) {
                            if (!firstKey) py.append(", ");
                            escapeUrlEncodedBytes(req, py, keyStart, pos);
                            py.append(": ''");
                        } else {
                            keyEnd = pos;
                        }
                    }
                } else if (b == (byte)'&' || pos == req.length - 1) {
                    if (firstKey) firstKey = false; else py.append(", ");
                    escapeUrlEncodedBytes(req, py, keyStart, keyEnd);
                    py.append(": ");
                    escapeUrlEncodedBytes(req, py, keyEnd + 1,
                            pos == req.length - 1 ? req.length : pos);
                    keyEnd = -1;
                    keyStart = pos + 1;
                }
            }
            py.append('}');
        } else {
            escapeBytes(req, py, bo, req.length);
        }
        return BodyType.DATA;
    }

    private void escapeUrlEncodedBytes(byte[] input, StringBuilder output,
                                       int start, int end) {
        if (end > start) {
            byte[] dec = helpers.urlDecode(Arrays.copyOfRange(input, start, end));
            escapeBytes(dec, output, 0, dec.length);
        } else {
            output.append("''");
        }
    }

    private static String byteSliceToString(byte[] input, int from, int till) {
        try {
            return new String(input, from, till - from, "ISO-8859-1");
        } catch (UnsupportedEncodingException uee) {
            throw new RuntimeException("All JVMs must support ISO-8859-1");
        }
    }

    private static void escapeString(String input, StringBuilder output) {
        output.append('"');
        int length = input.length();
        for (int pos = 0; pos < length; pos++) {
            output.append(JAVA_ESCAPE[input.charAt(pos) & 0xFF]);
        }
        output.append('"');
    }

    private static void escapeBytes(byte[] input, StringBuilder output,
                                    int start, int end) {
        output.append('"');
        for (int pos = start; pos < end; pos++) {
            output.append(JAVA_ESCAPE[input[pos] & 0xFF]);
        }
        output.append('"');
    }

    private static final String PYTHON_TRUE = "True", PYTHON_FALSE = "False", PYTHON_NULL = "None";

    private static void escapeJson(Json node, StringBuilder output) {
        if (node.isObject()) {
            String prefix = "{";
            Map<String, Json> tm = new TreeMap(String.CASE_INSENSITIVE_ORDER);
            tm.putAll(node.asJsonMap());
            for (Map.Entry<String, Json> e : tm.entrySet()) {
                output.append(prefix);
                prefix = ", ";
                escapeString(e.getKey(), output);
                output.append(": ");
                escapeJson(e.getValue(), output);
            }
            output.append('}');
        } else if (node.isArray()) {
            output.append('[');
            final Iterator<Json> iter = node.asJsonList().iterator();
            if (iter.hasNext()) {
                escapeJson(iter.next(), output);
                while (iter.hasNext()) {
                    output.append(", ");
                    escapeJson(iter.next(), output);
                }
            }
            output.append(']');
        } else if (node.isString()) {
            escapeString(node.asString(), output);
        } else if (node.isBoolean()) {
            output.append(node.asBoolean() ? PYTHON_TRUE : PYTHON_FALSE);
        } else if (node.isNull()) {
            output.append(PYTHON_NULL);
        } else if (node.isNumber()) {
            output.append(node.asString());
        }
    }

    @Override
    public void lostOwnership(Clipboard clipboard, Transferable contents) {}
}
