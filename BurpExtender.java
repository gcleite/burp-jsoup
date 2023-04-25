package burp;

import org.jsoup.Connection;
import org.jsoup.Jsoup;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;

public class ExportAsJsoup implements IContextMenuFactory {
    private static final String MENU_ITEM = "Copy as jsoup";

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        IHttpRequestResponse[] messages = invocation.getSelectedMessages();

        if (messages == null || messages.length == 0) {
            return null;
        }

        JMenuItem menuItem = new JMenuItem(MENU_ITEM);
        menuItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                StringBuilder sb = new StringBuilder();

                for (IHttpRequestResponse message : messages) {
                    IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(message);

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
                    BurpExtender.callbacks.copyToClipboard(sb.toString());
                }
            }
        });

        List<JMenuItem> menuItems = new ArrayList<>();
        menuItems.add(menuItem);

        return menuItems;
    }
}
